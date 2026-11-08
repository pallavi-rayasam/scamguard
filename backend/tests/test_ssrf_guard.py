import ipaddress
from io import BytesIO
from pathlib import Path
import socket
import ssl
import sys

import certifi
import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from url_scanner.ssrf_guard import (  # noqa: E402
    MAX_BODY_BYTES,
    MAX_DNS_ADDRESSES,
    FetchUnavailable,
    SSRFBlocked,
    safe_fetch,
    validate_target,
)


def dns_record(address: str, port: int):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port, 0, 0) if family == socket.AF_INET6 else (address, port))


class FakeSocket:
    def __init__(self, response: bytes):
        self.response = BytesIO(response)
        self.request = b""
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, request):
        self.request += request

    def makefile(self, mode):
        return self.response

    def close(self):
        self.closed = True


@pytest.mark.parametrize("url", [
    "http://10.0.0.8/",  # RFC1918 private
    "http://172.16.1.2/",  # RFC1918 private
    "http://192.168.1.9/",  # RFC1918 private
    "http://127.0.0.1/",  # IPv4 loopback
    "http://169.254.10.2/",  # IPv4 link-local
    "http://168.63.129.16/",  # Azure platform metadata
    "http://169.254.169.254/",  # common cloud metadata
    "http://169.254.170.2/",  # container metadata
    "http://100.100.100.200/",  # Alibaba metadata
    "http://[::1]/",  # IPv6 loopback
    "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6 loopback
    "http://[fe80::1]/",  # IPv6 link-local
    "http://[fc00::1]/",  # IPv6 unique-local
    "http://[fd00:ec2::254]/",  # AWS IPv6 metadata
])
def test_ssrf_attack_using_non_public_ip_literal_is_blocked(url):
    with pytest.raises(SSRFBlocked):
        validate_target(url)


def test_dns_rebinding_attack_with_public_and_private_answers_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port), dns_record("192.168.1.20", port)])
    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        validate_target("https://mixed.example/")


def test_public_ipv4_with_ipv6_unspecified_dns_answer_is_accepted(monkeypatch):
    records = [dns_record("20.193.173.92", 80), dns_record("::", 80)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: records)

    target = validate_target("http://testsafebrowsing.appspot.com/")

    assert target.addresses == ("20.193.173.92",)


def test_ssrf_validation_preserves_path_and_query_but_never_fragment(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])

    target = validate_target("https://example.test/a%2Fb?next=%2Fpay&x=1#client-only")

    assert target.origin == "https://example.test"
    assert target.url == "https://example.test/a%2Fb?next=%2Fpay&x=1"
    assert target.request_target == "/a%2Fb?next=%2Fpay&x=1"


def test_public_ipv4_and_private_ipv4_are_still_rejected_with_unspecified_answer(monkeypatch):
    records = [
        dns_record("20.193.173.92", 80),
        dns_record("::", 80),
        dns_record("192.168.1.20", 80),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: records)

    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        validate_target("http://mixed-public-private.example/")


def test_only_ipv6_unspecified_dns_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("::", 80)])

    with pytest.raises(SSRFBlocked, match="dns_no_usable_addresses"):
        validate_target("http://unspecified-only.example/")


def test_legitimate_multi_address_dns_is_accepted_with_bounded_pinned_candidates(monkeypatch):
    public_addresses = [f"1.1.1.{index}" for index in range(1, 34)]
    records = [dns_record(address, 443) for address in public_addresses]
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: records)

    target = validate_target("https://www.google.com/")

    assert len(public_addresses) > MAX_DNS_ADDRESSES
    assert target.addresses == tuple(sorted(public_addresses)[:MAX_DNS_ADDRESSES])
    assert len(target.addresses) == MAX_DNS_ADDRESSES


def test_dns_rebinding_attack_with_private_answer_beyond_candidate_cap_is_blocked(monkeypatch):
    public_addresses = [f"1.1.1.{index}" for index in range(1, 34)]
    records = [dns_record(address, 443) for address in public_addresses]
    records.append(dns_record("169.254.169.254", 443))
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: records)

    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        validate_target("https://mixed-after-cap.example/")


def test_excessive_dns_answer_set_is_still_rejected(monkeypatch):
    addresses = [str(ipaddress.IPv4Address("93.184.216.1") + index) for index in range(65)]
    records = [dns_record(address, 443) for address in addresses]
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: records)

    with pytest.raises(SSRFBlocked, match="too_many_dns_addresses"):
        validate_target("https://excessive-addresses.example/")


def test_dns_rebinding_attack_resolving_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("127.0.0.1", port)])
    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        validate_target("http://attacker-controlled.example/")


@pytest.mark.parametrize("url,reason", [
    ("file:///etc/passwd", "unsupported_scheme"),
    ("http://user:pass@example.com/", "userinfo_not_allowed"),
    ("http://example.com:8080/", "unsupported_port"),
    ("http://example.com/path\r\nHost: 127.0.0.1/", "control_character_in_url"),
])
def test_ssrf_attack_using_disallowed_scheme_userinfo_port_or_control_is_blocked(url, reason):
    with pytest.raises(SSRFBlocked, match=reason):
        validate_target(url)


def test_only_head_and_get_are_allowed():
    with pytest.raises(SSRFBlocked, match="method_not_allowed"):
        safe_fetch("http://example.com/", method="POST")


def test_limits_cannot_be_raised_by_a_caller():
    with pytest.raises(SSRFBlocked, match="body_size_limit_exceeded"):
        safe_fetch("http://example.com/", method="GET", max_bytes=MAX_BODY_BYTES + 1)
    with pytest.raises(SSRFBlocked, match="redirect_limit_exceeded"):
        safe_fetch("http://example.com/", max_redirects=MAX_BODY_BYTES)
    with pytest.raises(SSRFBlocked, match="timeout_limit_exceeded"):
        safe_fetch("http://example.com/", timeout=float("nan"))
    with pytest.raises(SSRFBlocked, match="url_too_long"):
        validate_target("http://example.com/" + "a" * 5000)


def test_dns_answer_is_pinned_to_numeric_ip_and_get_body_is_capped(monkeypatch):
    fake = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\n0123456789")
    connected = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: (connected.append(address), fake)[1])

    result = safe_fetch("http://example.test/check?q=1", method="GET", max_bytes=4)

    assert connected == [("93.184.216.34", 80)]
    assert fake.request.startswith(b"GET /check?q=1 HTTP/1.1\r\n")
    assert b"Host: example.test\r\n" in fake.request
    assert result.status == "completed"
    assert result.body_bytes == 4
    assert result.body_truncated is True
    assert result.redirect_count == 0
    assert not hasattr(result, "body")


def test_head_uses_certifi_ca_bundle_with_hostname_verification_and_never_reads_body(monkeypatch):
    fake = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1000000\r\n\r\nignored")
    seen_sni = []
    contexts = []
    real_create_default_context = ssl.create_default_context

    class FakeTLSContext:
        def __init__(self, real_context):
            self.verify_mode = real_context.verify_mode
            self.check_hostname = real_context.check_hostname

        def wrap_socket(self, connection, server_hostname):
            seen_sni.append(server_hostname)
            return connection

    def create_test_context(*, cafile):
        context = real_create_default_context(cafile=cafile)
        contexts.append((cafile, context.verify_mode, context.check_hostname))
        return FakeTLSContext(context)

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: fake)
    monkeypatch.setattr("url_scanner.ssrf_guard.ssl.create_default_context", create_test_context)

    result = safe_fetch("https://example.test/", method="HEAD")

    assert fake.request.startswith(b"HEAD / HTTP/1.1\r\n")
    assert seen_sni == ["example.test"]
    assert contexts == [(certifi.where(), ssl.CERT_REQUIRED, True)]
    assert result.body_bytes == 0
    assert result.body_truncated is False


def test_redirect_ssrf_attack_to_private_ip_is_revalidated_and_blocked(monkeypatch):
    fake = FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0\r\n\r\n")
    connected = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: (connected.append(address), fake)[1])

    with pytest.raises(SSRFBlocked, match="non_public_address"):
        safe_fetch("http://example.test/start", method="HEAD")
    assert connected == [("93.184.216.34", 80)]


def test_redirect_chain_attack_is_capped_without_automatic_following(monkeypatch):
    responses = [
        FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://two.example/\r\nContent-Length: 0\r\n\r\n"),
        FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://three.example/\r\nContent-Length: 0\r\n\r\n"),
    ]
    connected = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: (connected.append(address), responses[len(connected) - 1])[1])

    result = safe_fetch("http://one.example/", max_redirects=1)

    assert result.status == "redirect_limit"
    assert result.redirect_count == 1
    assert len(connected) == 2


def test_empty_dns_answer_is_unavailable_not_trusted(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [])
    with pytest.raises(FetchUnavailable, match="dns_no_addresses"):
        validate_target("https://no-record.example/")


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",  # decimal integer form of 127.0.0.1
        "http://0x7f000001/",  # hexadecimal form of 127.0.0.1
        "http://0177.0.0.1/",  # octal first component form of 127.0.0.1
    ],
    ids=["decimal-loopback-ip", "hex-loopback-ip", "octal-loopback-ip"],
)
def test_legacy_numeric_loopback_ip_attacks_are_rejected_before_dns(url, monkeypatch):
    def dns_must_not_be_used(host, port, type):
        raise AssertionError("ambiguous numeric IP notation must not be resolved as a hostname")

    monkeypatch.setattr(socket, "getaddrinfo", dns_must_not_be_used)
    with pytest.raises(SSRFBlocked, match="ambiguous_numeric_address"):
        validate_target(url)


@pytest.mark.parametrize(
    "url,reason",
    [
        ("http://user@127.0.0.1/", "userinfo_not_allowed"),
        ("http://evil.com@127.0.0.1/", "userinfo_not_allowed"),
        ("gopher://127.0.0.1/", "unsupported_scheme"),
        ("ftp://127.0.0.1/", "unsupported_scheme"),
        ("http://example.test:81/", "unsupported_port"),
        ("https://example.test:8443/", "unsupported_port"),
    ],
    ids=[
        "userinfo-direct-loopback",
        "userinfo-evil-domain-at-loopback",
        "gopher-scheme-loopback",
        "ftp-scheme-loopback",
        "nonstandard-http-port",
        "nonstandard-https-port",
    ],
)
def test_ssrf_attack_using_userinfo_non_http_scheme_or_nonstandard_port_is_blocked(url, reason):
    with pytest.raises(SSRFBlocked, match=reason):
        validate_target(url)


def test_redirect_revalidation_blocks_private_dns_answer_on_second_hop(monkeypatch):
    redirect = FakeSocket(
        b"HTTP/1.1 302 Found\r\nLocation: http://second.example/private\r\nContent-Length: 0\r\n\r\n"
    )
    connected = []
    resolved = []

    def resolve(host, port, type):
        resolved.append(host)
        address = "93.184.216.34" if host == "first.example" else "10.0.0.7"
        return [dns_record(address, port)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: (connected.append(address), redirect)[1],
    )

    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        safe_fetch("http://first.example/start", method="HEAD")

    assert resolved == ["first.example", "second.example"]
    assert connected == [("93.184.216.34", 80)]
