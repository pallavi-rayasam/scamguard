from io import BytesIO
from pathlib import Path
import socket
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from url_scanner.ssrf_guard import (  # noqa: E402
    MAX_BODY_BYTES,
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
def test_literal_private_loopback_link_local_and_metadata_addresses_are_blocked(url):
    with pytest.raises(SSRFBlocked):
        validate_target(url)


def test_dns_response_with_any_private_address_fails_closed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port), dns_record("192.168.1.20", port)])
    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        validate_target("https://mixed.example/")


def test_hostname_resolving_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("127.0.0.1", port)])
    with pytest.raises(SSRFBlocked, match="dns_returned_non_public_address"):
        validate_target("http://attacker-controlled.example/")


@pytest.mark.parametrize("url,reason", [
    ("file:///etc/passwd", "unsupported_scheme"),
    ("http://user:pass@example.com/", "userinfo_not_allowed"),
    ("http://example.com:8080/", "unsupported_port"),
    ("http://example.com/path\r\nHost: 127.0.0.1/", "control_character_in_url"),
])
def test_unsupported_or_malformed_targets_are_blocked_before_connect(url, reason):
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


def test_head_never_reads_or_returns_a_response_body(monkeypatch):
    fake = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1000000\r\n\r\nignored")
    seen_sni = []

    class FakeTLSContext:
        def wrap_socket(self, connection, server_hostname):
            seen_sni.append(server_hostname)
            return connection

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: fake)
    monkeypatch.setattr("url_scanner.ssrf_guard.ssl.create_default_context", FakeTLSContext)

    result = safe_fetch("https://example.test/", method="HEAD")

    assert fake.request.startswith(b"HEAD / HTTP/1.1\r\n")
    assert seen_sni == ["example.test"]
    assert result.body_bytes == 0
    assert result.body_truncated is False


def test_redirect_to_private_address_is_revalidated_and_blocked(monkeypatch):
    fake = FakeSocket(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0\r\n\r\n")
    connected = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, type: [dns_record("93.184.216.34", port)])
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: (connected.append(address), fake)[1])

    with pytest.raises(SSRFBlocked, match="non_public_address"):
        safe_fetch("http://example.test/start", method="HEAD")
    assert connected == [("93.184.216.34", 80)]


def test_redirect_count_is_capped_without_automatic_following(monkeypatch):
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
