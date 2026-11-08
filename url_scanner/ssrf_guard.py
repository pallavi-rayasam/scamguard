"""SSRF-safe, pinned-IP HTTP transport for limited URL inspection.

This module opens a socket to a vetted numeric IP address, while preserving the
original hostname for the HTTP Host header and TLS certificate/SNI validation.
It never delegates DNS resolution to an HTTP client and never follows redirects
implicitly.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import math
import re
import socket
import ssl
from urllib.parse import quote, urljoin, urlsplit

MAX_BODY_BYTES = 64 * 1024
MAX_REDIRECTS = 3
MAX_URL_LENGTH = 4096
# Keep the pinned candidate set small, but accept normal CDN/large-provider
# answers with more than eight unique public IPs. Validate all answers before
# selecting candidates so a private address cannot be hidden beyond the cap.
MAX_DNS_ADDRESSES = 32
MAX_DNS_ANSWER_ADDRESSES = 64
DEFAULT_TIMEOUT_SECONDS = 4.0
REDIRECT_CODES = {301, 302, 303, 307, 308}
METADATA_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "168.63.129.16/32",  # Azure platform address
    "169.254.169.254/32",  # common cloud metadata address
    "169.254.170.2/32",  # container metadata/credentials endpoints
    "100.100.100.200/32",  # Alibaba Cloud metadata address
    "fd00:ec2::254/128",  # AWS IPv6 metadata address
    "fd20:ce::254/128",  # GCP IPv6 metadata address
))


# Legacy numeric IPv4 spellings are not DNS names. Reject them before resolver
# interpretation can differ across platforms (decimal, hexadecimal, or octal).
_LEGACY_NUMERIC_IPV4_RE = re.compile(
    r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\.(?:0[xX][0-9a-fA-F]+|[0-9]+)){0,3}$"
)

class SSRFBlocked(ValueError):
    """The requested URL resolves to a non-public or unsupported target."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class FetchUnavailable(RuntimeError):
    """The safe transport could not complete a bounded request."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    request_target: str
    origin: str
    addresses: tuple[str, ...]

    @property
    def host_header(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        return host if self.port == default_port else f"{host}:{self.port}"


@dataclass(frozen=True)
class SafeFetchResult:
    status: str
    origin: str
    http_status: int | None
    content_type: str | None
    body_bytes: int
    body_truncated: bool
    redirect_count: int
    content_length: int | None = None


def _normalize_hostname(hostname: str) -> str:
    if not hostname or "%" in hostname or any(ord(ch) < 33 for ch in hostname):
        raise SSRFBlocked("invalid_hostname")
    unbracketed = hostname.rstrip(".")
    try:
        return str(ipaddress.ip_address(unbracketed))
    except ValueError:
        if _LEGACY_NUMERIC_IPV4_RE.fullmatch(unbracketed):
            raise SSRFBlocked("ambiguous_numeric_address")
        try:
            ascii_name = unbracketed.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise SSRFBlocked("invalid_hostname") from exc
        if len(ascii_name) > 253 or not ascii_name or any(not label or len(label) > 63 for label in ascii_name.split(".")):
            raise SSRFBlocked("invalid_hostname")
        return ascii_name


def _is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    if any(parsed in network for network in METADATA_NETWORKS):
        return False
    return parsed.is_global


def _resolve_public_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        value = str(literal)
        if not _is_public(value):
            raise SSRFBlocked("non_public_address")
        return (value,)

    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise FetchUnavailable("dns_resolution_failed") from exc
    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses:
        raise FetchUnavailable("dns_no_addresses")
    # Some resolver stacks include IPv6 unspecified (::) alongside real IPv4
    # answers. It is not a connectable destination, so ignore only this value;
    # every other answer is still checked below and must be globally routable.
    addresses = [address for address in addresses if address != "::"]
    if not addresses:
        raise SSRFBlocked("dns_no_usable_addresses")
    if len(addresses) > MAX_DNS_ANSWER_ADDRESSES:
        raise SSRFBlocked("too_many_dns_addresses")
    # Fail closed if even one A/AAAA answer is private. This also blocks mixed
    # public/private DNS responses that could otherwise enable rebinding. This
    # check intentionally runs before truncating the public candidate list.
    if any(not _is_public(address) for address in addresses):
        raise SSRFBlocked("dns_returned_non_public_address")
    return tuple(addresses[:MAX_DNS_ADDRESSES])


def validate_target(url: str) -> ValidatedTarget:
    """Parse, resolve and validate one HTTP(S) hop before creating a socket."""
    if len(url) > MAX_URL_LENGTH:
        raise SSRFBlocked("url_too_long")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise SSRFBlocked("control_character_in_url")
    try:
        parsed = urlsplit(url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise SSRFBlocked("unsupported_scheme")
        if parsed.username is not None or parsed.password is not None:
            raise SSRFBlocked("userinfo_not_allowed")
        if not parsed.hostname:
            raise SSRFBlocked("missing_hostname")
        hostname = _normalize_hostname(parsed.hostname)
        port = parsed.port or (443 if scheme == "https" else 80)
    except SSRFBlocked:
        raise
    except (ValueError, UnicodeError) as exc:
        raise SSRFBlocked("invalid_url") from exc
    expected_port = 443 if scheme == "https" else 80
    if port != expected_port:
        raise SSRFBlocked("unsupported_port")
    # Keep the transport request target origin-form, and reject control bytes
    # that could create malformed request lines or headers.
    path = parsed.path or "/"
    query = parsed.query
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path + query):
        raise SSRFBlocked("control_character_in_url")
    try:
        addresses = _resolve_public_addresses(hostname, port)
    except SSRFBlocked:
        raise
    safe_path = quote(path, safe="/%:@!$&'()*+,;=-._~%")
    safe_query = quote(query, safe="/?@!$&'()*+,;=-._~%:")
    request_target = safe_path + (f"?{safe_query}" if query else "")
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    origin = f"{scheme}://{display_host}"
    canonical_url = f"{origin}{request_target}"
    return ValidatedTarget(canonical_url, scheme, hostname, port, request_target, origin, addresses)


def _open_pinned_socket(target: ValidatedTarget, address: str, timeout: float):
    """Connect only to the already validated IP; TLS still verifies the hostname."""
    connection = socket.create_connection((address, target.port), timeout=timeout)
    connection.settimeout(timeout)
    if target.scheme == "https":
        context = ssl.create_default_context()
        try:
            connection = context.wrap_socket(connection, server_hostname=target.hostname)
        except Exception:
            connection.close()
            raise
    return connection


def _request_once(target: ValidatedTarget, method: str, max_bytes: int, timeout: float) -> tuple[int, dict[str, str], int, bool]:
    last_error: OSError | ssl.SSLError | None = None
    for address in target.addresses[:2]:
        connection = None
        response = None
        try:
            connection = _open_pinned_socket(target, address, timeout)
            request = (
                f"{method} {target.request_target} HTTP/1.1\r\n"
                f"Host: {target.host_header}\r\n"
                "User-Agent: ScamGuardURLScanner/1.0\r\n"
                "Accept: text/html, text/plain, application/xhtml+xml;q=0.9, */*;q=0.1\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            headers = {name.lower(): value.strip() for name, value in response.getheaders()}
            body_size = 0
            truncated = False
            if method == "GET":
                body = response.read(max_bytes + 1)
                body_size = min(len(body), max_bytes)
                declared = headers.get("content-length")
                declared_too_large = declared is not None and declared.isdigit() and int(declared) > max_bytes
                truncated = len(body) > max_bytes or declared_too_large
            return response.status, headers, body_size, truncated
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
    if isinstance(last_error, (socket.timeout, TimeoutError)):
        raise FetchUnavailable("request_timed_out") from last_error
    raise FetchUnavailable("connection_failed") from last_error


def safe_fetch(
    url: str,
    method: str = "HEAD",
    max_bytes: int = MAX_BODY_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> SafeFetchResult:
    """Perform only HEAD or bounded GET, validating and pinning every redirect hop.

    GET response bytes are kept only in memory long enough to enforce the cap;
    they are not returned, executed, parsed as scripts, or written to disk.
    """
    method = method.upper()
    if method not in {"HEAD", "GET"}:
        raise SSRFBlocked("method_not_allowed")
    if type(max_bytes) is not int or max_bytes < 0 or max_bytes > MAX_BODY_BYTES:
        raise SSRFBlocked("body_size_limit_exceeded")
    if type(max_redirects) is not int or max_redirects < 0 or max_redirects > MAX_REDIRECTS:
        raise SSRFBlocked("redirect_limit_exceeded")
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0 or timeout > 10:
        raise SSRFBlocked("timeout_limit_exceeded")

    current_url = url
    redirects = 0
    while True:
        target = validate_target(current_url)
        status_code, headers, body_bytes, truncated = _request_once(target, method, max_bytes, timeout)
        if status_code not in REDIRECT_CODES:
            content_length = headers.get("content-length")
            declared_length = int(content_length) if content_length and content_length.isdigit() else None
            return SafeFetchResult(
                status="completed",
                origin=target.origin,
                http_status=status_code,
                content_type=headers.get("content-type"),
                body_bytes=body_bytes,
                body_truncated=truncated,
                redirect_count=redirects,
                content_length=declared_length,
            )
        location = headers.get("location")
        if not location:
            return SafeFetchResult("redirect_without_location", target.origin, status_code, headers.get("content-type"), body_bytes, truncated, redirects)
        if redirects >= max_redirects:
            return SafeFetchResult("redirect_limit", target.origin, status_code, headers.get("content-type"), body_bytes, truncated, redirects)
        current_url = urljoin(target.url, location)
        redirects += 1
