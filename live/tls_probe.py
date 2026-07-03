"""Probe TLS trực tiếp tới domain (không qua Cloudflare Worker)."""

from __future__ import annotations

import asyncio
import datetime
import html
import ssl
from dataclasses import dataclass
from typing import Optional

_KNOWN_CA: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "let's encrypt": "Let's Encrypt",
    "google trust": "Google Trust",
    "digicert": "DigiCert",
    "amazon": "Amazon",
    "sectigo": "Sectigo",
    "globalsign": "GlobalSign",
    "zerossl": "ZeroSSL",
}

_FAILURE_LABELS: dict[str, str] = {
    "sni_reset": "SNI Reset",
    "timeout": "Timeout",
    "tcp_refused": "TCP Refused",
    "cert_expired": "Cert Expired",
    "cert_mismatch": "Cert Mismatch",
    "ssl_error": "SSL Error",
    "unknown": "Fail",
}


@dataclass
class TlsProbeResult:
    version: str
    negotiated: str
    error: str
    attempt_log: str = ""
    cert_status: str = "—"
    issuer: str = "—"
    hostname_match: bool = True
    failure_kind: str = ""

    @property
    def ok(self) -> bool:
        return self.version not in ("—", "", "FAIL")

    @property
    def cert_dead(self) -> bool:
        return self.cert_status in ("Expired", "Hostname mismatch", "Invalid")


def classify_tls_exception(ex: BaseException) -> str:
    if isinstance(ex, ConnectionResetError):
        return "sni_reset"
    if isinstance(ex, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(ex, ConnectionRefusedError):
        return "tcp_refused"
    if isinstance(ex, ssl.SSLError):
        msg = str(ex).lower()
        if "certificate has expired" in msg or "certificate verify failed" in msg:
            return "cert_expired"
        if "hostname" in msg or "doesn't match" in msg or "does not match" in msg:
            return "cert_mismatch"
        return "ssl_error"
    if isinstance(ex, (ConnectionError, OSError)):
        if isinstance(ex, ConnectionAbortedError):
            return "sni_reset"
        msg = str(ex).lower()
        if "reset" in msg or "forcibly closed" in msg:
            return "sni_reset"
        return "ssl_error"
    return "unknown"


def short_ca_from_issuer(issuer: str) -> str:
    if not issuer or issuer == "—":
        return ""
    low = issuer.lower()
    for needle, name in _KNOWN_CA.items():
        if needle in low:
            return name
    for part in issuer.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip()[:40]
    return issuer[:30]


def _negotiated_to_label(negotiated: str) -> str:
    mapping = {
        "TLSv1.3": "TLS 1.3",
        "TLSv1.2": "TLS 1.2",
        "TLSv1.1": "TLS 1.1",
        "TLSv1": "TLS 1.0",
    }
    return mapping.get(negotiated, negotiated or "—")


def _protocol_label(result: TlsProbeResult) -> str:
    if result.version and result.version not in ("FAIL", "—"):
        return result.version
    return _negotiated_to_label(result.negotiated)


def _cert_flat(result: TlsProbeResult) -> str:
    status = result.cert_status
    if status in ("—", "", "FAIL"):
        return ""
    org = short_ca_from_issuer(result.issuer)
    if status == "Valid":
        return f"Valid ({org})" if org else "Valid"
    if status == "Expired":
        return "Expired"
    if status == "Hostname mismatch" or not result.hostname_match:
        return "Mismatch"
    if status in ("Unverified", "Present (unverified)"):
        return status
    return status


def _failure_label(kind: str) -> str:
    return _FAILURE_LABELS.get(kind, _FAILURE_LABELS["unknown"])


def _issuer_from_cert_dict(cert: dict) -> str:
    issuer = cert.get("issuer")
    if not issuer:
        return "—"
    parts: list[str] = []
    for rdn in issuer:
        for key, val in rdn:
            parts.append(f"{key}={val}")
    return ", ".join(parts) if parts else "—"


def _cert_status_from_dict(cert: dict, hostname: str) -> tuple[str, bool]:
    """Trả (cert_status, hostname_match)."""
    hostname_match = True
    try:
        ssl.match_hostname(cert, hostname)
    except ssl.CertificateError:
        hostname_match = False
        return "Hostname mismatch", False
    except Exception:
        pass

    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if exp.replace(tzinfo=datetime.timezone.utc) < datetime.datetime.now(datetime.timezone.utc):
                return "Expired", hostname_match
        except ValueError:
            pass
    return "Valid", hostname_match


def _parse_cert_from_ssl(ssl_obj: ssl.SSLObject, hostname: str) -> tuple[str, str, bool]:
    """Đọc issuer + trạng thái chứng chỉ từ SSLObject."""
    cert = ssl_obj.getpeercert()
    if not cert:
        der = ssl_obj.getpeercert(binary_form=True)
        if not der:
            return "Unverified", "—", True
        return "Present (unverified)", "—", True

    issuer = _issuer_from_cert_dict(cert)
    status, hostname_match = _cert_status_from_dict(cert, hostname)
    return status, issuer, hostname_match


@dataclass
class LayerTrace:
    dns: str = "—"
    tcp: str = "—"
    tls: str = "—"
    http: str = "—"

    def format(self) -> str:
        return f"DNS->{self.dns} | TCP->{self.tcp} | TLS->{self.tls} | HTTP->{self.http}"


def _ssl_context(min_ver: ssl.TLSVersion, max_ver: ssl.TLSVersion) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    # Ép handshake mới — không resume session ticket (tránh TLS cache giữa các lần quét).
    if hasattr(ssl, "OP_NO_TICKET"):
        ctx.options |= ssl.OP_NO_TICKET
    return ctx


async def _tls_handshake(
    host: str,
    *,
    port: int = 443,
    server_hostname: Optional[str] = None,
    min_ver: ssl.TLSVersion,
    max_ver: ssl.TLSVersion,
    timeout: float,
) -> tuple[str, str, str, bool]:
    """Trả (negotiated_tls, cert_status, issuer, hostname_match)."""
    sni = server_hostname or host
    ctx = _ssl_context(min_ver, max_ver)
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
        timeout=timeout,
    )
    ssl_obj = writer.get_extra_info("ssl_object")
    negotiated = ssl_obj.version() if ssl_obj else "?"
    cert_status, issuer, hostname_match = "—", "—", True
    if ssl_obj:
        cert_status, issuer, hostname_match = _parse_cert_from_ssl(ssl_obj, sni)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return negotiated or "?", cert_status, issuer, hostname_match


def _cert_failure_kind(cert_status: str, hostname_match: bool) -> str:
    if cert_status == "Expired":
        return "cert_expired"
    if cert_status == "Hostname mismatch" or not hostname_match:
        return "cert_mismatch"
    return ""


_BROWSER_TLS_VERSION_MAP: dict[str, str] = {
    "QUIC": "TLS 1.3",
    "TLS 1.3": "TLS 1.3",
    "TLS 1.2": "TLS 1.2",
    "TLS 1.1": "TLS 1.1",
    "TLS 1.0": "TLS 1.0",
    "TLS 1": "TLS 1.0",
}

_BROWSER_HTTP_VER_MAP: dict[str, str] = {
    "QUIC": "h3",
    "TLS 1.3": "h2",
    "TLS 1.2": "h2",
    "TLS 1.1": "HTTP/1.1",
    "TLS 1.0": "HTTP/1.1",
    "TLS 1": "HTTP/1.1",
}


def browser_http_ver_from_security(details: dict | None) -> str:
    """HTTP Ver (h2/h3) từ Playwright security_details — không ghi vào cột TLS."""
    if not details:
        return ""
    protocol = str(details.get("protocol") or "").strip()
    return _BROWSER_HTTP_VER_MAP.get(protocol, "")


def _browser_tls_version_label(protocol: str) -> str:
    p = (protocol or "").strip()
    if not p:
        return "TLS (browser)"
    return _BROWSER_TLS_VERSION_MAP.get(p, p)


def _hostnames_match(cert_name: str, host: str) -> bool:
    cn = (cert_name or "").strip().lower().rstrip(".")
    want = (host or "").strip().lower().rstrip(".")
    if not want or not cn:
        return True
    if cn == want:
        return True
    if cn.startswith("*.") and (want == cn[2:] or want.endswith("." + cn[2:])):
        return True
    want_apex = want[4:] if want.startswith("www.") else want
    cn_apex = cn[4:] if cn.startswith("www.") else cn
    if want_apex and cn_apex and want_apex == cn_apex:
        return True
    if cn.startswith("*.") and want_apex and (want_apex == cn[2:] or want.endswith("." + cn[2:])):
        return True
    return False


def _cert_status_from_browser_timestamps(details: dict) -> str:
    valid_to = details.get("validTo")
    try:
        if valid_to is not None:
            exp = datetime.datetime.utcfromtimestamp(int(valid_to))
            if exp < datetime.datetime.utcnow():
                return "Expired"
    except (TypeError, ValueError, OSError):
        pass
    return "Valid"


def tls_result_from_browser_security(
    details: dict | None,
    host: str,
    *,
    final_url: str = "",
) -> Optional[TlsProbeResult]:
    """TLS/QUIC từ Playwright Response.security_details() sau khi trình duyệt tải HTTPS."""
    url_low = (final_url or "").strip().lower()
    if not details:
        if url_low.startswith("https://"):
            return TlsProbeResult(
                version="TLS (browser)",
                negotiated="",
                error="",
                attempt_log="browser https ok, no security_details",
                cert_status="—",
                issuer="—",
                hostname_match=True,
                failure_kind="",
            )
        return None

    protocol = str(details.get("protocol") or "").strip()
    version_label = _browser_tls_version_label(protocol)
    issuer = str(details.get("issuer") or "—").strip() or "—"
    subject = str(details.get("subjectName") or host).strip()
    cert_status = _cert_status_from_browser_timestamps(details)
    hostname_match = _hostnames_match(subject, host)
    if cert_status == "Valid" and not hostname_match:
        cert_status = "Hostname mismatch"

    return TlsProbeResult(
        version=version_label,
        negotiated=protocol,
        error="",
        attempt_log=f"browser security_details protocol={protocol or '?'}",
        cert_status=cert_status,
        issuer=issuer,
        hostname_match=hostname_match,
        failure_kind=_cert_failure_kind(cert_status, hostname_match),
    )


async def probe_tls_version(
    host: str,
    *,
    port: int = 443,
    connect_host: Optional[str] = None,
    timeout: float = 5.0,
) -> TlsProbeResult:
    """Một handshake TLS 1.2–1.3; server chọn version cao nhất hỗ trợ."""
    target = connect_host or host
    min_ver = ssl.TLSVersion.TLSv1_2
    max_ver = ssl.TLSVersion.TLSv1_3
    try:
        negotiated, cert_status, issuer, hostname_match = await _tls_handshake(
            target,
            port=port,
            server_hostname=host,
            min_ver=min_ver,
            max_ver=max_ver,
            timeout=timeout,
        )
        version_label = _negotiated_to_label(negotiated)
        failure_kind = _cert_failure_kind(cert_status, hostname_match)
        return TlsProbeResult(
            version=version_label,
            negotiated=negotiated,
            error="",
            attempt_log=f"negotiated={negotiated}",
            cert_status=cert_status,
            issuer=issuer,
            hostname_match=hostname_match,
            failure_kind=failure_kind,
        )
    except Exception as ex:
        failure_kind = classify_tls_exception(ex)
        return TlsProbeResult(
            version="FAIL",
            negotiated="",
            error=f"{type(ex).__name__}: {ex}"[:200],
            attempt_log=f"handshake FAIL ({failure_kind})",
            cert_status="FAIL",
            issuer="—",
            hostname_match=False,
            failure_kind=failure_kind,
        )


async def probe_tls_on_ips(
    host: str,
    ips: list[str],
    *,
    port: int = 443,
    timeout: float = 5.0,
) -> TlsProbeResult:
    if not ips:
        return await probe_tls_version(host, port=port, timeout=timeout)

    last = TlsProbeResult(
        version="FAIL",
        negotiated="",
        error="no IP",
        attempt_log="",
        cert_status="FAIL",
        failure_kind="unknown",
    )
    for ip in ips[:4]:
        result = await probe_tls_version(host, port=port, connect_host=ip, timeout=timeout)
        if result.ok:
            return result
        last = result
    return last


async def probe_udp443(ip: str, timeout: float = 3.0) -> bool:
    """
    Gửi gói UDP tới :443. Không ICMP unreachable nhanh → có thể có QUIC/HTTP/3.
    (Firewall chặn TCP TLS nhưng để UDP 443 mở là pattern phổ biến.)
    """
    try:
        loop = asyncio.get_running_loop()
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=(ip, 443)),
            timeout=timeout,
        )
        try:
            transport.send(b"\x00")
            await asyncio.sleep(min(0.35, timeout * 0.2))
            return True
        finally:
            transport.close()
    except OSError:
        return False
    except Exception:
        return False


async def probe_tcp(ip: str, port: int = 443, timeout: float = 5.0) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def probe_tcp_port_label(
    ips: list[str],
    port: int,
    *,
    timeout: float = 5.0,
    max_ips: int = 4,
) -> str:
    """OK ip:port / FAIL / —"""
    candidates = [ip for ip in ips if ip][:max_ips]
    if not candidates:
        return "—"
    for ip in candidates:
        if await probe_tcp(ip, port=port, timeout=timeout):
            return f"OK {ip}:{port}"
    return "FAIL"


async def probe_tcp_both(
    ips: list[str],
    *,
    timeout: float = 5.0,
) -> tuple[str, str]:
    if not ips:
        return "—", "—"
    tcp_80, tcp_443 = await asyncio.gather(
        probe_tcp_port_label(ips, 80, timeout=timeout),
        probe_tcp_port_label(ips, 443, timeout=timeout),
    )
    return tcp_80, tcp_443


def format_tls_column(result: TlsProbeResult) -> str:
    """Chuỗi phẳng cho CSV/export/sort."""
    if result.ok:
        parts = ["OK", _protocol_label(result)]
        cert_part = _cert_flat(result)
        if cert_part:
            parts.append(cert_part)
        return " · ".join(parts)
    if result.version == "FAIL":
        label = _failure_label(result.failure_kind)
        if result.error and result.failure_kind in ("ssl_error", "unknown"):
            short_err = result.error.split(":", 1)[0][:40]
            return f"{label} ({short_err})"
        return label
    return "—"


def _badge(text: str, css_class: str, *, title: str = "") -> str:
    safe = html.escape(text)
    title_attr = f' title="{html.escape(title)}"' if title else ""
    return f'<span class="tls-badge {css_class}"{title_attr}>{safe}</span>'


def _cert_badge(result: TlsProbeResult) -> str:
    flat = _cert_flat(result)
    if not flat:
        return ""
    if flat.startswith("Valid"):
        org = short_ca_from_issuer(result.issuer)
        label = f"Valid ({org})" if org else "Valid"
        title = result.issuer if result.issuer != "—" else ""
        return _badge(label, "tls-cert-valid", title=title)
    if flat == "Expired":
        return _badge("Expired", "tls-cert-bad")
    if flat == "Mismatch":
        return _badge("Mismatch", "tls-cert-bad", title=result.issuer)
    return _badge(flat, "tls-cert-warn")


def _proto_badge(label: str) -> str:
    css = "tls-proto-13" if "1.3" in label else "tls-proto-12"
    return _badge(label, css)


def format_tls_html(result: TlsProbeResult) -> str:
    """Badge HTML cho dashboard."""
    if result.ok:
        title = result.attempt_log or result.error
        bits = [
            _badge("OK", "tls-ok", title=title),
            _proto_badge(_protocol_label(result)),
            _cert_badge(result),
        ]
        return '<span class="tls-badges">' + "".join(b for b in bits if b) + "</span>"
    if result.version == "FAIL":
        label = _failure_label(result.failure_kind)
        css = {
            "sni_reset": "tls-fail-reset",
            "timeout": "tls-fail-timeout",
            "cert_expired": "tls-cert-bad",
            "cert_mismatch": "tls-cert-bad",
        }.get(result.failure_kind, "tls-fail")
        title = result.error or result.attempt_log
        return '<span class="tls-badges">' + _badge(label, css, title=title) + "</span>"
    return ""


def tls_column_to_html(text: str) -> str:
    """Chuyển chuỗi phẳng COL_TLS (từ CSV) sang badge HTML."""
    s = (text or "").strip()
    if not s or s == "—":
        return ""
    if s.startswith("OK"):
        parts = [p.strip() for p in s.split("·")]
        bits: list[str] = []
        for i, part in enumerate(parts):
            if i == 0:
                bits.append(_badge(part, "tls-ok"))
            elif part.startswith("TLS"):
                bits.append(_proto_badge(part))
            elif part.startswith("Valid"):
                bits.append(_badge(part, "tls-cert-valid"))
            elif part in ("Expired", "Mismatch"):
                bits.append(_badge(part, "tls-cert-bad"))
            else:
                bits.append(_badge(part, "tls-cert-warn"))
        return '<span class="tls-badges">' + "".join(bits) + "</span>"
    css = "tls-fail-reset" if s == "SNI Reset" else "tls-fail-timeout" if s == "Timeout" else "tls-fail"
    if s.startswith("Cert"):
        css = "tls-cert-bad"
    return '<span class="tls-badges">' + _badge(s, css) + "</span>"


async def run_layer_trace(
    host: str,
    url: str,
    local_ips: list[str],
    *,
    dns_summary: str,
    timeout: float,
    http_probe_coro,
) -> LayerTrace:
    trace = LayerTrace(dns=dns_summary)

    tcp_ip = ""
    for ip in local_ips[:4]:
        if await probe_tcp(ip, port=443, timeout=timeout):
            tcp_ip = ip
            break
    trace.tcp = f"OK {tcp_ip}:443" if tcp_ip else "FAIL"

    tls_result = await probe_tls_on_ips(host, local_ips, timeout=timeout)
    if tls_result.ok:
        trace.tls = format_tls_column(tls_result)
    else:
        err = tls_result.error[:80] if tls_result.error else _failure_label(tls_result.failure_kind)
        trace.tls = f"{_failure_label(tls_result.failure_kind)} ({err})"

    try:
        probe = await http_probe_coro()
        if hasattr(probe, "http_display"):
            result = probe
        else:
            status_code, final_url, _history, chain, _body = probe
            trace.http = f"HTTP {status_code} -> {final_url[:60]}"
            return trace
        if result.final_status > 0:
            cf = " CF" if result.is_cloudflare else ""
            trace.http = f"HTTP {result.http_display}{cf} -> {result.final_url[:50]}"
        else:
            trace.http = "FAIL"
    except Exception as ex:
        trace.http = f"FAIL ({type(ex).__name__})"

    return trace
