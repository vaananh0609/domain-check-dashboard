import asyncio
import ssl
from typing import Any, Optional
from urllib.parse import urlsplit

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

from .constants import BACKOFF_BASE_SECONDS, HTTP_RETRIES, USER_AGENT


# =========================
# TLS FORMAT HELPER (NEW)
# =========================
def normalize_tls_version(version: Optional[str]) -> str:
    """
    Chuyển đổi TLS version thô thành định dạng chuẩn.
    VD: TLSv1.3 → TLS 1.3
    Nếu không xác định được version thì mặc định dùng TLS 1.3.
    """
    if not version:
        return "-"

    mapping = {
        "TLSv1.3": "TLS 1.3",
        "TLSv1.2": "TLS 1.2",
        "TLSv1.1": "TLS 1.1",
        "TLSv1": "TLS 1.0",
    }
    return mapping.get(version, str(version))


def format_protocol_info(http_version: Optional[str], tls_version: Optional[str]) -> str:
    """
    Format protocol + TLS version information.
    VD: "HTTP/3 QUIC (TLS 1.3)", "HTTP/2 (TLS 1.3)", "HTTP/1.1 (TLS 1.2)"
    """
    if not http_version:
        http_version = "HTTP/1.1"
    
    if not tls_version:
        tls_version = "-"
    
    # HTTP/3 with QUIC
    if "h3" in http_version.lower() or "3" in http_version:
        return f"HTTP/3 QUIC ({tls_version})"
    # HTTP/2
    elif "2" in http_version:
        return f"HTTP/2 ({tls_version})"
    # HTTP/1.1 or HTTP/1.0
    else:
        return f"{http_version} ({tls_version})"


def _extract_raw_tls(response: Any) -> Optional[str]:
    try:
        ssl_obj = getattr(response, "ssl_object", None)
        if ssl_obj and hasattr(ssl_obj, "version"):
            return ssl_obj.version()
    except Exception:
        pass
    return None


# =========================
# URL PARSER
# =========================
def extract_host_and_urls(raw_target: str) -> tuple[str, list[str]]:
    original = raw_target.strip().lstrip("\ufeff")
    if not original:
        return "", []

    if "://" in original:
        parsed = urlsplit(original)
        host = parsed.hostname or ""
        urls = [original]
    else:
        parsed = urlsplit(f"//{original}")
        host = parsed.hostname or parsed.netloc or ""
        urls = [f"https://{original}", f"http://{original}"]

    return host.strip().rstrip("."), urls


# =========================
# REDIRECT CHAIN
# =========================
def _format_redirect_chain(start_url: str, response: Any) -> str:
    history = getattr(response, "history", None) or []
    if not history:
        return "—"  # Không có redirect, hiển thị "-"

    parts: list[str] = [start_url]
    for h in history:
        parts.append(f"→ HTTP {h.status_code} →")
        parts.append(str(h.url))

    parts.append(f"→ HTTP {response.status_code} →")
    parts.append(str(response.url))
    return " ".join(parts)


def _history_urls_from_response(response: Any) -> list[str]:
    history = getattr(response, "history", None) or []
    return [str(item.url) for item in history]


# =========================
# TLS CONTEXT
# =========================
def _build_tls_context(prefer_tls13: bool = True, force_tls13: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if force_tls13:
        # Bắt buộc TLS 1.3 (min=max=1.3)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass
    else:
        # Ưu tiên 1.3 nhưng cho phép fallback 1.2 (min=1.2, max=1.3)
        # Server sẽ chọn version cao nhất mà cả hai bên hỗ trợ
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass

    return ctx


# =========================
# LIVE REQUEST
# =========================
async def send_live_request(
    session: AsyncSession,
    url: str,
    timeout: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> tuple[int, str, list[str], str, str, str, dict]:
    """Gửi HTTP request với ưu tiên protocol: HTTP/3 QUIC → HTTP/2 TLS 1.3 → HTTP/1.1 TLS 1.3 → HTTP/1.1 TLS 1.2
    Trả về: (status_code, final_url, history_urls, redirect_chain, body, protocol_info, trace_info)
    """
    trace_info: dict = {"attempts": 0, "protocol_used": None}
    protocol_info = None

    # Thứ tự ưu tiên: HTTP/3 QUIC → HTTP/2 TLS 1.3 → HTTP/1.1 TLS 1.3 → HTTP/1.1 TLS 1.2
    protocols = [
        ("HTTP/3", "QUIC", "TLS 1.3", True),     # HTTP/3 QUIC TLS 1.3
        ("HTTP/2", "TCP", "TLS 1.3", True),      # HTTP/2 TLS 1.3
        ("HTTP/1.1", "TCP", "TLS 1.3", True),    # HTTP/1.1 TLS 1.3
        ("HTTP/1.1", "TCP", "TLS 1.2", False),   # HTTP/1.1 TLS 1.2
    ]

    for http_version, transport, tls_version, force_tls13 in protocols:
        ssl_ctx = _build_tls_context(force_tls13=force_tls13)
        
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": "https://www.google.com/",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

        for attempt in range(retries + 1):
            trace_info["attempts"] = attempt + 1
            protocol_label = f"{http_version} {transport} ({tls_version})"
            trace_info["testing_protocol"] = protocol_label
            
            try:
                # HTTP/3 QUIC - thử dùng httpx nếu available
                if "3" in http_version and HAS_HTTPX:
                    try:
                        client_kwargs = {
                            "http2": False,
                            "http3": True,
                            "verify": False,
                            "timeout": timeout,
                            "headers": headers,
                        }
                        if proxy_url:
                            client_kwargs["proxies"] = proxy_url
                        async with httpx.AsyncClient(**client_kwargs) as client:
                            response = await client.get(url, follow_redirects=follow_redirects)
                            http_version_used = "HTTP/3"
                    except Exception:
                        # HTTP/3 not supported by server, try next protocol
                        trace_info[f"attempt_{attempt}_error_{protocol_label}"] = "HTTP/3_not_supported"
                        break
                else:
                    # HTTP/1.1 và HTTP/2 - dùng curl_cffi
                    kwargs = {
                        "timeout": timeout,
                        "allow_redirects": follow_redirects,
                        "impersonate": "chrome",
                        "verify": False,
                        "ssl_context": ssl_ctx,
                        "headers": headers,
                    }
                    if proxy_url:
                        kwargs["proxy"] = proxy_url
                    
                    response = await session.get(url, **kwargs)
                    http_version_used = http_version

                body = response.text or ""
                history_urls = _history_urls_from_response(response)
                chain = _format_redirect_chain(url, response)

                # Trích xuất actual TLS version từ response
                actual_tls = _extract_raw_tls(response)
                if actual_tls:
                    tls_normalized = normalize_tls_version(actual_tls)
                else:
                    tls_normalized = tls_version

                # Format protocol info
                transport_used = "QUIC" if "3" in http_version_used else "TCP"
                protocol_info = format_protocol_info(http_version_used, tls_normalized)
                trace_info["protocol_used"] = protocol_info
                trace_info["http_version"] = http_version_used
                trace_info["tls_version"] = tls_normalized
                trace_info["transport"] = transport_used
                trace_info["http_method"] = "httpx" if http_version_used == "HTTP/3" else "curl_cffi"

                return (
                    response.status_code,
                    str(response.url),
                    history_urls,
                    chain,
                    body,
                    protocol_info,
                    trace_info,
                )

            except (asyncio.TimeoutError, TimeoutError, RequestsError, OSError, ConnectionError) as e:
                trace_info[f"attempt_{attempt}_error_{protocol_label}"] = str(type(e).__name__)
                if attempt >= retries:
                    # Hết retry cho protocol này, thử protocol khác
                    break
                await asyncio.sleep(backoff_base * (2 ** attempt))

    # Nếu tất cả protocols đều fail
    raise ConnectionError(f"Failed to connect with all protocols (HTTP/3, HTTP/2, HTTP/1.1). Trace: {trace_info}")


# =========================
# TLS PROBE (OPTIONAL)
# =========================
async def probe_tls_version(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    force_tls12: bool = False,
) -> tuple[Optional[str], dict]:
    """Probe TLS version trực tiếp qua TCP+SSL.
    
    Args:
        host: Target hostname
        port: Target port (default 443)
        timeout: Connection timeout
        force_tls12: Nếu True, chỉ test TLS 1.2; False => test 1.3 rồi fallback 1.2
    
    Returns:
        (tls_version, trace_info dict)
    """
    trace_info: dict = {"method": "direct_ssl_probe", "results": {}}

    async def _try(version_name: str, ctx: ssl.SSLContext) -> Optional[str]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if ssl_obj and hasattr(ssl_obj, "version"):
                raw_version = ssl_obj.version()
                trace_info["results"][version_name] = raw_version
                return raw_version
            return None

        except Exception as e:
            trace_info["results"][f"{version_name}_error"] = str(type(e).__name__)
            return None

    if force_tls12:
        # Chỉ test TLS 1.2
        ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx12.check_hostname = False
        ctx12.verify_mode = ssl.CERT_NONE
        try:
            ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
        raw_tls = await _try("TLS_1.2_only", ctx12)
        return (normalize_tls_version(raw_tls), trace_info)
    else:
        # Test TLS 1.3 trước, rồi fallback TLS 1.2
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.check_hostname = False
        ctx13.verify_mode = ssl.CERT_NONE
        try:
            ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
        except Exception:
            pass

        result = await _try("TLS_1.3", ctx13)
        if result:
            return (normalize_tls_version(result), trace_info)

        # Fallback TLS 1.2 (ưu tiên 1.3 nhưng cho phép 1.2)
        ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx12.check_hostname = False
        ctx12.verify_mode = ssl.CERT_NONE
        try:
            ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx12.maximum_version = ssl.TLSVersion.TLSv1_3
        except Exception:
            pass

        result = await _try("TLS_1.2_fallback", ctx12)
        formatted = format_protocol_info("HTTP/1.1", normalize_tls_version(result))
        return (formatted, trace_info)


# =========================
# RESPONSE SUMMARY
# =========================
def describe_response(http_code: int, final_url: str, history_urls: list[str]) -> str:
    redirect_count = len(history_urls)
    if redirect_count > 0:
        return f"HTTP {http_code} | Redirect {redirect_count} -> {final_url}"
    return f"HTTP {http_code}"


def format_trace_info(trace: dict) -> str:
    """Format trace info dict thành string readable."""
    if not trace:
        return ""
    parts = []
    for k, v in trace.items():
        if k == "results" and isinstance(v, dict):
            for rk, rv in v.items():
                parts.append(f"{rk}:{rv}")
        elif k not in ("attempts", "method"):
            parts.append(f"{k}:{v}")
    return " | ".join(parts) if parts else ""