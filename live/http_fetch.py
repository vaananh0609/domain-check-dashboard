import asyncio
import ssl
from typing import Any, Optional
from urllib.parse import urlsplit

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
def _build_tls_context(prefer_tls13: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if prefer_tls13:
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
    """Gửi HTTP request và capture TLS version.
    Trả về: (status_code, final_url, history_urls, redirect_chain, body, tls_version, trace_info)
    """
    ssl_ctx = _build_tls_context(prefer_tls13=True)
    trace_info: dict = {"attempts": 0}

    kwargs: dict = {
        "timeout": timeout,
        "allow_redirects": follow_redirects,
        "impersonate": "chrome",
        "verify": False,
        "ssl_context": ssl_ctx,
        "headers": {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": "https://www.google.com/",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    }

    if proxy_url:
        kwargs["proxy"] = proxy_url

    for attempt in range(retries + 1):
        trace_info["attempts"] = attempt + 1
        try:
            response = await session.get(url, **kwargs)

            body = response.text or ""
            history_urls = _history_urls_from_response(response)
            chain = _format_redirect_chain(url, response)

            # Capture TLS version từ response
            raw_tls = None
            try:
                ssl_obj = getattr(response, "ssl_object", None)
                if ssl_obj and hasattr(ssl_obj, "version"):
                    raw_tls = ssl_obj.version()
            except Exception:
                pass

            tls_final = normalize_tls_version(raw_tls)
            trace_info["http_method"] = "curl_cffi"
            trace_info["raw_tls"] = raw_tls
            trace_info["tls_normalized"] = tls_final

            return (
                response.status_code,
                str(response.url),
                history_urls,
                chain,
                body,
                tls_final,
                trace_info,
            )

        except (asyncio.TimeoutError, TimeoutError, RequestsError, OSError, ConnectionError) as e:
            trace_info[f"attempt_{attempt}_error"] = str(type(e).__name__)
            if attempt >= retries:
                raise
            await asyncio.sleep(backoff_base * (2 ** attempt))


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

        # Fallback TLS 1.2
        ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx12.check_hostname = False
        ctx12.verify_mode = ssl.CERT_NONE
        try:
            ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass

        result = await _try("TLS_1.2_fallback", ctx12)
        return (normalize_tls_version(result), trace_info)


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