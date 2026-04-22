# import asyncio
# from typing import Any, Optional
# from urllib.parse import urlsplit

# from curl_cffi.requests import AsyncSession
# from curl_cffi.requests.errors import RequestsError

# from .constants import BACKOFF_BASE_SECONDS, HTTP_RETRIES, USER_AGENT


# def extract_host_and_urls(raw_target: str) -> tuple[str, list[str]]:
#     original = raw_target.strip().lstrip("\ufeff")
#     if not original:
#         return "", []

#     if "://" in original:
#         parsed = urlsplit(original)
#         host = parsed.hostname or ""
#         urls = [original]
#     else:
#         parsed = urlsplit(f"//{original}")
#         host = parsed.hostname or parsed.netloc or ""
#         urls = [f"https://{original}", f"http://{original}"]

#     return host.strip().rstrip("."), urls


# def _format_redirect_chain(start_url: str, response: Any) -> str:
#     history = getattr(response, "history", None) or []
#     if not history:
#         return f"{start_url} → HTTP {response.status_code} → {response.url}"
#     parts: list[str] = [start_url]
#     for h in history:
#         parts.append(f"→ HTTP {h.status_code} →")
#         parts.append(str(h.url))
#     parts.append(f"→ HTTP {response.status_code} →")
#     parts.append(str(response.url))
#     return " ".join(parts)


# def _history_urls_from_response(response: Any) -> list[str]:
#     history = getattr(response, "history", None) or []
#     return [str(item.url) for item in history]


# async def send_live_request(
#     session: AsyncSession,
#     url: str,
#     timeout: int,
#     proxy_url: Optional[str] = None,
#     follow_redirects: bool = True,
#     retries: int = HTTP_RETRIES,
#     backoff_base: float = BACKOFF_BASE_SECONDS,
# ) -> tuple[int, str, list[str], str, str]:
#     kwargs: dict = {
#         "timeout": timeout,
#         "allow_redirects": follow_redirects,
#         "impersonate": "chrome",
#         "verify": False,
#         "headers": {
#             "User-Agent": USER_AGENT,
#             "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#             "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
#             "Referer": "https://www.google.com/",
#             "Cache-Control": "no-cache",
#             "Pragma": "no-cache",
#         },
#     }
#     if proxy_url:
#         kwargs["proxy"] = proxy_url

#     for attempt in range(retries + 1):
#         try:
#             response = await session.get(url, **kwargs)
#             body = response.text if response.text is not None else ""
#             history_urls = _history_urls_from_response(response)
#             chain = _format_redirect_chain(url, response)
#             return response.status_code, str(response.url), history_urls, chain, body
#         except (asyncio.TimeoutError, TimeoutError, RequestsError, OSError, ConnectionError):
#             if attempt >= retries:
#                 raise
#             await asyncio.sleep(backoff_base * (2**attempt))

# async def probe_tls_version(
#     host: str,
#     port: int = 443,
#     timeout: float = 5.0,
#     prefer_tls13: bool = True,
# ) -> Optional[str]:
#     """
#     Kết nối TLS trực tiếp đến host:port, trả về version thực tế được negotiate.
#     Ưu tiên TLS 1.3 nếu prefer_tls13=True; nếu thất bại fallback TLS 1.2.
#     Trả về: "TLSv1.3", "TLSv1.2", "TLSv1.1", ... hoặc None nếu không kết nối được.
#     """
#     async def _try_connect(ctx: ssl.SSLContext) -> Optional[str]:
#         try:
#             reader, writer = await asyncio.wait_for(
#                 asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
#                 timeout=timeout,
#             )
#             tls_ver = writer.get_extra_info("ssl_object").version()
#             writer.close()
#             try:
#                 await writer.wait_closed()
#             except Exception:
#                 pass
#             return tls_ver
#         except Exception:
#             return None

#     if prefer_tls13:
#         # Thử TLS 1.3 trước
#         ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#         ctx13.check_hostname = False
#         ctx13.verify_mode = ssl.CERT_NONE
#         try:
#             ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
#             ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
#         except AttributeError:
#             pass  # Python cũ không hỗ trợ — bỏ qua
#         result = await _try_connect(ctx13)
#         if result:
#             return result

#     # Fallback TLS 1.2
#     ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#     ctx12.check_hostname = False
#     ctx12.verify_mode = ssl.CERT_NONE
#     try:
#         ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
#         ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
#     except AttributeError:
#         pass
#     return await _try_connect(ctx12)

# def describe_response(http_code: int, final_url: str, history_urls: list[str]) -> str:
#     redirect_count = len(history_urls)
#     if redirect_count > 0:
#         return f"HTTP {http_code} | Redirect {redirect_count} -> {final_url}"
#     return f"HTTP {http_code}"

import asyncio
import ssl
from typing import Any, Optional
from urllib.parse import urlsplit

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

from .constants import BACKOFF_BASE_SECONDS, HTTP_RETRIES, USER_AGENT


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


def _format_redirect_chain(start_url: str, response: Any) -> str:
    history = getattr(response, "history", None) or []
    if not history:
        return f"{start_url} → HTTP {response.status_code} → {response.url}"
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


def _build_tls_context(prefer_tls13: bool = True) -> ssl.SSLContext:
    """
    Tạo SSL context ưu tiên TLS 1.3.
    - minimum_version = TLS 1.2  → cho phép fallback nếu server không hỗ trợ 1.3
    - maximum_version = TLS 1.3  → OpenSSL sẽ thương lượng TLS 1.3 trước
    - Nếu Python cũ không hỗ trợ TLSVersion enum, dùng default của hệ thống.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if prefer_tls13:
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # sàn: cho phép fallback TLS 1.2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3  # trần: ưu tiên TLS 1.3
        except AttributeError:
            pass  # Python < 3.7 — dùng default của OpenSSL
    return ctx


async def send_live_request(
    session: AsyncSession,
    url: str,
    timeout: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> tuple[int, str, list[str], str, str]:
    # Ưu tiên TLS 1.3; tự động fallback TLS 1.2 nếu server không hỗ trợ.
    ssl_ctx = _build_tls_context(prefer_tls13=True)

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
        try:
            response = await session.get(url, **kwargs)
            body = response.text if response.text is not None else ""
            history_urls = _history_urls_from_response(response)
            chain = _format_redirect_chain(url, response)
            return response.status_code, str(response.url), history_urls, chain, body
        except (asyncio.TimeoutError, TimeoutError, RequestsError, OSError, ConnectionError):
            if attempt >= retries:
                raise
            await asyncio.sleep(backoff_base * (2**attempt))


async def probe_tls_version(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    prefer_tls13: bool = True,
) -> Optional[str]:
    """
    Kết nối TLS trực tiếp đến host:port, trả về version thực tế được negotiate.
    Ưu tiên TLS 1.3 nếu prefer_tls13=True; nếu thất bại fallback TLS 1.2.
    Trả về: "TLSv1.3", "TLSv1.2", "TLSv1.1", ... hoặc None nếu không kết nối được.
    """
    async def _try_connect(ctx: ssl.SSLContext) -> Optional[str]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )
            tls_ver = writer.get_extra_info("ssl_object").version()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return tls_ver
        except Exception:
            return None

    if prefer_tls13:
        # Thử TLS 1.3 trước
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.check_hostname = False
        ctx13.verify_mode = ssl.CERT_NONE
        try:
            ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass  # Python cũ không hỗ trợ — bỏ qua
        result = await _try_connect(ctx13)
        if result:
            return result

    # Fallback TLS 1.2
    ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx12.check_hostname = False
    ctx12.verify_mode = ssl.CERT_NONE
    try:
        ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass
    return await _try_connect(ctx12)


def describe_response(http_code: int, final_url: str, history_urls: list[str]) -> str:
    redirect_count = len(history_urls)
    if redirect_count > 0:
        return f"HTTP {http_code} | Redirect {redirect_count} -> {final_url}"
    return f"HTTP {http_code}"