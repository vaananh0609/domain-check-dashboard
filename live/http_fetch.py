import asyncio
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


async def send_live_request(
    session: AsyncSession,
    url: str,
    timeout: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> tuple[int, str, list[str], str, str]:
    kwargs: dict = {
        "timeout": timeout,
        "allow_redirects": follow_redirects,
        "impersonate": "chrome",
        "verify": False,
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


def describe_response(http_code: int, final_url: str, history_urls: list[str]) -> str:
    redirect_count = len(history_urls)
    if redirect_count > 0:
        return f"HTTP {http_code} | Redirect {redirect_count} -> {final_url}"
    return f"HTTP {http_code}"
