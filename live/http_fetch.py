from typing import Optional
from urllib.parse import urlsplit

import aiohttp
import asyncio

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
        urls = [f"https://{original}"]

    return host.strip().rstrip("."), urls


def _format_redirect_chain(start_url: str, response) -> str:
    if not response.history:
        return f"{start_url} → HTTP {response.status} → {response.url}"
    parts: list[str] = [start_url]
    for h in response.history:
        parts.append(f"→ HTTP {h.status} →")
        parts.append(str(h.url))
    parts.append(f"→ HTTP {response.status} →")
    parts.append(str(response.url))
    return " ".join(parts)


def _history_urls_from_response(response) -> list[str]:
    return [str(item.url) for item in response.history]


async def send_live_request(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> tuple[int, str, list[str], str, str]:
    req_timeout = aiohttp.ClientTimeout(total=timeout, connect=min(10, timeout), sock_read=timeout)

    for attempt in range(retries + 1):
        try:
            async with session.get(
                url,
                timeout=req_timeout,
                ssl=False,
                allow_redirects=follow_redirects,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Referer": "https://www.google.com/",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "sec-ch-ua": '"Chromium";v="126", "Not A(Brand";v="99", "Google Chrome";v="126"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                },
                proxy=proxy_url,
            ) as response:
                body = await response.text(errors="ignore")
                history_urls = _history_urls_from_response(response)
                chain = _format_redirect_chain(url, response)
                return response.status, str(response.url), history_urls, chain, body
        except (asyncio.TimeoutError, aiohttp.ClientConnectionError, aiohttp.ClientError):
            if attempt >= retries:
                raise
            await asyncio.sleep(backoff_base * (2**attempt))


def describe_response(http_code: int, final_url: str, history_urls: list[str]) -> str:
    redirect_count = len(history_urls)
    if redirect_count > 0:
        return f"HTTP {http_code} | Redirect {redirect_count} -> {final_url}"
    return f"HTTP {http_code}"
