import asyncio
from typing import List, Optional, Tuple

from .constants import (
    PLAYWRIGHT_HEADLESS,
    PLAYWRIGHT_LOCALE,
    PLAYWRIGHT_POST_NAV_DELAY_SEC,
    PLAYWRIGHT_TIMEZONE,
    PLAYWRIGHT_VIEWPORT_HEIGHT,
    PLAYWRIGHT_VIEWPORT_WIDTH,
    PLAYWRIGHT_WAIT_UNTIL,
)

_STEALTH_INIT = """
(() => {
  try {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  } catch (e) {}
  try {
    window.chrome = { runtime: {} };
  } catch (e) {}
})();
"""


def _redirect_history_urls_from_request(request) -> List[str]:
    """Chuỗi URL các bước redirect (giống aiohttp history), để phân loại PARKED."""
    if not request:
        return []
    out: List[str] = []
    r = request.redirected_from
    while r:
        out.insert(0, r.url)
        r = r.redirected_from
    return out


_CHROMIUM_ARGS = (
    "--disable-blink-features=AutomationControlled",
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-infobars",
    "--window-size=1920,1080",
)


async def fetch_with_playwright(
    url: str,
    timeout: int = 10,
    user_agent: Optional[str] = None,
    extra_headers: Optional[dict] = None,
) -> Tuple[int, str, List[str], str, str]:
    """
    Return (status, final_url, history_urls, body, redirect_chain_note).
    Chromium + bớt dấu automation, viewport/locale/timezone, chờ domcontentloaded (tránh treo networkidle).
    """
    try:
        from playwright.async_api import async_playwright
    except Exception as ex:
        raise RuntimeError("Playwright not installed or cannot be imported") from ex

    viewport = {"width": PLAYWRIGHT_VIEWPORT_WIDTH, "height": PLAYWRIGHT_VIEWPORT_HEIGHT}
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=PLAYWRIGHT_HEADLESS,
            args=list(_CHROMIUM_ARGS),
        )
        context_kwargs: dict = {
            "viewport": viewport,
            "locale": PLAYWRIGHT_LOCALE,
            "timezone_id": PLAYWRIGHT_TIMEZONE,
            "java_script_enabled": True,
            "ignore_https_errors": True,
        }
        if user_agent:
            context_kwargs["user_agent"] = user_agent
        context = await browser.new_context(**context_kwargs)
        await context.add_init_script(_STEALTH_INIT)
        if extra_headers:
            try:
                await context.set_extra_http_headers(extra_headers)
            except Exception:
                pass

        page = await context.new_page()
        try:
            ms = max(1000, int(timeout * 1000))
            response = await page.goto(url, wait_until=PLAYWRIGHT_WAIT_UNTIL, timeout=ms)
            await asyncio.sleep(PLAYWRIGHT_POST_NAV_DELAY_SEC)
            try:
                await page.mouse.wheel(0, 400)
            except Exception:
                pass
            status = response.status if response is not None else 0
            final_url = page.url
            body = await page.content()
            history = _redirect_history_urls_from_request(response.request) if response else []
            if history:
                chain = (
                    f"{url} → "
                    + " → ".join(history)
                    + f" → HTTP {status} → {final_url} (Playwright Chromium)"
                )
            else:
                chain = (
                    f"{url} → HTTP {status} → {final_url} "
                    f"(Playwright Chromium, wait={PLAYWRIGHT_WAIT_UNTIL})"
                )
            return status, final_url, history, body, chain
        finally:
            try:
                await context.close()
            except Exception:
                pass
            try:
                await browser.close()
            except Exception:
                pass
