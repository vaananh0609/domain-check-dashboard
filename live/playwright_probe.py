"""Bước 3 — Playwright với trình duyệt thật + persistent profile (fingerprint tự nhiên)."""

from __future__ import annotations

import asyncio
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from .browser_profiles import (
    get_browser_profile,
    persistent_profile_setup_hint,
    resolve_chrome_executable,
    resolve_chrome_persistent_user_data,
    resolve_coccoc_executable,
    resolve_coccoc_persistent_user_data,
    resolve_edge_persistent_user_data,
)
from .probe_config import active_browser_profile
from .tls_probe import (
    TlsProbeResult,
    browser_http_ver_from_security,
    tls_result_from_browser_security,
)

BROWSER_PROBE_MIN_TIMEOUT_MS = 10_000
BROWSER_PROBE_DEFAULT_TIMEOUT_MS = 30_000
BROWSER_PROBE_MAX_TIMEOUT_MS = 60_000
BROWSER_PROBE_PHASE2_MAX_TIMEOUT_MS = 60_000
BROWSER_PROBE_HEADED_DWELL_MS = 5_000
BROWSER_PROBE_DEEP_PAUSE_MIN_MS = 800
BROWSER_PROBE_DEEP_PAUSE_MAX_MS = 2_500

_playwright_lock = asyncio.Lock()

_CF_IP_PREFIXES = ("104.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.")

# Giảm dấu hiệu automation; không thay UA / sec-ch-ua khi dùng profile thật.
_CHROMIUM_ARGS = (
    "--disable-blink-features=AutomationControlled",
)
_IGNORE_AUTOMATION_ARGS = ("--enable-automation",)

_STEALTH_INIT = """
(() => {
  try {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  } catch (e) {}
})();
"""


@dataclass
class BrowserProbeResult:
    final_status: int
    final_url: str
    document_url: str
    error: str = ""
    waf_suspected: bool = False
    via: str = "playwright/document"
    browser_label: str = ""
    profile_mode: str = ""
    browser_tls: Optional[TlsProbeResult] = None
    browser_http_ver: str = ""


def clamp_browser_timeout_ms(timeout_seconds: int, *, phase2: bool = False) -> int:
    ms = int(timeout_seconds) * 1000
    cap = BROWSER_PROBE_PHASE2_MAX_TIMEOUT_MS if phase2 else BROWSER_PROBE_MAX_TIMEOUT_MS
    return min(max(ms, BROWSER_PROBE_MIN_TIMEOUT_MS), cap)


def _deep_scan_pre_pause_ms() -> int:
    return random.randint(BROWSER_PROBE_DEEP_PAUSE_MIN_MS, BROWSER_PROBE_DEEP_PAUSE_MAX_MS)


def _hints_cloudflare_ip(ips: list[str]) -> bool:
    for raw in ips:
        ip = (raw or "").strip()
        if any(ip.startswith(p) for p in _CF_IP_PREFIXES):
            return True
    return False


def _waf_timeout_guess(error_text: str, connect_ips: list[str]) -> bool:
    low = (error_text or "").lower()
    if "timeout" not in low and "timed out" not in low:
        return False
    return _hints_cloudflare_ip(connect_ips) or "cloudflare" in low


def _profile_in_use_error(error_text: str) -> bool:
    low = (error_text or "").lower()
    return any(
        token in low
        for token in (
            "profile is in use",
            "singletonlock",
            "user data directory is already in use",
            "failed to create data directory",
            "process_singleton",
        )
    )


def _resolve_persistent_user_data(profile_id: str) -> str:
    if profile_id == "coccoc":
        return resolve_coccoc_persistent_user_data()
    if profile_id == "edge":
        return resolve_edge_persistent_user_data()
    if profile_id == "chrome":
        return resolve_chrome_persistent_user_data()
    return ""


def _playwright_launch_target(profile_id: str) -> dict[str, str]:
    """executable_path hoặc channel cho Chromium-based browsers."""
    if profile_id == "coccoc":
        return {"executable_path": resolve_coccoc_executable()}
    if profile_id == "chrome":
        env = (os.environ.get("PROBE_CHROME_EXECUTABLE") or "").strip()
        if env and Path(env).is_file():
            return {"executable_path": env}
        try:
            return {"executable_path": resolve_chrome_executable()}
        except FileNotFoundError:
            return {"channel": "chrome"}
    if profile_id == "edge":
        env = (os.environ.get("PROBE_EDGE_EXECUTABLE") or "").strip()
        if env and Path(env).is_file():
            return {"executable_path": env}
        return {"channel": "msedge"}
    profile = get_browser_profile(profile_id)
    if profile.playwright_channel:
        return {"channel": profile.playwright_channel}
    return {"channel": "chromium"}


def _ephemeral_launch_kwargs(profile_id: str, *, headless: bool) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "headless": headless,
        "args": list(_CHROMIUM_ARGS),
        "ignore_default_args": list(_IGNORE_AUTOMATION_ARGS),
    }
    kw.update(_playwright_launch_target(profile_id))
    return kw


def _persistent_launch_kwargs(profile_id: str, user_data_dir: str, *, headless: bool) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "user_data_dir": user_data_dir,
        "headless": headless,
        "ignore_https_errors": True,
        "args": list(_CHROMIUM_ARGS),
        "ignore_default_args": list(_IGNORE_AUTOMATION_ARGS),
    }
    kw.update(_playwright_launch_target(profile_id))
    return kw


def _attach_document_listener(
    page,
    captured: list[tuple[int, str]],
    security_details: list[dict],
) -> None:
    def on_response(response) -> None:
        try:
            if response.request.resource_type != "document":
                return
            if response.frame and response.frame.parent_frame:
                return
            captured.append((response.status, response.url))
            if not security_details:
                getter = getattr(response, "security_details", None)
                if callable(getter):
                    sd = getter()
                    if sd:
                        security_details.append(dict(sd))
        except Exception:
            pass

    page.on("response", on_response)


def _headed_dwell_ms(headless: bool) -> int:
    raw = (os.environ.get("PROBE_BROWSER_DWELL_MS") or "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return 0 if headless else BROWSER_PROBE_HEADED_DWELL_MS


def _open_probe_page(context) -> Any:
    """Tab mới — tránh tab khôi phục từ profile (NTP / about:blank không có domain)."""
    page = context.new_page()
    try:
        page.bring_to_front()
    except Exception:
        pass
    try:
        page.wait_for_timeout(400)
    except Exception:
        pass
    return page


def _target_host(url: str) -> str:
    return (urlsplit((url or "").strip()).hostname or "").lower().rstrip(".")


def _current_page_host(page) -> str:
    try:
        return (urlsplit((page.url or "").strip()).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _is_blank_browser_url(url: str) -> bool:
    low = (url or "").strip().lower()
    if not low or low == "about:blank":
        return True
    return low.startswith(("about:", "chrome://", "edge://", "coccoc://", "moz-extension://"))


def _navigation_reached_target(page, target_url: str) -> bool:
    try:
        current = (page.url or "").strip()
    except Exception:
        return False
    if _is_blank_browser_url(current):
        return False
    want = _target_host(target_url)
    got = _current_page_host(page)
    if want and got:
        return want == got or got.endswith("." + want) or want.endswith("." + got)
    return bool(got)


def _page_url_safe(page) -> str:
    try:
        return (page.url or "").strip()
    except Exception:
        return ""


def _wait_after_navigation(page, *, timeout_ms: int) -> None:
    try:
        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    try:
        page.wait_for_load_state("load", timeout=min(12_000, timeout_ms))
    except Exception:
        pass
    try:
        page.wait_for_load_state("networkidle", timeout=min(8_000, timeout_ms))
    except Exception:
        pass


def _run_goto(page, url: str, *, timeout_ms: int) -> tuple[str, str]:
    error = ""
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        _wait_after_navigation(page, timeout_ms=timeout_ms)
    except Exception as ex:
        error = str(ex).strip() or type(ex).__name__
    return _page_url_safe(page) or url, error


def _navigate_via_location_assign(page, url: str, *, timeout_ms: int) -> tuple[str, str]:
    error = ""
    try:
        page.evaluate("(u) => { window.location.assign(u); }", url)
        _wait_after_navigation(page, timeout_ms=timeout_ms)
    except Exception as ex:
        error = str(ex).strip() or type(ex).__name__
    return _page_url_safe(page) or url, error


def _navigate_via_omnibox(page, url: str, *, timeout_ms: int) -> tuple[str, str]:
    """Phương án phụ — Cốc Cốc automation thường bỏ qua Ctrl+L (vẫn about:blank)."""
    error = ""
    try:
        page.bring_to_front()
        page.keyboard.press("Control+L")
        page.wait_for_timeout(250)
        page.keyboard.press("Control+KeyA")
        page.keyboard.type(url, delay=25)
        page.keyboard.press("Enter")
        _wait_after_navigation(page, timeout_ms=timeout_ms)
    except Exception as ex:
        error = str(ex).strip() or type(ex).__name__
    return _page_url_safe(page) or url, error


def _navigate_to_target(
    page,
    url: str,
    *,
    timeout_ms: int,
    headed: bool,
) -> tuple[str, str]:
    """Luôn page.goto trước; chỉ coi thành công khi URL thực sự rời about:blank."""
    errors: list[str] = []
    final_url = url

    final_url, err = _run_goto(page, url, timeout_ms=timeout_ms)
    if err:
        errors.append(f"goto: {err}")
    if _navigation_reached_target(page, url):
        return final_url, "; ".join(errors)

    final_url, err = _navigate_via_location_assign(page, url, timeout_ms=timeout_ms)
    if err:
        errors.append(f"location.assign: {err}")
    if _navigation_reached_target(page, url):
        return final_url, "; ".join(errors)

    if headed:
        final_url, err = _navigate_via_omnibox(page, url, timeout_ms=timeout_ms)
        if err:
            errors.append(f"omnibox: {err}")
        if _navigation_reached_target(page, url):
            return final_url, "; ".join(errors)

    stuck = _page_url_safe(page) or "about:blank"
    errors.append(f"không điều hướng được tới {url} (đang ở {stuck})")
    return final_url, "; ".join(errors)


def _probe_sync(
    url: str,
    *,
    timeout_ms: int,
    profile_id: str,
    headless: bool,
    deep_scan: bool = False,
) -> BrowserProbeResult:
    from playwright.sync_api import sync_playwright

    profile = get_browser_profile(profile_id)
    captured: list[tuple[int, str]] = []
    doc_status = 0
    doc_url = url
    final_url = url
    error = ""
    waf = False
    profile_mode = "ephemeral"
    via = f"playwright/{profile.playwright_via_label}"
    if deep_scan:
        via += "+phase2"

    url = (url or "").strip()
    if not url:
        return BrowserProbeResult(
            final_status=0,
            final_url="",
            document_url="",
            error="URL trống — không điều hướng được",
            via=via,
            browser_label=profile.label,
            profile_mode=profile_mode,
        )

    user_data_dir = _resolve_persistent_user_data(profile_id)
    host = _target_host(url)
    security_details: list[dict] = []
    browser_tls: Optional[TlsProbeResult] = None

    with sync_playwright() as pw:
        context = None
        browser = None
        close_fn: Optional[Callable[[], None]] = None

        if user_data_dir:
            try:
                pkw = _persistent_launch_kwargs(profile_id, user_data_dir, headless=headless)
                context = pw.chromium.launch_persistent_context(**pkw)
                profile_mode = "persistent"
                via = f"playwright/{profile.playwright_via_label}+profile"
                if deep_scan:
                    via += "+phase2"
                close_fn = context.close
            except Exception as ex:
                err = str(ex).strip() or type(ex).__name__
                if _profile_in_use_error(err):
                    hint = persistent_profile_setup_hint(profile_id)
                    raise RuntimeError(
                        f"Profile trình duyệt đang bị khóa hoặc đang mở. {hint}"
                    ) from ex
                # Clone lỗi / thiếu — fallback profile trống, vẫn dùng browser.exe thật.

        if context is None:
            browser = pw.chromium.launch(**_ephemeral_launch_kwargs(profile_id, headless=headless))
            context = browser.new_context(ignore_https_errors=True)
            context.add_init_script(_STEALTH_INIT)
            profile_mode = "ephemeral"
            close_fn = browser.close

        if context is None:
            return BrowserProbeResult(
                final_status=0,
                final_url=url,
                document_url=url,
                error=error or "Không mở được trình duyệt",
                via=via,
                browser_label=profile.label,
                profile_mode=profile_mode,
            )

        if profile_mode == "persistent":
            context.add_init_script(_STEALTH_INIT)

        try:
            page = _open_probe_page(context)
            _attach_document_listener(page, captured, security_details)
            if deep_scan:
                try:
                    page.wait_for_timeout(_deep_scan_pre_pause_ms())
                except Exception:
                    pass
            final_url, goto_err = _navigate_to_target(
                page,
                url,
                timeout_ms=timeout_ms,
                headed=not headless,
            )
            if goto_err:
                error = goto_err

            dwell_ms = _headed_dwell_ms(headless)
            if dwell_ms > 0:
                page.wait_for_timeout(dwell_ms)
        finally:
            if close_fn:
                close_fn()

    if captured:
        doc_status, doc_url = captured[-1]
        final_url = final_url or doc_url

    browser_tls: Optional[TlsProbeResult] = None
    browser_http_ver = ""

    if doc_status > 0:
        sd = security_details[-1] if security_details else None
        browser_tls = tls_result_from_browser_security(sd, host, final_url=final_url)
        browser_http_ver = browser_http_ver_from_security(sd)

    if doc_status <= 0 and error and _waf_timeout_guess(error, []):
        waf = True

    return BrowserProbeResult(
        final_status=doc_status,
        final_url=final_url,
        document_url=doc_url,
        error=error,
        waf_suspected=waf,
        via=via,
        browser_label=profile.label,
        profile_mode=profile_mode,
        browser_tls=browser_tls,
        browser_http_ver=browser_http_ver,
    )


async def probe_url_browser(
    url: str,
    *,
    timeout_ms: int = BROWSER_PROBE_DEFAULT_TIMEOUT_MS,
    headless: bool = False,
    connect_ips: Optional[list[str]] = None,
    profile_id: Optional[str] = None,
    deep_scan: bool = False,
    phase2: bool = False,
) -> BrowserProbeResult:
    """
    Một domain / một cửa sổ — khóa toàn cục.
    Cốc Cốc: ưu tiên User Data Automation (clone), không ghi đè UA/fingerprint.
    """
    pid = (profile_id or active_browser_profile().id).strip().lower()
    cap = BROWSER_PROBE_PHASE2_MAX_TIMEOUT_MS if phase2 else BROWSER_PROBE_MAX_TIMEOUT_MS
    if (timeout_ms or 0) >= 1000:
        eff_ms = min(max(int(timeout_ms), BROWSER_PROBE_MIN_TIMEOUT_MS), cap)
    else:
        eff_ms = clamp_browser_timeout_ms(max(1, int(timeout_ms)), phase2=phase2)
    async with _playwright_lock:
        result = await asyncio.to_thread(
            _probe_sync,
            url,
            timeout_ms=eff_ms,
            profile_id=pid,
            headless=headless,
            deep_scan=deep_scan,
        )
    if result.final_status <= 0 and result.error and _waf_timeout_guess(result.error, list(connect_ips or [])):
        result.waf_suspected = True
    return result
