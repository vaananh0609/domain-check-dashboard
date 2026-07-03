"""Cấu hình mô phỏng trình duyệt — Edge, Chrome, Cốc Cốc."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .constants import (
    USER_AGENT_CHROME_149,
    USER_AGENT_COCCOC_154,
    USER_AGENT_EDGE_149,
)

_PROFILE_ENV = "PROBE_BROWSER_PROFILE"

COCCOC_BROWSER_EXE_CANDIDATES: tuple[str, ...] = (
    r"C:\Program Files\CocCoc\Browser\Application\browser.exe",
    r"C:\Program Files (x86)\CocCoc\Browser\Application\browser.exe",
)

CHROME_BROWSER_EXE_CANDIDATES: tuple[str, ...] = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
)

COCCOC_USER_DATA_AUTOMATION_SUFFIX = ("CocCoc", "Browser", "User Data Automation")
EDGE_USER_DATA_AUTOMATION_SUFFIX = ("Microsoft", "Edge", "User Data Automation")
CHROME_USER_DATA_AUTOMATION_SUFFIX = ("Google", "Chrome", "User Data Automation")
DEFAULT_COCCOC_USER_DATA_DIR = r"E:\User Data Coccoc"
DEFAULT_EDGE_USER_DATA_DIR = r"E:\User Data Edge"
DEFAULT_CHROME_USER_DATA_DIR = r"E:\User Data Chrome"


@dataclass(frozen=True)
class BrowserProfile:
    id: str
    label: str
    user_agent: str
    impersonate: str
    accept_language: str
    client_hints: dict[str, str] = field(default_factory=dict)
    prefer_http3_first: bool = True
    probe_dns_mode: str = "isp"
    doh_provider: str = ""
    playwright_channel: str = ""
    playwright_executable: str = ""
    playwright_persistent_user_data: str = ""
    playwright_engine: str = "chromium"

    @property
    def playwright_via_label(self) -> str:
        if self.id == "coccoc":
            return "coccoc"
        if self.id == "edge":
            return "msedge"
        if self.id == "chrome":
            return "chrome"
        return "browser"

    @property
    def doh_label(self) -> str:
        return {"google": "Google DoH", "cloudflare": "Cloudflare DoH"}.get(
            self.doh_provider, self.doh_provider
        )

    @property
    def dns_mode_label(self) -> str:
        if self.probe_dns_mode == "doh":
            return f"DoH ({self.doh_label})"
        return "DNS ISP (local)"


_PROFILES: dict[str, BrowserProfile] = {
    "edge": BrowserProfile(
        id="edge",
        label="Microsoft Edge 149",
        user_agent=USER_AGENT_EDGE_149,
        impersonate="chrome142",
        accept_language="en-US,en;q=0.9",
        client_hints={
            "sec-ch-ua": '"Microsoft Edge";v="149", "Chromium";v="149", "Not.A/Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        prefer_http3_first=True,
        probe_dns_mode="doh",
        doh_provider="google",
        playwright_channel="msedge",
    ),
    "chrome": BrowserProfile(
        id="chrome",
        label="Google Chrome 149",
        user_agent=USER_AGENT_CHROME_149,
        impersonate="chrome142",
        accept_language="en-US,en;q=0.9",
        client_hints={
            "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not.A/Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        prefer_http3_first=True,
        probe_dns_mode="doh",
        doh_provider="google",
        playwright_channel="chrome",
    ),
    "coccoc": BrowserProfile(
        id="coccoc",
        label="Cốc Cốc 154",
        user_agent=USER_AGENT_COCCOC_154,
        impersonate="chrome142",
        accept_language="vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        client_hints={
            "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not.A/Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        prefer_http3_first=True,
        probe_dns_mode="isp",
        doh_provider="",
        playwright_executable=COCCOC_BROWSER_EXE_CANDIDATES[0],
    ),
}

DEFAULT_PROFILE_ID = "edge"


def get_browser_profile(profile_id: str | None) -> BrowserProfile:
    key = (profile_id or DEFAULT_PROFILE_ID).strip().lower()
    return _PROFILES.get(key, _PROFILES[DEFAULT_PROFILE_ID])


def list_browser_profile_ids() -> tuple[str, ...]:
    return tuple(_PROFILES.keys())


def resolve_coccoc_executable() -> str:
    import os

    override = (os.environ.get("PROBE_COCCOC_EXECUTABLE") or "").strip()
    if override and Path(override).is_file():
        return override
    for raw in COCCOC_BROWSER_EXE_CANDIDATES:
        p = Path(raw)
        if p.is_file():
            return str(p)
    raise FileNotFoundError(
        "Không tìm thấy Cốc Cốc (browser.exe). "
        "Cài Cốc Cốc hoặc đặt PROBE_COCCOC_EXECUTABLE=đường_dẫn\\browser.exe"
    )


def resolve_chrome_executable() -> str:
    import os

    override = (os.environ.get("PROBE_CHROME_EXECUTABLE") or "").strip()
    if override and Path(override).is_file():
        return override
    for raw in CHROME_BROWSER_EXE_CANDIDATES:
        p = Path(raw)
        if p.is_file():
            return str(p)
    raise FileNotFoundError(
        "Không tìm thấy chrome.exe. "
        "Cài Google Chrome hoặc đặt PROBE_CHROME_EXECUTABLE=đường_dẫn\\chrome.exe"
    )


def _localappdata_automation_dir(*parts: str) -> str:
    import os

    local = (os.environ.get("LOCALAPPDATA") or "").strip()
    if not local:
        return ""
    return str(Path(local).joinpath(*parts))


def resolve_coccoc_persistent_user_data() -> str:
    import os

    if (os.environ.get("PROBE_COCCOC_USE_PERSISTENT") or "1").strip().lower() in ("0", "false", "no"):
        return ""

    override = (os.environ.get("PROBE_COCCOC_USER_DATA") or "").strip()
    if override:
        return override if Path(override).is_dir() else ""

    for candidate in (
        DEFAULT_COCCOC_USER_DATA_DIR,
        _localappdata_automation_dir(*COCCOC_USER_DATA_AUTOMATION_SUFFIX),
    ):
        if candidate and Path(candidate).is_dir():
            return candidate
    return ""


def resolve_edge_persistent_user_data() -> str:
    import os

    if (os.environ.get("PROBE_EDGE_USE_PERSISTENT") or "1").strip().lower() in ("0", "false", "no"):
        return ""

    override = (os.environ.get("PROBE_EDGE_USER_DATA") or "").strip()
    if override:
        return override if Path(override).is_dir() else ""

    for candidate in (
        DEFAULT_EDGE_USER_DATA_DIR,
        _localappdata_automation_dir(*EDGE_USER_DATA_AUTOMATION_SUFFIX),
    ):
        if candidate and Path(candidate).is_dir():
            return candidate
    return ""


def resolve_chrome_persistent_user_data() -> str:
    import os

    if (os.environ.get("PROBE_CHROME_USE_PERSISTENT") or "1").strip().lower() in ("0", "false", "no"):
        return ""

    override = (os.environ.get("PROBE_CHROME_USER_DATA") or "").strip()
    if override:
        return override if Path(override).is_dir() else ""

    for candidate in (
        DEFAULT_CHROME_USER_DATA_DIR,
        _localappdata_automation_dir(*CHROME_USER_DATA_AUTOMATION_SUFFIX),
    ):
        if candidate and Path(candidate).is_dir():
            return candidate
    return ""


def persistent_profile_setup_hint(profile_id: str) -> str:
    if profile_id == "coccoc":
        src = _localappdata_automation_dir("CocCoc", "Browser", "User Data")
        return (
            f"Đóng Cốc Cốc, copy folder profile sang bản clone (vd. {DEFAULT_COCCOC_USER_DATA_DIR}):\n"
            f'  "{src}" → clone trên ổ E:\n'
            f"Hoặc đặt PROBE_COCCOC_USER_DATA=đường_dẫn_thư_mục"
        )
    if profile_id == "edge":
        src = _localappdata_automation_dir("Microsoft", "Edge", "User Data")
        return (
            f"Đóng Edge, copy folder profile sang bản clone (vd. {DEFAULT_EDGE_USER_DATA_DIR}):\n"
            f'  "{src}" → clone trên ổ E:\n'
            f"Hoặc đặt PROBE_EDGE_USER_DATA=đường_dẫn_thư_mục"
        )
    if profile_id == "chrome":
        src = _localappdata_automation_dir("Google", "Chrome", "User Data")
        return (
            f"Đóng Chrome, copy folder profile sang bản clone (vd. {DEFAULT_CHROME_USER_DATA_DIR}):\n"
            f'  "{src}" → clone trên ổ E:\n'
            f"Hoặc đặt PROBE_CHROME_USER_DATA=đường_dẫn_thư_mục"
        )
    return ""
