"""Cấu hình chuẩn hóa probe — đồng nhất giữa các máy trạm cùng mạng."""

from __future__ import annotations

import os

from .browser_profiles import BrowserProfile, get_browser_profile

_PROFILE_ENV = "PROBE_BROWSER_PROFILE"
COCCOC_USER_DATA_ENV = "PROBE_COCCOC_USER_DATA"
EDGE_USER_DATA_ENV = "PROBE_EDGE_USER_DATA"
CHROME_USER_DATA_ENV = "PROBE_CHROME_USER_DATA"

# Clone profile Bước 3 (ổ E:) — ghi đè bằng env hoặc ô trên form.
DEFAULT_COCCOC_USER_DATA_DIR = r"E:\User Data Coccoc"
DEFAULT_EDGE_USER_DATA_DIR = r"E:\User Data Edge"
DEFAULT_CHROME_USER_DATA_DIR = r"E:\User Data Chrome"

# Ghi đè impersonate toàn cục (debug): PROBE_CURL_IMPERSONATE=chrome136
CURL_IMPERSONATE = os.environ.get("PROBE_CURL_IMPERSONATE", "chrome142")

# DNS nhà mạng (ISP) — cấu hình qua UI hoặc env PROBE_LOCAL_DNS.
DEFAULT_LOCAL_DNS = "172.16.16.4"
LOCAL_DNS_SERVERS: list[str] = []

_PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


def active_browser_profile() -> BrowserProfile:
    return get_browser_profile(os.environ.get(_PROFILE_ENV))


def curl_impersonate() -> str:
    override = os.environ.get("PROBE_CURL_IMPERSONATE")
    if override:
        return override
    return active_browser_profile().impersonate


def parse_local_dns_servers(raw: str | None) -> list[str]:
    from .parsing import parse_dns_servers

    text = (raw or os.environ.get("PROBE_LOCAL_DNS") or DEFAULT_LOCAL_DNS).strip()
    if text:
        return parse_dns_servers(text)
    return list(LOCAL_DNS_SERVERS)


def probe_request_headers() -> dict[str, str]:
    profile = active_browser_profile()
    headers = {
        "User-Agent": profile.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": profile.accept_language,
        "Referer": "https://www.google.com/",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "Connection": "close",
    }
    headers.update(profile.client_hints)
    lang_override = (os.environ.get("PROBE_ACCEPT_LANGUAGE") or "").strip()
    if lang_override:
        headers["Accept-Language"] = lang_override
    ua_override = (os.environ.get("PROBE_USER_AGENT") or "").strip()
    if ua_override and ua_override not in ("edge", "coccoc", "chrome"):
        headers["User-Agent"] = ua_override
    return headers


def curl_probe_kwargs(*, timeout: int, proxy_url: str | None = None) -> dict:
    kwargs: dict = {
        "timeout": timeout,
        "allow_redirects": False,
        "impersonate": curl_impersonate(),
        "verify": False,
        "headers": probe_request_headers(),
    }
    if proxy_url:
        kwargs["proxy"] = proxy_url
    else:
        kwargs["proxies"] = {"http": None, "https": None, "all": None}
    return kwargs
