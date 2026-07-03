"""HTTP session chuẩn hóa — cô lập khỏi proxy/cache OS."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from curl_cffi.requests import AsyncSession

from .browser_profiles import list_browser_profile_ids
from .probe_config import (
    CHROME_USER_DATA_ENV,
    COCCOC_USER_DATA_ENV,
    EDGE_USER_DATA_ENV,
    _PROFILE_ENV,
    _PROXY_ENV_KEYS,
    active_browser_profile,
    curl_impersonate,
)


@contextmanager
def isolated_probe_process_env(
    *,
    browser_profile: str | None = None,
    coccoc_user_data: str | None = None,
    edge_user_data: str | None = None,
    chrome_user_data: str | None = None,
) -> Iterator[None]:
    """Tạm gỡ biến proxy hệ thống; áp dụng profile curl (Edge / Cốc Cốc)."""
    saved: dict[str, str] = {}
    for key in _PROXY_ENV_KEYS:
        if key in os.environ:
            saved[key] = os.environ.pop(key)

    profile = (browser_profile or "").strip().lower()
    saved_profile = os.environ.get(_PROFILE_ENV)
    valid = set(list_browser_profile_ids())
    if profile in valid:
        os.environ[_PROFILE_ENV] = profile

    saved_coccoc_ud = os.environ.get(COCCOC_USER_DATA_ENV)
    coccoc_ud = (coccoc_user_data or "").strip()
    if coccoc_ud:
        os.environ[COCCOC_USER_DATA_ENV] = coccoc_ud

    saved_edge_ud = os.environ.get(EDGE_USER_DATA_ENV)
    edge_ud = (edge_user_data or "").strip()
    if edge_ud:
        os.environ[EDGE_USER_DATA_ENV] = edge_ud

    saved_chrome_ud = os.environ.get(CHROME_USER_DATA_ENV)
    chrome_ud = (chrome_user_data or "").strip()
    if chrome_ud:
        os.environ[CHROME_USER_DATA_ENV] = chrome_ud

    try:
        yield
    finally:
        if profile in valid:
            if saved_profile is None:
                os.environ.pop(_PROFILE_ENV, None)
            else:
                os.environ[_PROFILE_ENV] = saved_profile
        if coccoc_ud:
            if saved_coccoc_ud is None:
                os.environ.pop(COCCOC_USER_DATA_ENV, None)
            else:
                os.environ[COCCOC_USER_DATA_ENV] = saved_coccoc_ud
        if edge_ud:
            if saved_edge_ud is None:
                os.environ.pop(EDGE_USER_DATA_ENV, None)
            else:
                os.environ[EDGE_USER_DATA_ENV] = saved_edge_ud
        if chrome_ud:
            if saved_chrome_ud is None:
                os.environ.pop(CHROME_USER_DATA_ENV, None)
            else:
                os.environ[CHROME_USER_DATA_ENV] = saved_chrome_ud
        os.environ.update(saved)


def make_probe_session() -> AsyncSession:
    _ = active_browser_profile()
    return AsyncSession(impersonate=curl_impersonate())
