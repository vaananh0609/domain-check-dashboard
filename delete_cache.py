#!/usr/bin/env python3
"""
Mo profile clone Chrome / Coccoc / Edge tren o E: de xoa lich su & cache thu cong.

Cach chay:
  python delete_cache.py chrome
  python delete_cache.py coccoc
  python delete_cache.py edge

Giu cua so trinh duyet ~60 giay roi dong.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from live.browser_profiles import resolve_chrome_executable, resolve_coccoc_executable
from live.probe_config import (
    CHROME_USER_DATA_ENV,
    COCCOC_USER_DATA_ENV,
    DEFAULT_CHROME_USER_DATA_DIR,
    DEFAULT_COCCOC_USER_DATA_DIR,
    DEFAULT_EDGE_USER_DATA_DIR,
    EDGE_USER_DATA_ENV,
)

EDGE_EXE_CANDIDATES: tuple[str, ...] = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)

DEFAULT_HOLD_SECONDS = 60

_CLEAR_URL = {
    "coccoc": "chrome://settings/clearBrowserData",
    "edge": "edge://settings/clearBrowserData",
    "chrome": "chrome://settings/clearBrowserData",
}

_LABEL = {
    "coccoc": "Coc Coc",
    "edge": "Microsoft Edge",
    "chrome": "Google Chrome",
}

_USER_DATA_ENV = {
    "coccoc": COCCOC_USER_DATA_ENV,
    "edge": EDGE_USER_DATA_ENV,
    "chrome": CHROME_USER_DATA_ENV,
}

_DEFAULT_USER_DATA = {
    "coccoc": DEFAULT_COCCOC_USER_DATA_DIR,
    "edge": DEFAULT_EDGE_USER_DATA_DIR,
    "chrome": DEFAULT_CHROME_USER_DATA_DIR,
}


def _resolve_edge_executable() -> str:
    override = (os.environ.get("PROBE_EDGE_EXECUTABLE") or "").strip()
    if override and Path(override).is_file():
        return override
    for raw in EDGE_EXE_CANDIDATES:
        if Path(raw).is_file():
            return raw
    raise FileNotFoundError(
        "Khong tim thay msedge.exe. Cai Edge hoac dat PROBE_EDGE_EXECUTABLE=duong_dan\\msedge.exe"
    )


def _user_data_dir(browser: str) -> str:
    env_key = _USER_DATA_ENV[browser]
    default = _DEFAULT_USER_DATA[browser]
    return (os.environ.get(env_key) or default).strip()


def _executable(browser: str) -> str:
    if browser == "coccoc":
        return resolve_coccoc_executable()
    if browser == "chrome":
        return resolve_chrome_executable()
    return _resolve_edge_executable()


def open_profile_browser(browser: str, *, hold_seconds: int = DEFAULT_HOLD_SECONDS) -> int:
    browser = browser.strip().lower()
    if browser not in _CLEAR_URL:
        raise ValueError(f"browser khong hop le: {browser}")

    user_data = _user_data_dir(browser)
    if not user_data or not Path(user_data).is_dir():
        print(f"Loi: khong thay thu muc profile:\n  {user_data}", file=sys.stderr)
        print("Copy User Data goc len o E: truoc khi chay.", file=sys.stderr)
        return 1

    try:
        exe = _executable(browser)
    except FileNotFoundError as ex:
        print(f"Loi: {ex}", file=sys.stderr)
        return 1

    label = _LABEL[browser]
    start_url = _CLEAR_URL[browser]

    print(f"=== {label} — xoa cache / lich su ===")
    print(f"  browser.exe : {exe}")
    print(f"  user-data   : {user_data}")
    print(f"  Giu mo      : {hold_seconds}s")
    print()
    print("Neu trinh duyet dang mo voi profile nay -> dong het roi chay lai.")
    print("Trang mo: Xoa du lieu duyet web — chon muc can xoa roi Xoa ngay.")
    print()

    proc = subprocess.Popen(
        [exe, f"--user-data-dir={user_data}", start_url],
    )

    try:
        time.sleep(max(1, int(hold_seconds)))
    except KeyboardInterrupt:
        print("\nDa huy — dong trinh duyet.")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    print(f"Da dong {label}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mo profile clone Chrome / Coc Coc / Edge (o E:) de xoa lich su & cache.",
    )
    parser.add_argument(
        "browser",
        choices=("chrome", "coccoc", "edge"),
        help="chrome, coccoc hoac edge",
    )
    parser.add_argument(
        "--seconds",
        type=int,
        default=DEFAULT_HOLD_SECONDS,
        help=f"Giu trinh duyet mo bao lau (mac dinh {DEFAULT_HOLD_SECONDS})",
    )
    args = parser.parse_args(argv)
    return open_profile_browser(args.browser, hold_seconds=args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
