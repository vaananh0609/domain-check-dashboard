#!/usr/bin/env python3
"""
Xóa lịch sử duyệt web Chrome — profile clone trên ổ E: (mặc định E:\\User Data Chrome).

Cách chạy:
  python delete_history_chrome.py

Đóng hết cửa sổ Chrome đang dùng profile này trước khi chạy (file History bị khóa nếu còn mở).

Tùy chọn:
  python delete_history_chrome.py --gui          # mở chrome://settings/clearBrowserData ~60s
  python delete_history_chrome.py --gui --seconds 90

Ghi đè thư mục profile: đặt biến môi trường PROBE_CHROME_USER_DATA.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from live.browser_profiles import resolve_chrome_executable
from live.probe_config import CHROME_USER_DATA_ENV, DEFAULT_CHROME_USER_DATA_DIR

_CLEAR_URL = "chrome://settings/clearBrowserData"
_DEFAULT_HOLD_SECONDS = 60

# File SQLite / index liên quan lịch sử duyệt web (không đụng Cache).
_HISTORY_FILES = (
    "History",
    "History-journal",
    "Visited Links",
    "Visited Links-journal",
    "Top Sites",
    "Top Sites-journal",
)


def _user_data_dir() -> Path:
    raw = (os.environ.get(CHROME_USER_DATA_ENV) or DEFAULT_CHROME_USER_DATA_DIR).strip()
    return Path(raw)


def _profile_dirs(user_data: Path) -> list[Path]:
    default = user_data / "Default"
    if default.is_dir():
        return [default]
    profiles = sorted(p for p in user_data.glob("Profile *") if p.is_dir())
    return profiles


def clear_chrome_history_files(user_data: Path) -> tuple[list[str], list[str]]:
    """Xóa file lịch sử trong từng profile. Trả về (đã xóa, lỗi)."""
    removed: list[str] = []
    errors: list[str] = []
    profiles = _profile_dirs(user_data)
    if not profiles:
        errors.append(f"Không thấy profile Default/ trong: {user_data}")
        return removed, errors

    for profile in profiles:
        for name in _HISTORY_FILES:
            path = profile / name
            if not path.exists():
                continue
            try:
                path.unlink()
                removed.append(str(path))
            except OSError as ex:
                errors.append(f"{path}: {ex}")
    return removed, errors


def open_clear_gui(*, hold_seconds: int = _DEFAULT_HOLD_SECONDS) -> int:
    user_data = _user_data_dir()
    if not user_data.is_dir():
        print(f"Lỗi: không thấy thư mục profile:\n  {user_data}", file=sys.stderr)
        print("Copy User Data gốc lên ổ E: trước khi chạy.", file=sys.stderr)
        return 1

    try:
        exe = resolve_chrome_executable()
    except FileNotFoundError as ex:
        print(f"Lỗi: {ex}", file=sys.stderr)
        return 1

    print("=== Google Chrome — xóa lịch sử (giao diện) ===")
    print(f"  chrome.exe  : {exe}")
    print(f"  user-data   : {user_data}")
    print(f"  Giữ mở      : {hold_seconds}s")
    print()
    print("Nếu Chrome đang mở với profile này → đóng hết rồi chạy lại.")
    print("Trang mở: Xóa dữ liệu duyệt web — chọn «Lịch sử duyệt web» rồi Xóa ngay.")
    print()

    proc = subprocess.Popen(
        [exe, f"--user-data-dir={user_data}", _CLEAR_URL],
    )

    try:
        time.sleep(max(1, int(hold_seconds)))
    except KeyboardInterrupt:
        print("\nĐã hủy — đóng trình duyệt.")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    print("Đã đóng Chrome.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Xóa lịch sử duyệt web Chrome (profile clone trên ổ E:).",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Mở trang chrome://settings/clearBrowserData để xóa thủ công",
    )
    parser.add_argument(
        "--seconds",
        type=int,
        default=_DEFAULT_HOLD_SECONDS,
        help=f"Khi dùng --gui: giữ trình duyệt mở bao lâu (mặc định {_DEFAULT_HOLD_SECONDS})",
    )
    args = parser.parse_args(argv)

    if args.gui:
        return open_clear_gui(hold_seconds=args.seconds)

    user_data = _user_data_dir()
    if not user_data.is_dir():
        print(f"Lỗi: không thấy thư mục profile:\n  {user_data}", file=sys.stderr)
        print("Copy User Data gốc lên ổ E: trước khi chạy.", file=sys.stderr)
        return 1

    print("=== Google Chrome — xóa lịch sử (tự động) ===")
    print(f"  user-data: {user_data}")
    print()

    removed, errors = clear_chrome_history_files(user_data)

    if removed:
        print(f"Đã xóa {len(removed)} file:")
        for p in removed:
            print(f"  - {p}")
    else:
        print("Không có file lịch sử nào cần xóa (hoặc profile trống).")

    if errors:
        print("\nLỗi (thường do Chrome còn đang mở — đóng hết rồi chạy lại):", file=sys.stderr)
        for msg in errors:
            print(f"  {msg}", file=sys.stderr)
        return 1

    print("\nXong. Mở lại Chrome để kiểm tra lịch sử đã trống.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
