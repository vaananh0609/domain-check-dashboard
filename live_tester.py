import argparse
import csv
import ipaddress
import re
import socket
import time
from pathlib import Path
from typing import List, Tuple

import requests
from requests import Response
from requests.exceptions import ConnectionError, Timeout
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

STATUS_BLOCKED = "BLOCKED"
STATUS_LEAKED = "LEAKED"
STATUS_DEAD = "DEAD DOMAIN"

IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)


def normalize_domain(raw_value: str) -> str:
    value = raw_value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]

    if "@" in value:
        value = value.rsplit("@", 1)[-1]

    if ":" in value and value.count(":") == 1:
        host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            value = host

    return value.rstrip(".")


def is_ipv4(value: str) -> bool:
    if not IPV4_REGEX.match(value):
        return False
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def load_targets(input_path: Path) -> List[str]:
    content = input_path.read_text(encoding="utf-8-sig", errors="ignore")
    targets: List[str] = []
    seen = set()

    for line in content.splitlines():
        val = line.strip()
        if not val:
            continue

        # Hỗ trợ CSV đơn giản: lấy cột đầu tiên
        if "," in val:
            val = val.split(",", 1)[0].strip()

        domain = normalize_domain(val)
        if not domain or domain in seen:
            continue

        seen.add(domain)
        targets.append(domain)

    return targets


def can_resolve_dns(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def send_request(url: str, timeout: int) -> Response:
    return requests.get(
        url,
        timeout=timeout,
        verify=False,
        allow_redirects=False,
        headers={"User-Agent": "GatewayLiveTester/1.0"},
    )


def classify_target(domain: str, timeout: int) -> str:
    if is_ipv4(domain):
        # Kiểm thử live cho domain; IP không đánh giá theo DNS policy
        return STATUS_BLOCKED

    if not can_resolve_dns(domain):
        return STATUS_DEAD

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = send_request(url, timeout=timeout)
            if response.status_code in {200, 301, 302}:
                return STATUS_LEAKED
            # Có phản hồi HTTP nghĩa là traffic đã đi qua, xem là bị lọt
            return STATUS_LEAKED
        except Timeout:
            return STATUS_BLOCKED
        except ConnectionError:
            # Theo yêu cầu, ConnectionError xem như bị chặn bởi FW (drop)
            return STATUS_BLOCKED
        except Exception:
            continue

    return STATUS_BLOCKED


def detect_public_ip(timeout: int = 5) -> str:
    try:
        resp = requests.get("https://api.ipify.org", timeout=timeout)
        if resp.ok:
            return resp.text.strip()
    except Exception:
        pass
    return "Không xác định"


def write_output(rows: List[Tuple[str, str]], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Trạng_Thái"])
        writer.writerows(rows)


def run(input_file: Path, output_file: Path, timeout: int) -> None:
    targets = load_targets(input_file)
    if not targets:
        print("[LỖI] Không có domain hợp lệ trong file đầu vào.")
        return

    public_ip = detect_public_ip()
    print(f"[INFO] Public IP hiện tại: {public_ip}")
    print("[INFO] Khuyến nghị chạy bằng mạng Guest Wifi của công ty trước khi test.")
    print(f"[INFO] Bắt đầu kiểm thử {len(targets)} domain, timeout={timeout}s")

    rows: List[Tuple[str, str]] = []
    start = time.time()

    for idx, domain in enumerate(targets, start=1):
        status = classify_target(domain, timeout=timeout)
        rows.append((domain, status))

        if idx % 50 == 0 or idx == len(targets):
            elapsed = time.time() - start
            print(f"[PROGRESS] {idx}/{len(targets)} - elapsed: {elapsed:.1f}s")

    write_output(rows, output_file)

    blocked = sum(1 for _, s in rows if s == STATUS_BLOCKED)
    leaked = sum(1 for _, s in rows if s == STATUS_LEAKED)
    dead = sum(1 for _, s in rows if s == STATUS_DEAD)

    total = len(rows)
    print("\n[RESULT]")
    print(f"Tổng domain: {total}")
    print(f"Blocked: {blocked} ({(blocked / total * 100):.2f}%)")
    print(f"Leaked: {leaked} ({(leaked / total * 100):.2f}%)")
    print(f"Dead: {dead} ({(dead / total * 100):.2f}%)")
    print(f"[DONE] Đã xuất file: {output_file}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Worker script kiểm thử live Gateway bằng HTTP requests an toàn (không dùng browser automation)."
    )
    parser.add_argument("--input", required=True, help="Đường dẫn file domain đầu vào (.txt/.csv)")
    parser.add_argument("--output", default="live_test_results.csv", help="Đường dẫn file CSV kết quả")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout cho mỗi request (giây)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run(Path(args.input), Path(args.output), timeout=args.timeout)


if __name__ == "__main__":
    main()
