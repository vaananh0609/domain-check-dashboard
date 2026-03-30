import ipaddress
import re

from .constants import IPV4_REGEX


def read_uploaded_text_lines(raw: bytes) -> list[str]:
    if not raw:
        return []

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="ignore")

    rows = []
    for line in text.splitlines():
        val = line.strip()
        if not val:
            continue
        rows.append(val)
    return rows


def normalize_target(raw_value: str) -> str:
    value = raw_value.strip().lower()
    if value:
        value = value.split()[0]
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


def parse_dns_servers(raw_value: str) -> list[str]:
    servers = [item.strip() for item in raw_value.split(",") if item.strip()]
    from .constants import PUBLIC_DNS_SERVERS

    return servers or PUBLIC_DNS_SERVERS


def browse_url_for_cell(text: str) -> str:
    """URL để mở trong trình duyệt từ nội dung ô Tên miền/IP gốc."""
    if not text or not str(text).strip():
        return ""
    t = str(text).strip().splitlines()[0].strip()
    low = t.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return t
    first = t.split()[0] if t.split() else t
    host_part = first.split("/")[0]
    host_only = host_part.split(":")[0] if ":" in host_part else host_part
    if is_ipv4(host_only):
        return f"http://{host_part}"
    return f"https://{host_only}"
