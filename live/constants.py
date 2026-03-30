import re

STATUS_BLOCKED = "BLOCKED"
STATUS_LEAKED = "LEAKED"
STATUS_DEAD = "DEAD DOMAIN"

COL_ORIGINAL = "Tên miền / IP gốc"
COL_FINAL_VI = "Trạng thái cuối cùng"
COL_HTTP = "Mã HTTP"
COL_CHAIN = "Chuỗi chuyển hướng"
COL_FINAL_URL = "URL đích"
COL_DNS = "Phân giải DNS (mạng local)"
COL_NET = "Kết nối mạng (local)"

EXPECTED_GUEST_IP = "113.160.48.66"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

ASYNC_CONCURRENCY = 40

DNS_TIMEOUT_SECONDS = 4
HTTP_RETRIES = 2
BACKOFF_BASE_SECONDS = 0.3
PREFLIGHT_TIMEOUT_SECONDS = 3

PUBLIC_DNS_SERVERS = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
]

PRIVATE_IP_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "0.0.0.0",
)

IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)