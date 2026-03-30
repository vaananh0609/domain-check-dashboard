"""Hằng số dùng chung cho kiểm thử live (production-ready)."""

import re

# =========================
# STATUS
# =========================
STATUS_BLOCKED = "BLOCKED"
STATUS_LEAKED = "LEAKED"
STATUS_PARKED = "PARKED / NO CONTENT"
STATUS_DEAD = "DEAD DOMAIN"

# =========================
# OUTPUT COLUMNS
# =========================
COL_ORIGINAL = "Tên miền / IP gốc"
COL_FINAL_VI = "Trạng thái cuối cùng"
COL_HTTP = "Mã HTTP"
COL_CHAIN = "Chuỗi chuyển hướng"
COL_FINAL_URL = "URL đích"
COL_DNS = "Phân giải DNS (mạng local)"
COL_NET = "Kết nối mạng (local)"

# =========================
# NETWORK CONFIG
# =========================
EXPECTED_GUEST_IP = "113.160.48.66"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

ASYNC_CONCURRENCY = 20

DNS_TIMEOUT_SECONDS = 6   # giảm để tránh treo lâu
HTTP_RETRIES = 3
BACKOFF_BASE_SECONDS = 0.5  # tăng nhẹ để ổn định hơn
PREFLIGHT_TIMEOUT_SECONDS = 4

# Playwright (live/playwright_helper.py)
PLAYWRIGHT_HEADLESS = True
PLAYWRIGHT_LOCALE = "vi-VN"
PLAYWRIGHT_TIMEZONE = "Asia/Ho_Chi_Minh"
PLAYWRIGHT_VIEWPORT_WIDTH = 1920
PLAYWRIGHT_VIEWPORT_HEIGHT = 1080
PLAYWRIGHT_WAIT_UNTIL = "domcontentloaded"
PLAYWRIGHT_POST_NAV_DELAY_SEC = 0.35

# =========================
# PUBLIC DNS (GROUND TRUTH)
# =========================
# Thêm 9.9.9.9 để tránh edge-case NXDOMAIN sai
PUBLIC_DNS_SERVERS = [
    "8.8.8.8",   # Google
    "1.1.1.1",   # Cloudflare
    "9.9.9.9",   # Quad9
]

# =========================
# PRIVATE / SINKHOLE IP DETECTION (RẤT QUAN TRỌNG)
# =========================
# Fix lỗi lớn: VNPT hay trả IP nội bộ → trước đây bị classify LEAK sai
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

# =========================
# PARKED DETECTION (STRICT)
# =========================
# CHỈ dùng redirect + DNS NS → tránh false positive
PARKED_REDIRECT_HOST_SUFFIXES = (
    "sedo.com",
    "dan.com",
    "hugedomains.com",
    "parkingcrew.net",
    "bodis.com",
)

PARKED_DNS_HINTS = [
    "sedoparking",
    "bodis",
    "parkingcrew",
]

# ⚠️ QUAN TRỌNG: KHÔNG dùng HTML content để classify
# → tránh false BLOCK / PARKED
PARKED_PAGE_CONTENT_HINTS = ()

# =========================
# REGEX
# =========================
IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)