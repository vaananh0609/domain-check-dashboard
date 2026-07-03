import re

STATUS_BLOCKED = "BLOCKED"
STATUS_LEAKED = "LEAKED"
STATUS_DEAD = "DEAD DOMAIN"
STATUS_TIMEOUT = "TIMEOUT"

COL_ORIGINAL = "Domain"
COL_FINAL_VI = "Status"
COL_RESULT_SOURCE = "Source"
COL_HTTP = "HTTP"
COL_HTTP_VER = "HTTP Ver"
COL_CHAIN = "Redirect chain"
COL_DNS = "DNS"
# Cột legacy — chỉ đọc CSV/bảng cũ; run mới chỉ ghi COL_DNS
COL_DNS_LOCAL = "Local DNS"
COL_DNS_PUBLIC = "Public DNS"
COL_DNS_GOOGLE_DOH = "Google DoH"
COL_DNS_CLOUDFLARE_DOH = "Cloudflare DoH"
COL_DNS_LEGACY_KEYS = (
    COL_DNS_LOCAL,
    COL_DNS_PUBLIC,
    COL_DNS_GOOGLE_DOH,
    COL_DNS_CLOUDFLARE_DOH,
    "DNS resolution",
)
COL_TCP_80 = "TCP 80"
COL_TCP_443 = "TCP 443"
COL_PLAYWRIGHT_ERR = "Playwright error"
COL_TLS = "TLS/SSL"
COL_LATENCY = "Latency"
COL_TRACE = "Trace"

SOURCE_DNS_A_AAAA = "A&AAAA"
SOURCE_HTTP_REFERENCE = "HTTP Reference"

MAX_HTTP_REDIRECTS = 15
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

EXPECTED_GUEST_IP = "113.160.48.66"

USER_AGENT_EDGE_149 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0"
)

USER_AGENT_COCCOC_154 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36 coc_coc_browser/154.0.0"
)

USER_AGENT_CHROME_149 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36"
)

# Mặc định khớp Microsoft Edge 149 (trình duyệt test chính trên Windows).
USER_AGENT = USER_AGENT_EDGE_149

ASYNC_CONCURRENCY = 20

DNS_TIMEOUT_SECONDS = 4
DNS_QUERY_ATTEMPTS = 3
DNS_RETRY_BACKOFF_SECONDS = 0.3
HTTP_RETRIES = 2
BACKOFF_BASE_SECONDS = 0.3
PREFLIGHT_TIMEOUT_SECONDS = 3

# HTTP/3 (QUIC): edge Cloudflare đôi khi trả 5xx chậm hơn 10s — tránh timeout giả → LEAKED.
HTTP_H3_TIMEOUT_MIN = 20
HTTP_H3_TIMEOUT_MAX = 30


PHASE1_MIN_TIMEOUT_SECONDS = 10
PHASE1_MAX_TIMEOUT_SECONDS = 45


def clamp_phase1_timeout_seconds(seconds: int) -> int:
    try:
        n = int(seconds)
    except (TypeError, ValueError):
        n = PHASE1_MIN_TIMEOUT_SECONDS
    return max(PHASE1_MIN_TIMEOUT_SECONDS, min(n, PHASE1_MAX_TIMEOUT_SECONDS))


def effective_h3_timeout(base_seconds: int) -> int:
    """Timeout riêng cho hop h3 — cao hơn TCP một chút, có trần."""
    return min(max(int(base_seconds) + 10, HTTP_H3_TIMEOUT_MIN), HTTP_H3_TIMEOUT_MAX)

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