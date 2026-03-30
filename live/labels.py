from urllib.parse import urlsplit

from .constants import (
    COL_CHAIN,
    COL_DNS,
    COL_FINAL_URL,
    COL_FINAL_VI,
    COL_HTTP,
    COL_NET,
    COL_ORIGINAL,
    PARKED_PAGE_CONTENT_HINTS,
    PARKED_REDIRECT_HOST_SUFFIXES,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_PARKED,
)

_FINAL_VI_BY_STATUS = {
    STATUS_DEAD: "Dead (Chết)",
    STATUS_PARKED: "Parked (Đỗ / Chờ bán)",
    STATUS_BLOCKED: "Blocked (Đã chặn an toàn)",
    STATUS_LEAKED: "Leaked (Lọt lưới — cảnh báo)",
}


def format_dns_column(rcode: str, ips: list[str]) -> str:
    if ips:
        return f"{rcode}: {', '.join(ips)}"
    return f"{rcode}: (không có A/AAAA)"


def final_status_vietnamese(internal: str) -> str:
    return _FINAL_VI_BY_STATUS.get(internal, internal)


def local_network_result_vietnamese(internal: str, detail: str) -> str:
    det = (detail or "").lower()
    if internal == STATUS_LEAKED:
        # LEAKED có thể do chính sách khi probe timeout / không đo được HTTP — không gọi là "Thành công" tuyến.
        if (
            "timeout" in det
            or "thất bại" in det
            or "không đo được" in det
            or "probe http thất bại" in det
            or "không nhận được phản hồi http" in det
            or "lỗi kỹ thuật khi đo http" in det
        ):
            return "Không đo đủ HTTP (vẫn lọt theo chính sách)"
        return "Thành công"
    if "timeout" in det:
        return "Timeout"
    if internal == STATUS_PARKED:
        return "Parking / landing"
    if internal == STATUS_DEAD:
        return "Không còn bản ghi DNS"
    if internal == STATUS_BLOCKED:
        return "Bị chặn"
    return "—"


def build_live_row_dict(
    original_label: str,
    internal: str,
    detail: str,
    final_url: str,
    http_code: str,
    redirect_chain: str,
    dns_rcode: str,
    dns_ips: list[str],
    dns_column_suffix: str = "",
) -> dict[str, str]:
    dns_text = format_dns_column(dns_rcode, dns_ips)
    if dns_column_suffix:
        dns_text = f"{dns_text}{dns_column_suffix}"
    return {
        COL_ORIGINAL: original_label,
        COL_FINAL_VI: final_status_vietnamese(internal),
        COL_HTTP: str(http_code) if http_code is not None else "",
        COL_CHAIN: redirect_chain,
        COL_FINAL_URL: final_url,
        COL_DNS: dns_text,
        COL_NET: local_network_result_vietnamese(internal, detail),
        "Trạng_Thái": internal,
    }


def _host_matches_parked_redirect(host: str) -> bool:
    h = (host or "").lower().strip(".")
    for suffix in PARKED_REDIRECT_HOST_SUFFIXES:
        if h == suffix or h.endswith("." + suffix):
            return True
    return False


def is_parked_by_redirect(origin_domain: str, history_urls: list[str], final_url: str) -> bool:
    """Có redirect (history) và chuỗi URL chứa host parking (sedo/dan/…)."""
    if not history_urls:
        return False
    urls = history_urls + [final_url]
    origin = origin_domain.lower().strip(".")

    for raw_url in urls:
        host = (urlsplit(raw_url).hostname or "").lower().strip(".")
        if not host:
            continue

        changed_host = host != origin and not host.endswith(f".{origin}")
        if changed_host and _host_matches_parked_redirect(host):
            return True

    return False


def is_parked_by_page_content(html: str, final_url: str = "") -> bool:
    """HTTP 200 nhưng landing từ provider parking (chuỗi cụ thể trong HTML/URL)."""
    if not html or not str(html).strip():
        return False
    snippet = str(html)[:500_000].lower()
    if any(h in snippet for h in PARKED_PAGE_CONTENT_HINTS):
        return True
    fin = (final_url or "").lower()
    if fin and any(h in fin for h in ("parklogic", "sedoparking", "parkingcrew", "hugedomains", "bodis", "dan.com")):
        return True
    return False


def is_sensitive_by_page_content(html: str, final_url: str = "") -> bool:
    """
    Nhận diện nhanh nội dung nhạy cảm (cờ bạc/đặt cược) để gán LEAKED.
    Cố tình dùng heuristic từ khóa để tránh phụ thuộc parser phức tạp.
    """
    if not (html and str(html).strip()) and not (final_url and str(final_url).strip()):
        return False

    snippet = (html or "")[:200_000].lower()  # cắt ngắn để tránh tốn bộ nhớ
    fin = (final_url or "").lower()

    # Từ khóa "mạnh" (ưu tiên độ chính xác hơn là phủ rộng).
    strong_keywords = (
        "casino",
        "baccarat",
        "roulette",
        "slot",
        "tài xỉu",
        "tai xiu",
        "xì dách",
        "xi dach",
        "lô đề",
        "lo de",
        "xóc đĩa",
        "soc dia",
        "đánh bạc",
        "cờ bạc",
        "cá cược",
        "đặt cược",
    )

    for kw in strong_keywords:
        if kw in snippet or (fin and kw in fin):
            return True

    # Từ khóa "vừa" chỉ kết luận khi có >= 2 dấu hiệu cùng lúc.
    moderate_keywords = (
        "betting",
        "sportsbook",
        "sports betting",
        "wager",
        "bookmaker",
        "gambling",
    )
    hits = sum(1 for kw in moderate_keywords if kw in snippet or (fin and kw in fin))
    return hits >= 2
