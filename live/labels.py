from urllib.parse import urlsplit

from .constants import (
    COL_CHAIN,
    COL_DNS,
    COL_FINAL_URL,
    COL_FINAL_VI,
    COL_HTTP,
    COL_NET,
    COL_ORIGINAL,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
)

_FINAL_VI_BY_STATUS = {
    STATUS_DEAD: "Dead (Chết)",
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
