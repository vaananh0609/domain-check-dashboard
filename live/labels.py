import math
from urllib.parse import urlsplit

from .constants import (
    COL_CHAIN,
    COL_DNS,
    COL_FINAL_URL,
    COL_FINAL_VI,
    COL_HTTP,
    COL_TLS,
    COL_ORIGINAL,
    COL_DETAIL,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
)

_FINAL_VI_BY_STATUS = {
    STATUS_DEAD: "Dead",
    STATUS_BLOCKED: "Blocked",
    STATUS_LEAKED: "Leaked",
}


def format_dns_column(rcode: str, ips: list[str]) -> str:
    if ips:
        return f"{rcode}: {', '.join(ips)}"
    return f"{rcode}: (không có A/AAAA)"


def final_status_vietnamese(internal: str) -> str:
    return _FINAL_VI_BY_STATUS.get(internal, internal)


def _cell_str(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and math.isnan(v):
        return ""
    s = str(v).strip()
    if s.lower() in ("nan", "none", "<na>"):
        return ""
    return s


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
    tls: str = "",
) -> dict[str, str]:
    dns_text = format_dns_column(dns_rcode, dns_ips)
    if dns_column_suffix:
        dns_text = f"{dns_text}{dns_column_suffix}"

    return {
        COL_ORIGINAL: original_label,
        COL_FINAL_VI: final_status_vietnamese(internal),
        COL_HTTP: _cell_str(http_code),
        COL_TLS: _cell_str(tls),
        COL_CHAIN: _cell_str(redirect_chain),
        COL_FINAL_URL: _cell_str(final_url),
        COL_DNS: dns_text,
        COL_DETAIL: detail,
        "Trạng_Thái": internal,
    }