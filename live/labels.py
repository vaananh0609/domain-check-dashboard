import ipaddress
import math
from typing import Any, Optional
from urllib.parse import urlsplit

from .constants import (
    COL_CHAIN,
    COL_DNS,
    COL_DNS_CLOUDFLARE_DOH,
    COL_DNS_GOOGLE_DOH,
    COL_DNS_LOCAL,
    COL_DNS_PUBLIC,
    COL_FINAL_VI,
    COL_HTTP,
    COL_HTTP_VER,
    COL_LATENCY,
    COL_ORIGINAL,
    COL_PLAYWRIGHT_ERR,
    COL_RESULT_SOURCE,
    COL_TCP_443,
    COL_TCP_80,
    COL_TLS,
    COL_TRACE,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_TIMEOUT,
)
from .constants import SOURCE_DNS_A_AAAA, SOURCE_HTTP_REFERENCE
from .evidence import LayerEvidence

_BROWSER_SOURCE_SHORT: dict[str, str] = {
    "coccoc": "Coccoc",
    "edge": "Edge",
    "chrome": "Chrome",
}


def browser_result_source(profile_id: str | None, *, phase2: bool = False) -> str:
    from .browser_profiles import get_browser_profile

    p = get_browser_profile(profile_id)
    name = _BROWSER_SOURCE_SHORT.get(p.id, p.label.split()[0] if p.label else "Browser")
    return f"P2 {name}" if phase2 else name

_FINAL_VI_BY_STATUS = {
    STATUS_DEAD: "Dead",
    STATUS_BLOCKED: "Blocked",
    STATUS_LEAKED: "Leaked",
    STATUS_TIMEOUT: "Timeout",
}


_DNS_DISPLAY_MAX_IPV4 = 2

DNS_EVIDENCE_COLUMN_KEYS: tuple[str, ...] = (COL_DNS,)


def primary_dns_display(
    local_rcode: str,
    local_ips: list[str],
    *,
    public_rcode: str = "",
    public_ips: Optional[list[str]] = None,
    evidence: Optional[LayerEvidence] = None,
) -> str:
    """Một cột DNS — ưu tiên nguồn có IP thật (local → public → DoH)."""
    from .dns import real_ips_from_list

    candidates: list[tuple[str, list[str]]] = [
        (local_rcode, list(local_ips or [])),
        (public_rcode, list(public_ips or [])),
    ]
    if evidence is not None:
        candidates.extend(
            [
                (evidence.google_doh_rcode, list(evidence.google_doh_ips)),
                (evidence.cloudflare_doh_rcode, list(evidence.cloudflare_doh_ips)),
            ]
        )
    for rcode, ips in candidates:
        if real_ips_from_list(ips):
            return format_dns_column(rcode, ips)
    for rcode, ips in candidates:
        rc = (rcode or "").strip()
        if rc and rc not in ("—", ""):
            return format_dns_column(rcode, ips)
    return format_dns_column(local_rcode, local_ips)


def primary_dns_display_from_row(row: dict[str, Any]) -> str:
    """Gộp cột DNS từ row mới hoặc CSV cũ (4 cột / DNS resolution)."""
    merged = _cell_str(row.get(COL_DNS))
    if merged and merged != "—":
        return merged
    from .dns import real_ips_from_list

    for key in (COL_DNS_LOCAL, COL_DNS_PUBLIC, COL_DNS_GOOGLE_DOH, COL_DNS_CLOUDFLARE_DOH):
        text = _cell_str(row.get(key))
        if not text or text == "—":
            continue
        ips = _ips_from_dns_cell_text(text)
        if real_ips_from_list(ips) or ":" in text:
            return text.split("|", 1)[0].strip()
    legacy = _cell_str(row.get("DNS resolution"))
    if legacy and legacy != "—":
        return legacy
    return merged or "—"


def _ips_from_dns_cell_text(cell: str) -> list[str]:
    s = (cell or "").strip()
    if not s or s == "—" or ":" not in s:
        return []
    rest = s.split(":", 1)[1].strip()
    if not rest or rest.startswith("("):
        return []
    out: list[str] = []
    for part in rest.split(","):
        ip = part.strip()
        if ip and not ip.startswith("("):
            out.append(ip)
    return out


def _ipv4_for_display(ips: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in ips:
        n = (raw or "").strip()
        if not n or n in seen:
            continue
        try:
            if ipaddress.ip_address(n).version == 4:
                seen.add(n)
                out.append(n)
        except ValueError:
            continue
    return out[:_DNS_DISPLAY_MAX_IPV4]


def format_dns_column(rcode: str, ips: list[str]) -> str:
    """Hiển thị DNS: rcode + tối đa 2 IPv4 (không IPv6, không suffix)."""
    rc = (rcode or "").strip() or "—"
    v4 = _ipv4_for_display(list(ips or []))
    if v4:
        return f"{rc}: {', '.join(v4)}"
    if ips:
        return f"{rc}: (không có A IPv4)"
    return f"{rc}: (không có A/AAAA)"


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


def dns_evidence_columns_dict(
    local_rcode: str,
    local_ips: list[str],
    *,
    public_rcode: str = "",
    public_ips: Optional[list[str]] = None,
    evidence: Optional[LayerEvidence] = None,
) -> dict[str, str]:
    """Snapshot cột DNS — dùng để không bị Playwright/patch ghi đè."""
    return {
        COL_DNS: primary_dns_display(
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            evidence=evidence,
        ),
    }


def preserve_dns_evidence_columns(
    row: dict[str, str],
    prior: Optional[dict[str, Any]] = None,
) -> dict[str, str]:
    """Giữ nguyên cột DNS đã có — không downgrade về trống/—."""
    if not prior:
        return row
    out = dict(row)
    for key in DNS_EVIDENCE_COLUMN_KEYS:
        prev = _cell_str(prior.get(key))
        new = _cell_str(out.get(key))
        if prev and prev != "—" and (not new or new == "—"):
            out[key] = prev
    return out


def build_live_row_dict(
    original_label: str,
    internal: str,
    http_code: str,
    redirect_chain: str,
    dns_rcode: str,
    dns_ips: list[str],
    dns_column_suffix: str = "",
    tls_version: str = "—",
    tls_html: str = "",
    trace: str = "",
    *,
    http_version: str = "",
    latency: str = "",
    public_dns_rcode: str = "",
    public_dns_ips: Optional[list[str]] = None,
    pending_vi: str = "",
    evidence: Optional[LayerEvidence] = None,
    dns_preserve_from: Optional[dict[str, Any]] = None,
    result_source: str = "",
) -> dict[str, str]:
    dns_text = primary_dns_display(
        dns_rcode,
        dns_ips,
        public_rcode=public_dns_rcode,
        public_ips=public_dns_ips,
        evidence=evidence,
    )

    row: dict[str, str] = {
        COL_ORIGINAL: original_label,
        COL_FINAL_VI: _cell_str(pending_vi) or final_status_vietnamese(internal),
        COL_RESULT_SOURCE: "—" if pending_vi else (_cell_str(result_source) or "—"),
        COL_HTTP: _cell_str(http_code),
        COL_HTTP_VER: _cell_str(http_version) or "—",
        COL_TLS: _cell_str(tls_version),
        COL_CHAIN: _cell_str(redirect_chain),
        COL_DNS: dns_text,
        COL_TCP_80: "—",
        COL_TCP_443: "—",
        COL_PLAYWRIGHT_ERR: "—",
        COL_LATENCY: _cell_str(latency) or "—",
        COL_TRACE: _cell_str(trace),
        "Trạng_Thái": internal if not pending_vi else "",
    }
    if evidence is not None:
        row.update(evidence.as_row_kw())
    if tls_html:
        row["_tls_html"] = tls_html
    if dns_preserve_from:
        row = preserve_dns_evidence_columns(row, dns_preserve_from)
    return row