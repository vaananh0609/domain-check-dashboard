"""Phase 2 — deep scan lại các ca Timeout bằng trình duyệt/cấu hình khác."""

from __future__ import annotations

from .labels import DNS_EVIDENCE_COLUMN_KEYS, preserve_dns_evidence_columns
from .constants import COL_FINAL_VI, COL_RESULT_SOURCE

PHASE2_DEFAULT_TIMEOUT_SECONDS = 60
PHASE2_MIN_TIMEOUT_SECONDS = 60
PHASE2_MAX_TIMEOUT_SECONDS = 60

PHASE2_FINAL_TIMEOUT_DETAIL = (
    "Kết nối bị Drop hoàn toàn hoặc vòng lặp WAF từ chối phục vụ "
    "(đã thử qua trình duyệt thực mô phỏng — Phase 2)"
)

BROWSER_PROFILE_ORDER: tuple[str, ...] = ("edge", "chrome", "coccoc")


def clamp_phase2_timeout_seconds(seconds: int) -> int:
    try:
        n = int(seconds)
    except (TypeError, ValueError):
        n = PHASE2_DEFAULT_TIMEOUT_SECONDS
    return max(PHASE2_MIN_TIMEOUT_SECONDS, min(n, PHASE2_MAX_TIMEOUT_SECONDS))


def phase2_browser_profiles(phase1_profile: str) -> tuple[str, ...]:
    """Các profile Phase 2 — mọi trình duyệt khác Phase 1, theo thứ tự cố định."""
    pid = (phase1_profile or "edge").strip().lower()
    return tuple(p for p in BROWSER_PROFILE_ORDER if p != pid)


def alternate_browser_profile(phase1_profile: str) -> str:
    """Profile Phase 2 đầu tiên (tương thích code cũ)."""
    profiles = phase2_browser_profiles(phase1_profile)
    return profiles[0] if profiles else "coccoc"


def _rcode_from_dns_cell(cell: str) -> str:
    s = (cell or "").strip()
    if not s or s == "—":
        return "—"
    if ":" in s:
        return s.split(":", 1)[0].strip() or "—"
    return s


def _ips_from_dns_cell(cell: str) -> list[str]:
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


def merge_phase2_result(phase1_row: dict, phase2_row: dict, *, update_keys: tuple[str, ...] | None = None) -> dict:
    """Giữ bằng chứng Phase 1; cập nhật kết quả đo Phase 2."""
    keys = update_keys or (
        COL_FINAL_VI,
        COL_RESULT_SOURCE,
        "HTTP",
        "HTTP Ver",
        "TLS/SSL",
        "Redirect chain",
        "Playwright error",
        "Latency",
        "Trace",
        "Trạng_Thái",
        "_tls_html",
    )
    merged = dict(phase1_row)
    for key in keys:
        if key in phase2_row and phase2_row[key] not in (None, ""):
            merged[key] = phase2_row[key]
    merged = preserve_dns_evidence_columns(merged, phase1_row)
    for key in DNS_EVIDENCE_COLUMN_KEYS:
        prev = str(phase1_row.get(key) or "").strip()
        if prev and prev != "—":
            merged[key] = phase1_row[key]
    return merged
