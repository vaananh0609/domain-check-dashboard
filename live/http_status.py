"""
Phân loại mã HTTP cho Probe Tool — ưu tiên phát hiện lọt Gateway.

Nguyên tắc: có phản hồi HTTP từ hạ tầng phía sau ISP → LEAKED (kể cả 404, 5xx, 522).
DEAD (tầng HTTP): chỉ khi không có mã HTTP hoặc vòng lặp redirect vô hạn.
BLOCKED: 451, redirect cảnh báo ISP, 403 + body kiểm duyệt, DNS sinkhole (Bước 1), TLS SNI reset (DPI).
TIMEOUT: hết thời gian chờ TCP/TLS/HTTP/Playwright — không đủ chứng cứ chặn ISP.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .constants import REDIRECT_STATUS_CODES
from .http_models import HttpProbeResult, _via_implies_h3

# Kind nội bộ → map sang STATUS_* trong classify.py
KIND_LEAKED = "LEAKED"
KIND_SERVER_DEAD = "SERVER_DEAD"  # chỉ dùng khi không có phản hồi HTTP (code <= 0)
KIND_CLIENT_DEAD = "CLIENT_DEAD"  # alias SERVER_DEAD — không có HTTP
KIND_NOT_FOUND_LEAKED = "NOT_FOUND_LEAKED"
KIND_CF_ORIGIN_LEAKED = "CF_ORIGIN_LEAKED"
KIND_CLIENT_FORBIDDEN = "CLIENT_FORBIDDEN"
KIND_CENSORSHIP_BLOCK = "CENSORSHIP_BLOCK"
KIND_ISP_REDIRECT_BLOCK = "ISP_REDIRECT_BLOCK"
KIND_WAF_LEAKED = "WAF_LEAKED"
KIND_CF_WAF_LEAKED = "CF_WAF_LEAKED"
KIND_REDIRECT_LOOP = "REDIRECT_LOOP"
KIND_TOOL_ERROR = "TOOL_ERROR"
KIND_TEMPORARY_ERROR = "TEMPORARY_ERROR"
KIND_MISDIRECTED = "MISDIRECTED"

_CF_ORIGIN_DEAD_CODES = frozenset(range(520, 531))

_ISP_BLOCK_LOCATION_HINTS = (
    "block",
    "blocked",
    "canh-bao",
    "canhbao",
    "cảnh báo",
    "warning",
    "access-denied",
    "access_denied",
    "tttt",
    "vi-pham",
    "not_available",
    "filter",
    "gateway",
    "cpd",
    "walled",
)

_ISP_BLOCK_HOST_HINTS = (
    "block",
    "warning",
    "filter",
    "gateway",
    "captive",
    "redirect",
)

_ISP_BLOCK_BODY_HINTS = _ISP_BLOCK_LOCATION_HINTS + (
    "vi phạm",
    "truy cập bị chặn",
    "truy cap bi chan",
    "không được phép",
    "khong duoc phep",
    "illegal content",
    "legal reasons",
    "bộ thông tin",
    "bo thong tin",
    "vnpt",
    "viettel",
    "fpt",
)


def _status_series(status: int) -> int:
    if 100 <= status <= 599:
        return status // 100
    return 0


def _body_suggests_isp_censorship(probe: HttpProbeResult) -> bool:
    text = (probe.body or "").lower()
    if not text:
        return False
    return any(h in text for h in _ISP_BLOCK_BODY_HINTS)


def _final_host_matches_target(probe: HttpProbeResult, original_host: str) -> bool:
    orig = (original_host or "").strip().lower().rstrip(".")
    if not orig:
        return True
    try:
        parsed = urlsplit(probe.final_url or "")
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    return host == orig or host.endswith("." + orig)


def classify_http_status_code(status: int, *, is_cloudflare: bool = False) -> str:
    """
    Phân loại một mã HTTP (không có redirect chain / body).
    Dùng cho đối chứng Worker.
    """
    series = _status_series(status)
    if series == 1 or series == 2:
        return KIND_LEAKED
    if series == 3:
        return KIND_LEAKED
    if status in _CF_ORIGIN_DEAD_CODES:
        return KIND_CF_ORIGIN_LEAKED
    if series == 5:
        return KIND_TEMPORARY_ERROR
    if series == 4:
        if status == 400:
            return KIND_TOOL_ERROR
        if status == 421:
            return KIND_MISDIRECTED
        if status == 451:
            return KIND_CENSORSHIP_BLOCK
        if status in (403, 429) and is_cloudflare:
            return KIND_WAF_LEAKED
        if status == 403:
            return KIND_CLIENT_FORBIDDEN
        if status in (404, 410):
            return KIND_NOT_FOUND_LEAKED
        return KIND_LEAKED
    return KIND_LEAKED


def _is_isp_block_redirect(probe: HttpProbeResult, original_host: str) -> bool:
    """3xx trỏ sang trang cảnh báo / domain lạ — pattern chặn proxy ISP."""
    orig = (original_host or "").strip().lower().rstrip(".")
    for hop in probe.hops:
        if hop.status not in REDIRECT_STATUS_CODES:
            continue
        loc = (hop.location or "").lower()
        if any(h in loc for h in _ISP_BLOCK_LOCATION_HINTS):
            return True
        try:
            parsed = urlsplit(loc if "://" in loc else f"//{loc}")
            redir_host = (parsed.hostname or "").lower().rstrip(".")
        except Exception:
            redir_host = ""
        if not redir_host or not orig:
            continue
        if redir_host == orig or redir_host.endswith("." + orig):
            continue
        if any(h in redir_host for h in _ISP_BLOCK_HOST_HINTS):
            return True
    return False


def analyze_http_context(
    probe: HttpProbeResult,
    *,
    original_host: str = "",
    dns_sinkhole: bool = False,
) -> str:
    """
    Phân loại HTTP đầy đủ (có Server header, redirect chain, body).
    Trả về kind nội bộ — classify.py map sang BLOCKED/LEAKED/DEAD.
    """
    code = probe.final_status
    if probe.redirect_loop:
        return KIND_REDIRECT_LOOP

    if code <= 0:
        return KIND_CLIENT_DEAD

    series = _status_series(code)

    if code == 421:
        return KIND_MISDIRECTED

    if series == 1 or series == 2:
        if _via_implies_h3(probe.via) and original_host and not _final_host_matches_target(probe, original_host):
            return KIND_MISDIRECTED
        return KIND_LEAKED

    if series == 3:
        if dns_sinkhole or _is_isp_block_redirect(probe, original_host):
            return KIND_ISP_REDIRECT_BLOCK
        return KIND_LEAKED

    if code in _CF_ORIGIN_DEAD_CODES:
        return KIND_CF_ORIGIN_LEAKED

    if series == 5:
        return KIND_TEMPORARY_ERROR

    if series == 4:
        if code == 400:
            return KIND_TOOL_ERROR
        if code == 451:
            return KIND_CENSORSHIP_BLOCK
        if probe.is_cloudflare and code in (403, 429):
            return KIND_CF_WAF_LEAKED
        if code == 403:
            if _body_suggests_isp_censorship(probe):
                return KIND_CENSORSHIP_BLOCK
            return KIND_CLIENT_FORBIDDEN
        if code in (404, 410):
            return KIND_NOT_FOUND_LEAKED
        return KIND_LEAKED

    return KIND_LEAKED


def analyze_http_status(status_code: int) -> str:
    """Alias Worker đối chứng — không có header Server."""
    return classify_http_status_code(status_code, is_cloudflare=False)
