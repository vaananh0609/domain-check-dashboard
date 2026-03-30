"""
Phân loại live — **VNPT-first / tuyến local là chân lý**: kết quả đo trên mạng đang dùng quyết định LEAKED/PARKED/BLOCKED.

**Public DNS** chỉ để: (1) **DEAD** khi cả A và AAAA đều NXDOMAIN; (2) so sánh phụ cho **DNS filter** (local NXDOMAIN
còn public có bản ghi) và **sinkhole private** (local RFC1918/127… còn public có IP công cộng). **Không** chặn chỉ vì
local và public trả **khác IP công cộng** (CDN/anycast/geo).

**Không** probe HTTP qua Internet công khai để phân loại — tránh lệch so với hành vi VNPT.

Luồng: public DEAD? → local DNS (filter / sinkhole private) → HTTP local (retry 3, **có 1 lần HTTP là xếp theo đó**) → PARKED → LEAKED.

1. **DEAD** — Cả query public A và AAAA đều NXDOMAIN.

2. **BLOCKED** — Sau **3 lần** HTTP đều lỗi; hoặc HTTP 403/451; hoặc DNS filter; hoặc **IP local private/sinkhole** so với public.

3. **PARKED** — NS/redirect parking (strict).

4. **LEAKED** — Bất kỳ phản hồi HTTP hợp lệ nào trên local (trừ các nhánh trên).
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import aiohttp
import aiodns

from .constants import (
    BACKOFF_BASE_SECONDS,
    DNS_TIMEOUT_SECONDS,
    HTTP_RETRIES,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_PARKED,
    PRIVATE_IP_PREFIXES,
    USER_AGENT,
)
from .dns import (
    detect_dns_sinkhole,
    detect_dns_sparse_local,
    is_parked_by_dns,
    resolve_a_and_aaaa,
    resolve_a_and_aaaa_with_rcodes,
    resolve_ns_records,
)
from .http_fetch import describe_response, extract_host_and_urls, send_live_request
from .labels import (
    build_live_row_dict,
    is_parked_by_page_content,
    is_parked_by_redirect,
    is_sensitive_by_page_content,
)
from .parsing import is_ipv4


#region agent log
_DEBUG_LOG_PATH = Path(__file__).resolve().parents[1] / "debug-fc053f.log"


def _dbg_log(hypothesisId: str, location: str, message: str, data: Optional[dict] = None, *, runId: str = "debug_before_fix") -> None:
    """
    NDJSON log phục vụ debug mode (không ảnh hưởng logic phân loại).
    """
    try:
        payload: dict = {
            "sessionId": "fc053f",
            "runId": runId,
            "hypothesisId": hypothesisId,
            "location": location,
            "message": message,
            "data": data or {},
            "timestamp": int(time.time() * 1000),
        }
        with _DEBUG_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        # Tuyệt đối không làm vỡ luồng classify vì lỗi log.
        pass

#endregion


def _http_final_success(status: int) -> bool:
    return 200 <= status < 300


def _http_server_error(status: int) -> bool:
    return 500 <= status < 600


def _classify_local_http_response(
    original_label: str,
    host: str,
    status_code: int,
    final_url: str,
    history_urls: list[str],
    redirect_chain: str,
    local_rcode: str,
    local_ips: list[str],
    *,
    dns_column_suffix: str = "",
    response_body: str = "",
) -> dict[str, str]:
    http_code = str(status_code)
    if status_code in (403, 451):
        return build_live_row_dict(
            original_label,
            STATUS_BLOCKED,
            f"HTTP {status_code} trên tuyến mạng đang dùng — từ chối/WAF (chặn truy cập)",
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
        )
    if _http_server_error(status_code):
        return build_live_row_dict(
            original_label,
            STATUS_LEAKED,
            f"HTTP {status_code} — máy chủ/CDN phản hồi trên tuyến local (có mã HTTP)",
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
        )
    if 400 <= status_code < 500:
        detail = f"HTTP {status_code} — máy chủ trả client error trên tuyến local (có phản hồi HTTP)"
        return build_live_row_dict(
            original_label,
            STATUS_LEAKED,
            detail,
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
        )
    if _http_final_success(status_code):
        parked_redirect = is_parked_by_redirect(host, history_urls, final_url)
        parked_page = is_parked_by_page_content(response_body, final_url)

        try:
            body_text = response_body or ""
        except Exception:
            body_text = ""

        sensitive = is_sensitive_by_page_content(body_text, final_url)

        if (parked_redirect or parked_page) and not sensitive:
            #region agent log
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
            moderate_keywords = (
                "betting",
                "sportsbook",
                "sports betting",
                "wager",
                "bookmaker",
                "gambling",
            )
            snippet = (body_text or "")[:200_000].lower()
            strong_hit = any((kw in snippet) for kw in strong_keywords)
            moderate_hits = sum(1 for kw in moderate_keywords if kw in snippet)
            _dbg_log(
                "H_parked_precedence",
                "classify._classify_local_http_response/http_200_decision",
                "Local 200-299 triggered parked hints; sensitive=false -> likely mislabeled as PARKED.",
                data={
                    "status_code": status_code,
                    "final_url": final_url,
                    "parked_redirect": parked_redirect,
                    "parked_page": parked_page,
                    "sensitive": sensitive,
                    "body_len": len(body_text or ""),
                    "strong_hit": strong_hit,
                    "moderate_hits": moderate_hits,
                    "history_count": len(history_urls or []),
                },
            )
            #endregion

        if parked_redirect:
            return build_live_row_dict(
                original_label,
                STATUS_PARKED,
                "Redirect sang domain parked/registrar",
                final_url,
                http_code,
                redirect_chain,
                local_rcode,
                local_ips,
                dns_column_suffix=dns_column_suffix,
            )
        if parked_page:
            return build_live_row_dict(
                original_label,
                STATUS_PARKED,
                "Nội dung trang parking / tên miền hết hạn hoặc for-sale (không phải site đang hoạt động)",
                final_url,
                http_code,
                redirect_chain,
                local_rcode,
                local_ips,
                dns_column_suffix=dns_column_suffix,
            )
        # Chỉ gán LEAKED khi HTTP 200..299 và nội dung có dấu hiệu cờ bạc/nhạy cảm.
        # Nếu không có dấu hiệu nhạy cảm, coi là PARKED / NO CONTENT (không kết luận lọt).
        if sensitive:
            return build_live_row_dict(
                original_label,
                STATUS_LEAKED,
                f"Lọt Gateway | {describe_response(status_code, final_url, history_urls)} (nội dung nhạy cảm)",
                final_url,
                http_code,
                redirect_chain,
                local_rcode,
                local_ips,
                dns_column_suffix=dns_column_suffix,
            )

        return build_live_row_dict(
            original_label,
            STATUS_PARKED,
            f"HTTP {status_code} nhưng không có nội dung cờ bạc rõ rệt → PARKED / NO CONTENT",
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
        )
    return build_live_row_dict(
        original_label,
        STATUS_LEAKED,
        f"HTTP {status_code} — có phản hồi từ máy chủ trên tuyến local",
        final_url,
        http_code,
        redirect_chain,
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
    )


def _local_transport_fail_row(
    original_label: str,
    local_rcode: str,
    local_ips: list[str],
    *,
    detail: str,
    dns_column_suffix: str = "",
    is_timeout: bool = False,
) -> dict[str, str]:
    def _is_private_ip(ip: str) -> bool:
        for p in PRIVATE_IP_PREFIXES:
            if p.endswith(".") and ip.startswith(p):
                return True
            if ip == p:
                return True
        return False

    def _has_cloudflare_cf_combo(ips: list[str]) -> bool:
        has_104_21 = any((i or "").startswith("104.21.") for i in ips)
        has_172_67 = any((i or "").startswith("172.67.") for i in ips)
        return has_104_21 and has_172_67

    # Heuristic VNPT-first từ thực nghiệm:
    # Nếu DNS local có combo 104.21.* + 172.67.* thì:
    # - Nếu lỗi là TIMEOUT → coi là LEAKED (không đo được HTTP)
    # - Nếu lỗi là connection refused/reset → coi là BLOCKED (chặn thực)
    # Không có combo 104.21.* + 172.67.* và không lấy được mã HTTP → BLOCKED
    if _has_cloudflare_cf_combo(local_ips) and not any(_is_private_ip(i) for i in local_ips):
        if is_timeout:
            leak_msg = (
                detail
                + " — DNS local có combo 104.21.x.x + 172.67.x.x (gợi ý Cloudflare), lỗi timeout → coi là LEAKED."
            )
            return build_live_row_dict(
                original_label,
                STATUS_LEAKED,
                leak_msg,
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix=dns_column_suffix,
            )
        else:
            block_msg = (
                detail
                + " — DNS local có combo 104.21.x.x + 172.67.x.x (gợi ý Cloudflare), nhưng kết nối bị chặn → BLOCKED."
            )
            return build_live_row_dict(
                original_label,
                STATUS_BLOCKED,
                block_msg,
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix=dns_column_suffix,
            )

    block_msg = (
        detail
        + " — Trên tuyến mạng đang dùng không có phản hồi HTTP đầy đủ → BLOCKED."
    )
    return build_live_row_dict(
        original_label,
        STATUS_BLOCKED,
        block_msg,
        "",
        "",
        "—",
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
    )


async def classify_live_domain(
    raw_target: str,
    original_label: str,
    session: aiohttp.ClientSession,
    resolver: aiodns.DNSResolver,
    public_resolver: aiodns.DNSResolver,
    public_session: aiohttp.ClientSession,  # giữ API runner; không dùng để probe HTTP phân loại (VNPT-first)
    timeout: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    use_playwright: bool = True,
    dns_timeout: int = DNS_TIMEOUT_SECONDS,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> dict[str, str]:
    host, urls = extract_host_and_urls(raw_target)
    local_rcode = "—"
    local_ips: list[str] = []
    public_rcode = "—"
    public_ips: list[str] = []

    if not host or not urls:
        return build_live_row_dict(
            original_label,
            STATUS_DEAD,
            "Input không hợp lệ",
            "",
            "",
            "—",
            "N/A",
            [],
        )

    dns_compare_hint = ""

    if is_ipv4(host):
        local_rcode, local_ips = ("NOERROR", [host])
    else:
        local_rcode, local_ips = await resolve_a_and_aaaa(host, resolver, dns_timeout, prefer_os_getaddrinfo=True)
        public_rcode, public_ips, ra_pub, r6_pub = await resolve_a_and_aaaa_with_rcodes(
            host, public_resolver, dns_timeout, prefer_os_getaddrinfo=False
        )
        if detect_dns_sparse_local(local_ips, public_ips):
            dns_compare_hint = " | gợi ý: local 1 IP vs public ≥2 (CDN/throttle DNS)"

        if ra_pub == "NXDOMAIN" and r6_pub == "NXDOMAIN":
            return build_live_row_dict(
                original_label,
                STATUS_DEAD,
                "Public DNS: cả A và AAAA đều NXDOMAIN (tên không tồn tại)",
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix=dns_compare_hint,
            )

        if local_rcode == "NXDOMAIN" and public_rcode == "NOERROR":
            public_ns = await resolve_ns_records(host, public_resolver, dns_timeout)
            if is_parked_by_dns(public_ns):
                return build_live_row_dict(
                    original_label,
                    STATUS_PARKED,
                    "NS cho thấy domain parked/registrar",
                    "",
                    "",
                    "—",
                    local_rcode,
                    local_ips,
                    dns_column_suffix=dns_compare_hint,
                )
            return build_live_row_dict(
                original_label,
                STATUS_BLOCKED,
                "DNS trên tuyến mạng đang dùng: NXDOMAIN — ISP chặn/RPZ DNS (Public DNS vẫn có bản ghi)",
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix=dns_compare_hint,
            )

        if detect_dns_sinkhole(local_ips, public_ips):
            return build_live_row_dict(
                original_label,
                STATUS_BLOCKED,
                "DNS sinkhole trên tuyến local (IP rác) — chặn DNS ISP so với bản ghi công khai",
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix=dns_compare_hint,
            )

    use_playwright_for_fetch = bool(use_playwright)

    for url in urls:
        for attempt in range(3):
            try:
                if use_playwright_for_fetch:
                    try:
                        from .playwright_helper import fetch_with_playwright
                    except Exception:
                        status_code, final_url, history_urls, redirect_chain, _response_text = await send_live_request(
                            session,
                            url,
                            timeout=timeout,
                            proxy_url=proxy_url,
                            follow_redirects=follow_redirects,
                            retries=retries,
                            backoff_base=backoff_base,
                        )
                    else:
                        try:
                            status_code, final_url, history_urls, _response_text, redirect_chain = await fetch_with_playwright(
                                url, timeout=timeout, user_agent=USER_AGENT, extra_headers={"Accept-Language": "vi-VN"}
                            )
                        except Exception:
                            status_code, final_url, history_urls, redirect_chain, _response_text = await send_live_request(
                                session,
                                url,
                                timeout=timeout,
                                proxy_url=proxy_url,
                                follow_redirects=follow_redirects,
                                retries=retries,
                                backoff_base=backoff_base,
                            )
                else:
                    status_code, final_url, history_urls, redirect_chain, _response_text = await send_live_request(
                        session,
                        url,
                        timeout=timeout,
                        proxy_url=proxy_url,
                        follow_redirects=follow_redirects,
                        retries=retries,
                        backoff_base=backoff_base,
                    )
                # Playwright đôi khi trả về status_code=0 khi không có response HTTP.
                # Trường hợp này không nên coi là LEAKED; coi như đo thất bại mạng và retry.
                if not isinstance(status_code, int) or status_code <= 0:
                    raise RuntimeError(f"No HTTP response (status_code={status_code})")
                return _classify_local_http_response(
                    original_label,
                    host,
                    status_code,
                    final_url,
                    history_urls,
                    redirect_chain,
                    local_rcode,
                    local_ips,
                    dns_column_suffix=dns_compare_hint,
                    response_body=_response_text or "",
                )
            except Exception as ex:
                if attempt < 2:
                    await asyncio.sleep(backoff_base * (2**attempt))
                    continue
                if isinstance(ex, asyncio.TimeoutError):
                    return _local_transport_fail_row(
                        original_label,
                        local_rcode,
                        local_ips,
                        detail="Timeout HTTP mạng local (đã thử lại 3 lần)",
                        dns_column_suffix=dns_compare_hint,
                        is_timeout=True,
                    )
                if isinstance(
                    ex,
                    (
                        aiohttp.ClientConnectionError,
                        aiohttp.ClientSSLError,
                        aiohttp.ClientConnectorError,
                        ConnectionRefusedError,
                        ConnectionResetError,
                    ),
                ):
                    return _local_transport_fail_row(
                        original_label,
                        local_rcode,
                        local_ips,
                        detail="Kết nối TCP/TLS mạng local bị ngắt hoặc từ chối",
                        dns_column_suffix=dns_compare_hint,
                        is_timeout=False,
                    )
                if isinstance(ex, aiohttp.ClientError):
                    return _local_transport_fail_row(
                        original_label,
                        local_rcode,
                        local_ips,
                        detail="Lỗi client HTTP mạng local",
                        dns_column_suffix=dns_compare_hint,
                        is_timeout=False,
                    )
                return _local_transport_fail_row(
                    original_label,
                    local_rcode,
                    local_ips,
                    detail=f"Lỗi kỹ thuật khi đo HTTP mạng local (Playwright/aiohttp): {ex}",
                    dns_column_suffix=dns_compare_hint,
                    is_timeout=False,
                )

    return _local_transport_fail_row(
        original_label,
        local_rcode,
        local_ips,
        detail="Không nhận được phản hồi HTTP mạng local sau thử lại",
        dns_column_suffix=dns_compare_hint,
        is_timeout=False,
    )
