# Phân loại theo tuyến local; public DNS: DEAD (NXDOMAIN) + so DNS filter/sinkhole.

import asyncio
from typing import Optional

import aiodns
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

from .constants import (
    BACKOFF_BASE_SECONDS,
    DNS_TIMEOUT_SECONDS,
    HTTP_RETRIES,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
)
from .dns import (
    detect_dns_sinkhole,
    resolve_a_and_aaaa,
    resolve_a_and_aaaa_with_rcodes,
)
from .http_fetch import describe_response, extract_host_and_urls, send_live_request
from .labels import build_live_row_dict
from .parsing import is_ipv4


def _classify_local_http_response(
    original_label: str,
    _host: str,
    status_code: int,
    final_url: str,
    history_urls: list[str],
    redirect_chain: str,
    local_rcode: str,
    local_ips: list[str],
    *,
    dns_column_suffix: str = "",
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

    return build_live_row_dict(
        original_label,
        STATUS_LEAKED,
        f"Lọt Gateway | {describe_response(status_code, final_url, history_urls)}",
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
    _ = is_timeout
    block_msg = detail + " — Trên tuyến mạng đang dùng không có phản hồi HTTP đầy đủ → BLOCKED."
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
    session: AsyncSession,
    resolver: aiodns.DNSResolver,
    public_resolver: aiodns.DNSResolver,
    timeout: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    dns_timeout: int = DNS_TIMEOUT_SECONDS,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> dict[str, str]:
    host, urls = extract_host_and_urls(raw_target)
    local_rcode = "—"
    local_ips: list[str] = []
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

    if is_ipv4(host):
        local_rcode, local_ips = ("NOERROR", [host])
    else:
        local_rcode, local_ips = await resolve_a_and_aaaa(host, resolver, dns_timeout, prefer_os_getaddrinfo=True)
        _public_rcode, public_ips, ra_pub, r6_pub = await resolve_a_and_aaaa_with_rcodes(
            host, public_resolver, dns_timeout, prefer_os_getaddrinfo=False
        )

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
                dns_column_suffix="",
            )

        public_has_record_hint = bool(public_ips) or (ra_pub == "NOERROR") or (r6_pub == "NOERROR")
        if local_rcode == "NXDOMAIN" and public_has_record_hint:
            return build_live_row_dict(
                original_label,
                STATUS_BLOCKED,
                "DNS trên tuyến mạng đang dùng: NXDOMAIN — ISP chặn/RPZ DNS (Public DNS vẫn có bản ghi)",
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix="",
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
                dns_column_suffix="",
            )

    for url in urls:
        for attempt in range(3):
            try:
                status_code, final_url, history_urls, redirect_chain, _response_text = await send_live_request(
                    session,
                    url,
                    timeout=timeout,
                    proxy_url=proxy_url,
                    follow_redirects=follow_redirects,
                    retries=retries,
                    backoff_base=backoff_base,
                )
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
                    dns_column_suffix="",
                )
            except Exception as ex:
                if attempt < 2:
                    await asyncio.sleep(backoff_base * (2**attempt))
                    continue
                if isinstance(ex, (asyncio.TimeoutError, TimeoutError)):
                    return _local_transport_fail_row(
                        original_label,
                        local_rcode,
                        local_ips,
                        detail="Timeout HTTP mạng local (đã thử lại 3 lần)",
                        dns_column_suffix="",
                        is_timeout=True,
                    )
                if isinstance(
                    ex,
                    (
                        ConnectionRefusedError,
                        ConnectionResetError,
                        BrokenPipeError,
                    ),
                ):
                    return _local_transport_fail_row(
                        original_label,
                        local_rcode,
                        local_ips,
                        detail="Kết nối TCP/TLS mạng local bị ngắt hoặc từ chối",
                        dns_column_suffix="",
                        is_timeout=False,
                    )
                if isinstance(ex, RequestsError):
                    return _local_transport_fail_row(
                        original_label,
                        local_rcode,
                        local_ips,
                        detail="Lỗi client HTTP mạng local (curl_cffi)",
                        dns_column_suffix="",
                        is_timeout=False,
                    )
                return _local_transport_fail_row(
                    original_label,
                    local_rcode,
                    local_ips,
                    detail=f"Lỗi kỹ thuật khi đo HTTP mạng local (curl_cffi): {ex}",
                    dns_column_suffix="",
                    is_timeout=False,
                )

    return _local_transport_fail_row(
        original_label,
        local_rcode,
        local_ips,
        detail="Không nhận được phản hồi HTTP mạng local sau thử lại",
        dns_column_suffix="",
        is_timeout=False,
    )
