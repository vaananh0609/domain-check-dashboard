# Phân loại theo tuyến local; public DNS: DEAD (NXDOMAIN) + so DNS filter/sinkhole.
# Phân loại theo tuyến local; public DNS: DEAD (NXDOMAIN) + so DNS filter/sinkhole.

import asyncio
import json
import re
from typing import Any, Optional
from urllib.parse import quote

import aiodns
import dns.asyncresolver
from curl_cffi.requests import AsyncSession

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
from .http_fetch import describe_response, extract_host_and_urls, send_live_request, probe_tls_version, format_trace_info
from .labels import build_live_row_dict
from .parsing import is_ipv4

CLOUDFLARE_WORKER_URL = "https://falling-glade-cacd.nguyenthivananh2021.workers.dev/?url="


def _http_display_from_worker_error(worker_result: dict[str, Any]) -> str:
    """
    Khi Worker không trả JSON có `status` — vẫn điền cột Mã HTTP (mã edge / mô tả lỗi ngắn).
    """
    err = str(worker_result.get("error", "") or "").strip()
    if not err:
        return "—"
    m = re.match(r"worker_http_(\d+)$", err)
    if m:
        return m.group(1)
    if err.startswith("worker_fail:"):
        tail = err[len("worker_fail:") :].strip()
        return f"Worker: {tail[:120]}" if tail else "Worker: fail"
    if err == "worker_json_parse":
        return "Worker: JSON parse"
    if err == "worker_json_invalid":
        return "Worker: JSON invalid"
    return f"Worker: {err[:120]}"


def _raw_worker_status_value(worker_result: dict[str, Any]) -> Any:
    """Worker có thể dùng `status`, `http_status`, `code`, `http_code`."""
    for key in ("status", "http_status", "code", "http_code"):
        if key not in worker_result:
            continue
        v = worker_result[key]
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


async def has_ech_record(host: str) -> bool:
    """Query HTTPS record qua public DNS, kiểm tra ECH param (key 5)."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 3
        resolver.lifetime = 3
        answer = await resolver.resolve(host, "HTTPS")
        for rdata in answer:
            params = getattr(rdata, "params", {})
            if params and 5 in params:
                return True
        return False
    except Exception:
        return False


async def probe_tcp(ip: str, port: int = 443, timeout: float = 5.0) -> bool:
    """True = TCP connect được -> IP không bị chặn tầng mạng local."""
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _parse_worker_status_int(raw: Any) -> Optional[int]:
    """Parse mã HTTP từ JSON (int, float, '523', '523.0', …)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    if isinstance(raw, float):
        if raw != raw:
            return None
        i = int(raw)
        return i if i > 0 else None
    s = str(raw).strip()
    if not s:
        return None
    try:
        i = int(float(s))
        return i if i > 0 else None
    except (ValueError, OverflowError):
        return None


def _worker_final_url(worker_result: dict[str, Any], probe_url: str) -> str:
    u = (
        worker_result.get("final_url")
        or worker_result.get("url")
        or worker_result.get("finalUrl")
        or ""
    )
    s = str(u).strip()
    return s if s else probe_url


def _http_col_when_worker_row_missing(worker_result: dict[str, Any]) -> str:
    """Có `error` hoặc raw status nhưng không build được row — vẫn điền cột HTTP."""
    err = str(worker_result.get("error", "") or "").strip()
    if err:
        return _http_display_from_worker_error(worker_result)
    raw = _raw_worker_status_value(worker_result)
    if raw is not None:
        t = str(raw).strip()
        if t:
            return t[:80]
    return "—"


def analyze_http_status(status_code: int) -> str:
    """
    Phân loại mã HTTP thống nhất (local và Worker).
    Trả về SERVER_DEAD | WAF_BLOCK | ALIVE.
    """
    if status_code in (500, 502, 504) or (520 <= status_code <= 530):
        return "SERVER_DEAD"
    if status_code in (403, 406, 429, 451, 503):
        return "WAF_BLOCK"
    return "ALIVE"


def _build_worker_row(
    original_label: str,
    internal: str,
    detail: str,
    *,
    proxy_final_url: str,
    proxy_http_status: int,
    local_rcode: str,
    local_ips: list[str],
    dns_column_suffix: str = "",
) -> dict[str, str]:
    """Worker JSON: `status` → Mã HTTP, `final_url` → URL đích (đã gộp fallback probe nếu trống)."""
    return build_live_row_dict(
        original_label,
        internal,
        detail,
        proxy_final_url,
        str(proxy_http_status),
        "—",
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
    )


async def _verify_with_worker(target_url: str) -> dict[str, Any]:
    """Gọi Worker: Luôn cố gắng đọc JSON bất kể status_code để lấy log lỗi chi tiết từ JS."""
    try:
        q = quote(target_url, safe="")
        worker_url = f"{CLOUDFLARE_WORKER_URL}{q}"
        async with AsyncSession() as ws:
            res = await ws.get(
                worker_url,
                timeout=15,
                verify=False,
                impersonate="chrome",
            )

        # Luôn thử ép kiểu JSON trước (Worker JS của ta luôn trả về JSON)
        try:
            data = res.json()
        except Exception:
            try:
                data = json.loads(res.text or "")
            except Exception:
                data = None

        # Nếu lấy được JSON hợp lệ từ Worker, trả nguyên dict (giữ các trường cần thiết)
        if isinstance(data, dict):
            return data

        # Fallback nếu Worker trả về HTML rác (lỗi nền tảng của Cloudflare)
        return {"error": f"worker_http_{res.status_code}"}

    except Exception as e:
        return {"error": f"worker_fail: {str(e)}"}


def _row_from_worker_result(
    original_label: str,
    worker_result: dict[str, Any],
    local_rcode: str,
    local_ips: list[str],
    *,
    public_ips: Optional[list[str]] = None,
    probe_url: str,
    dns_column_suffix: str = "",
) -> Optional[dict[str, str]]:
    raw_status = _raw_worker_status_value(worker_result)
    if raw_status is None:
        return None

    proxy_final_url = _worker_final_url(worker_result, probe_url)
    proxy_status = _parse_worker_status_int(raw_status)

    if proxy_status is None:
        return build_live_row_dict(
            original_label,
            STATUS_DEAD,
            f"Đối chứng Worker: mã HTTP không parse được ({str(raw_status)[:50]!r})",
            proxy_final_url,
            str(raw_status).strip()[:80] or "—",
            "—",
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
        )

    kind = analyze_http_status(proxy_status)
    if kind == "SERVER_DEAD":
        return _build_worker_row(
            original_label,
            STATUS_DEAD,
            f"Máy chủ / origin lỗi toàn cầu (đối chứng HTTP {proxy_status}) → DEAD",
            proxy_final_url=proxy_final_url,
            proxy_http_status=proxy_status,
            local_rcode=local_rcode,
            local_ips=local_ips,
            dns_column_suffix=dns_column_suffix,
        )
    if kind == "WAF_BLOCK":
        return _build_worker_row(
            original_label,
            STATUS_LEAKED,
            f"Local lỗi nhưng đối chứng HTTP {proxy_status} (WAF/anti-bot) → LEAKED",
            proxy_final_url=proxy_final_url,
            proxy_http_status=proxy_status,
            local_rcode=local_rcode,
            local_ips=local_ips,
            dns_column_suffix=dns_column_suffix,
        )

    pub_ips = public_ips or []
    try:
        if detect_dns_sinkhole(local_ips, pub_ips):
            return _build_worker_row(
                original_label,
                STATUS_BLOCKED,
                f"DNS sinkhole/local DNS trả IP rác so với public (đối chứng HTTP {proxy_status}) → BLOCKED",
                proxy_final_url=proxy_final_url,
                proxy_http_status=proxy_status,
                local_rcode=local_rcode,
                local_ips=local_ips,
                dns_column_suffix=dns_column_suffix,
            )
    except Exception:
        pass

    return _build_worker_row(
        original_label,
        STATUS_LEAKED,
        f"Local probe thất bại nhưng đối chứng HTTP {proxy_status} — khả năng lỗi mạng cục bộ/tạm thời → LEAKED",
        proxy_final_url=proxy_final_url,
        proxy_http_status=proxy_status,
        local_rcode=local_rcode,
        local_ips=local_ips,
        dns_column_suffix=dns_column_suffix,
    )


def _classify_local_http_response(
    original_label: str,
    _host: str,
    status_code: int,
    final_url: str,
    history_urls: list[str],
    redirect_chain: str,
    local_rcode: str,
    local_ips: list[str],
    tls_version: Optional[str],
    *,
    dns_column_suffix: str = "",
    trace_http: Optional[dict] = None,
) -> dict[str, str]:
    http_code = str(status_code)
    kind = analyze_http_status(status_code)
    
    # Build detail message with optional trace info
    detail_base = ""
    if kind == "SERVER_DEAD":
        detail_base = f"Máy chủ / origin lỗi (HTTP {status_code}) — Cloudflare hoặc upstream sập / không tới được origin"
    elif kind == "WAF_BLOCK":
        detail_base = f"Bị tường lửa / WAF chặn probe (HTTP {status_code})"
    else:
        detail_base = f"Lọt Gateway | {describe_response(status_code, final_url, history_urls)}"
    
    # Append trace info if available
    if trace_http:
        trace_str = format_trace_info(trace_http)
        detail_msg = f"{detail_base} | Trace: {trace_str}"
    else:
        detail_msg = detail_base
    
    if kind == "SERVER_DEAD":
        return build_live_row_dict(
            original_label,
            STATUS_DEAD,
            detail_msg,
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
        )
    if kind == "WAF_BLOCK":
        return build_live_row_dict(
            original_label,
            STATUS_LEAKED,
            detail_msg,
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
        detail_msg,
        final_url,
        http_code,
        redirect_chain,
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
        tls_version=tls_version,
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
    is_ip_target = is_ipv4(host)
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

    if is_ip_target:
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

        # TIMEOUT và không có bản ghi A/AAAA từ public -> coi là DEAD.
        if not public_ips and _public_rcode == "TIMEOUT":
            return build_live_row_dict(
                original_label,
                STATUS_DEAD,
                "Public DNS TIMEOUT và không có bản ghi A/AAAA -> DEAD",
                "",
                "",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix="",
            )

        public_has_record_hint = bool(public_ips)
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

    # Retry + backoff chỉ ở đây; send_live_request(..., retries=0) tránh chồng với retry trong http_fetch.
    for url in urls:
        for attempt in range(retries + 1):
            try:
                status_code, final_url, history_urls, redirect_chain, _response_text, tls_version, trace_http = await send_live_request(
                    session,
                    url,
                    timeout=timeout,
                    proxy_url=proxy_url,
                    follow_redirects=follow_redirects,
                    retries=0,
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
                    tls_version,
                    local_rcode,
                    local_ips,
                    dns_column_suffix="",
                    trace_http=trace_http,
                )
            except Exception as http_exc:
                if attempt < retries:
                    await asyncio.sleep(backoff_base * (2**attempt))
                    continue

                # Local HTTP failed - cần probe TLS để xác định BLOCKED vs LEAKED
                trace_tls_13, probe_trace_13 = await probe_tls_version(host, port=443, timeout=float(timeout), force_tls12=False)
                
                if trace_tls_13:
                    # TLS probe thành công → vẫn gọi Worker để lấy HTTP code thực
                    worker_result = await _verify_with_worker(url)
                    worker_http_code = _http_col_when_worker_row_missing(worker_result) if isinstance(worker_result, dict) else "—"
                    
                    tls_probe_detail = f"Local HTTP fail nhưng TLS {trace_tls_13} probe thành công → LEAKED | {format_trace_info(probe_trace_13)}"
                    return build_live_row_dict(
                        original_label,
                        STATUS_LEAKED,
                        tls_probe_detail,
                        url,
                        worker_http_code,  # ← dùng HTTP code từ Worker thay vì "—"
                        "—",  # redirect_chain vẫn "—" vì local HTTP fail
                        local_rcode,
                        local_ips,
                        dns_column_suffix="",
                        tls_version=trace_tls_13,
                    )

                # TLS probe fail - IP trực tiếp: không có SNI/ECH -> probe cả 443 và 80,
                # kết luận dựa vào kết nối TCP local thay vì dựa vào Worker.
                if is_ip_target:
                    tcp_443 = await probe_tcp(host, port=443, timeout=float(timeout))
                    tcp_80 = await probe_tcp(host, port=80, timeout=float(timeout))
                    tcp_ok = tcp_443 or tcp_80

                    if not tcp_ok:
                        return build_live_row_dict(
                            original_label,
                            STATUS_BLOCKED,
                            f"IP trực tiếp, TCP {host}:443 và :80 đều không kết nối được -> BLOCKED tầng mạng",
                            url,
                            "—",
                            "—",
                            local_rcode,
                            local_ips,
                            dns_column_suffix="",
                        )

                    port_ok = 443 if tcp_443 else 80
                    return build_live_row_dict(
                        original_label,
                        STATUS_LEAKED,
                        f"IP trực tiếp, TCP:{port_ok} reachable từ local -> người dùng vào được -> LEAKED",
                        url,
                        "—",
                        "—",
                        local_rcode,
                        local_ips,
                        dns_column_suffix="",
                    )

                # Local HTTP fail hết retry → kiểm tra ECH để quyết định BLOCKED vs verify with Worker
                ech = await has_ech_record(host)
                if not ech:
                    # Không có ECH → BLOCKED
                    return build_live_row_dict(
                        original_label,
                        STATUS_BLOCKED,
                        "Local HTTP fail, không có ECH record → người dùng không bypass SNI block được → BLOCKED",
                        url,
                        "—",
                        "—",
                        local_rcode,
                        local_ips,
                        dns_column_suffix="",
                    )

                # Có ECH → verify with Worker để xác định LEAKED hay DEAD
                worker_result = await _verify_with_worker(url)
                row = _row_from_worker_result(
                    original_label,
                    worker_result,
                    local_rcode,
                    local_ips,
                    public_ips=public_ips,
                    probe_url=url,
                    dns_column_suffix="",
                )
                if row is not None:
                    return row
                err_msg = (
                    worker_result.get("error", "unknown error")
                    if isinstance(worker_result, dict)
                    else "unknown error"
                )
                wr = worker_result if isinstance(worker_result, dict) else {}
                http_disp = _http_col_when_worker_row_missing(wr)

                return build_live_row_dict(
                    original_label,
                    STATUS_DEAD,
                    f"Có ECH nhưng Worker cũng không phản hồi (Server Down: {err_msg}) → DEAD",
                    url,
                    http_disp,
                    "—",
                    local_rcode,
                    local_ips,
                    dns_column_suffix="",
                )
