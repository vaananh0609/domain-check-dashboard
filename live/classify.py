# Phân loại theo tuyến local; public DNS: DEAD (NXDOMAIN) + so DNS filter/sinkhole.

import asyncio
import json
import re
from typing import Any, Optional
from urllib.parse import quote
import ssl

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
from .http_fetch import describe_response, extract_host_and_urls, send_live_request
from .labels import build_live_row_dict
from .parsing import is_ipv4

CLOUDFLARE_WORKER_URL = "https://falling-glade-cacd.nguyenthivananh2021.workers.dev/?url="

# Cache TLS probe results for the lifetime of the process/run to avoid duplicate probes
_tls_cache: dict[str, str] = {}
_tls_locks: dict[str, asyncio.Lock] = {}
# Limit concurrent worker fallbacks to avoid hammering the remote worker
_worker_semaphore = asyncio.Semaphore(8)


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


async def _probe_tls_local(host: str, port: int = 443, timeout: float = 2.0, server_hostname: Optional[str] = None) -> str:
    """Try a local TLS handshake and return the negotiated protocol string (e.g. 'TLSv1.3').

    `host` is the connect target (IP or hostname). `server_hostname` if provided will be
    used as the SNI value in the TLS handshake (useful when connecting directly to an IP).
    """
    sni = server_hostname or host
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        coro = asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                proto = ""
            else:
                proto = ssl_obj.version() or ""
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return str(proto or "")
    except Exception:
        return ""


async def _fetch_tls_via_worker(target_url: str) -> str:
    """Call the worker (with concurrency limit) and extract TLS version from its JSON result."""
    try:
        async with _worker_semaphore:
            res = await _verify_with_worker(target_url)
        if isinstance(res, dict):
            return str(res.get("tls_version") or res.get("tls") or "")
    except Exception:
        pass
    return ""


async def _get_tls_cached(host: str, port: int = 443, probe_timeout: float = 1.5, use_worker_fallback: bool = False, worker_probe_url: Optional[str] = None) -> str:
    """Return TLS version for host:port using cache -> local probe -> optional worker fallback.

    - `use_worker_fallback` when True will call the remote worker to fetch TLS if local probe fails.
    - `worker_probe_url` if provided will be used as the URL passed to the worker; otherwise `https://{host}` is used.
    """
    key = f"{host}:{port}"
    if key in _tls_cache:
        return _tls_cache[key]

    lock = _tls_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _tls_locks[key] = lock

    async with lock:
        if key in _tls_cache:
            return _tls_cache[key]
        # Try local probe
        tls = ""
        try:
            tls = await _probe_tls_local(host, port=port, timeout=probe_timeout)
        except Exception:
            tls = ""

        if tls:
            _tls_cache[key] = tls
            return tls

        if use_worker_fallback:
            try:
                url = worker_probe_url or f"https://{host}"
                tls_worker = await _fetch_tls_via_worker(url)
                if tls_worker:
                    _tls_cache[key] = tls_worker
                    return tls_worker
            except Exception:
                pass

        _tls_cache[key] = ""
        return ""


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
    tls: str = "",
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
        tls=tls,
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
        
        # Nếu lấy được JSON hợp lệ từ Worker, trả nguyên dict (giữ fields như tls_version)
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
    tls_value = ""
    try:
        if isinstance(worker_result, dict):
            tls_value = str(worker_result.get("tls_version") or worker_result.get("tls") or "")
    except Exception:
        tls_value = ""

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
            tls=tls_value,
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
            tls=tls_value,
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
            tls=tls_value,
        )
    # Worker thấy site ALIVE (ví dụ HTTP 200) nhưng local probe fail trước đó.
    # Nếu DNS local là sinkhole so với public -> thực sự bị chặn (BLOCKED).
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
                tls=tls_value,
            )
    except Exception:
        # Nếu có lỗi khi kiểm tra DNS, fallback sang logic thận trọng bên dưới
        pass

    # Mặc định: worker truy cập được nhưng local probe thất bại có thể là lỗi mạng cục bộ
    # Tránh kết luận BLOCKED sai; đánh dấu LEAKED (cần kiểm tra thủ công nếu cần chắc chắn).
    return _build_worker_row(
        original_label,
        STATUS_LEAKED,
        f"Local probe thất bại nhưng đối chứng HTTP {proxy_status} — khả năng lỗi mạng cục bộ/tạm thời → LEAKED",
        proxy_final_url=proxy_final_url,
        proxy_http_status=proxy_status,
        local_rcode=local_rcode,
        local_ips=local_ips,
        dns_column_suffix=dns_column_suffix,
        tls=tls_value,
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
    *,
    dns_column_suffix: str = "",
    tls: str = "",
) -> dict[str, str]:
    http_code = str(status_code)
    kind = analyze_http_status(status_code)
    if kind == "SERVER_DEAD":
        return build_live_row_dict(
            original_label,
            STATUS_DEAD,
            f"Máy chủ / origin lỗi (HTTP {status_code}) — Cloudflare hoặc upstream sập / không tới được origin",
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
            tls=tls,
        )
    if kind == "WAF_BLOCK":
        return build_live_row_dict(
            original_label,
            STATUS_LEAKED,
            f"Bị tường lửa / WAF chặn probe (HTTP {status_code})",
            final_url,
            http_code,
            redirect_chain,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
            tls=tls,
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
        tls=tls,
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
            tls_val = ""
            try:
                tls_val = await _get_tls_cached(host, 443, probe_timeout=1.0, use_worker_fallback=True, worker_probe_url=f"https://{host}")
            except Exception:
                tls_val = ""
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
                tls=tls_val,
            )

        # TIMEOUT và không có bản ghi A/AAAA từ public -> coi là DEAD.
        if not public_ips and _public_rcode == "TIMEOUT":
            tls_val = ""
            try:
                tls_val = await _get_tls_cached(host, 443, probe_timeout=1.0, use_worker_fallback=True, worker_probe_url=f"https://{host}")
            except Exception:
                tls_val = ""
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
                tls=tls_val,
            )

        public_has_record_hint = bool(public_ips)
        if local_rcode == "NXDOMAIN" and public_has_record_hint:
            tls_val = ""
            try:
                tls_val = await _get_tls_cached(host, 443, probe_timeout=1.0, use_worker_fallback=True, worker_probe_url=f"https://{host}")
            except Exception:
                tls_val = ""
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
                tls=tls_val,
            )

        if detect_dns_sinkhole(local_ips, public_ips):
            tls_val = ""
            try:
                tls_val = await _get_tls_cached(host, 443, probe_timeout=1.0, use_worker_fallback=True, worker_probe_url=f"https://{host}")
            except Exception:
                tls_val = ""
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
                tls=tls_val,
            )

    # Retry + backoff chỉ ở đây; send_live_request(..., retries=0) tránh chồng với retry trong http_fetch.
    for url in urls:
        for attempt in range(retries + 1):
            try:
                status_code, final_url, history_urls, redirect_chain, _response_text = await send_live_request(
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

                tls_val = ""
                try:
                    if str(final_url).lower().startswith("https://"):
                        tls_val = await _get_tls_cached(host, 443, probe_timeout=min(1.5, float(timeout)), use_worker_fallback=False)
                except Exception:
                    tls_val = ""

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
                    tls=tls_val,
                )
            except Exception:
                if attempt < retries:
                    await asyncio.sleep(backoff_base * (2**attempt))
                    continue

                # IP trực tiếp: không có SNI/ECH -> probe cả 443 và 80,
                # kết luận dựa vào kết nối TCP local thay vì dựa vào Worker.
                if is_ip_target:
                    tcp_443 = await probe_tcp(host, port=443, timeout=float(timeout))
                    tcp_80 = await probe_tcp(host, port=80, timeout=float(timeout))
                    tcp_ok = tcp_443 or tcp_80

                    if not tcp_ok:
                        tls_val = ""
                        try:
                            tls_val = await _get_tls_cached(host, 443, probe_timeout=1.0, use_worker_fallback=True, worker_probe_url=url)
                        except Exception:
                            tls_val = ""
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
                            tls=tls_val,
                        )

                    port_ok = 443 if tcp_443 else 80
                    tls_val = ""
                    if port_ok == 443:
                        try:
                            tls_val = await _get_tls_cached(host, 443, probe_timeout=min(1.5, float(timeout)), use_worker_fallback=False)
                        except Exception:
                            tls_val = ""
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
                        tls=tls_val,
                    )

                # Local HTTP fail hết retry → kiểm tra ECH để quyết định BLOCKED vs verify with Worker
                ech = await has_ech_record(host)
                if not ech:
                    # Không có ECH → BLOCKED
                    tls_val = ""
                    try:
                        tls_val = await _get_tls_cached(host, 443, probe_timeout=1.0, use_worker_fallback=True, worker_probe_url=url)
                    except Exception:
                        tls_val = ""
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
                        tls=tls_val,
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
                tls_val = ""
                try:
                    tls_val = str(wr.get("tls_version") or wr.get("tls") or "")
                except Exception:
                    tls_val = ""

                # Fallbacks if worker didn't provide TLS info:
                # 1) local probe to the host
                if not tls_val:
                    try:
                        tls_val = await _get_tls_cached(host, 443, probe_timeout=min(1.5, float(timeout)), use_worker_fallback=False)
                    except Exception:
                        tls_val = ""

                # 2) try probing public IPs directly with SNI set to host
                if not tls_val and public_ips:
                    for ip in public_ips:
                        try:
                            t = await _probe_tls_local(ip, port=443, timeout=1.0, server_hostname=host)
                            if t:
                                tls_val = t
                                break
                        except Exception:
                            continue

                # 3) final attempt: ask worker specifically (longer timeout) via cached helper
                if not tls_val:
                    try:
                        tls_val = await _get_tls_cached(host, 443, probe_timeout=3.0, use_worker_fallback=True, worker_probe_url=url)
                    except Exception:
                        tls_val = ""

                # If worker returned an error but didn't include tls info, attempt local probe
                # and finally call worker as a dedicated fallback to fetch tls_version.
                if not tls_val:
                    try:
                        # local probe first (fast)
                        tls_val = await _get_tls_cached(host, 443, probe_timeout=1.5, use_worker_fallback=False)
                    except Exception:
                        tls_val = ""
                if not tls_val:
                    try:
                        tls_val = await _get_tls_cached(host, 443, probe_timeout=2.0, use_worker_fallback=True, worker_probe_url=url)
                    except Exception:
                        tls_val = ""
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
                    tls=tls_val,
                )
