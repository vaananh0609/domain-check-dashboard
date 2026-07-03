# Luồng tuần tự: (1) DNS → (2) HTTP TCP/443 → (3) Playwright (cửa sổ hiển thị).

import asyncio
import time
from typing import Any, Awaitable, Callable, Optional

import aiodns
from curl_cffi.requests import AsyncSession

from .constants import (
    BACKOFF_BASE_SECONDS,
    COL_CHAIN,
    COL_DNS,
    COL_DNS_LOCAL,
    COL_DNS_PUBLIC,
    COL_FINAL_VI,
    COL_HTTP,
    COL_HTTP_VER,
    COL_LATENCY,
    COL_ORIGINAL,
    COL_PLAYWRIGHT_ERR,
    COL_TLS,
    COL_TRACE,
    DNS_TIMEOUT_SECONDS,
    HTTP_RETRIES,
    SOURCE_DNS_A_AAAA,
    SOURCE_HTTP_REFERENCE,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_TIMEOUT,
)
from .dns import (
    detect_dns_sinkhole,
    evaluate_dns_step1,
    prefer_ipv4_first,
    real_ips_from_list,
    resolve_dns_step1_parallel,
    resolve_doh_step1_parallel,
    resolve_probe_ips,
)
from .evidence import LayerEvidence
from .probe_config import active_browser_profile
from .http_fetch import (
    extract_host_and_urls,
    send_live_request_tcp_reference,
)
from .http_models import HttpProbeResult
from .http_status import (
    KIND_CENSORSHIP_BLOCK,
    KIND_CLIENT_DEAD,
    KIND_ISP_REDIRECT_BLOCK,
    KIND_REDIRECT_LOOP,
    KIND_SERVER_DEAD,
    analyze_http_context,
)
from .labels import (
    build_live_row_dict,
    browser_result_source,
    dns_evidence_columns_dict,
)
from .parsing import is_ipv4
from .phase2 import (
    PHASE2_FINAL_TIMEOUT_DETAIL,
    _ips_from_dns_cell,
    _rcode_from_dns_cell,
    merge_phase2_result,
)
from .browser_profiles import get_browser_profile
from .playwright_probe import (
    BrowserProbeResult,
    clamp_browser_timeout_ms,
    probe_url_browser,
)
from .tls_probe import (
    TlsProbeResult,
    format_tls_column,
    format_tls_html,
    probe_tls_on_ips,
    probe_tls_version,
    probe_tcp_both,
    run_layer_trace,
)

VI_STEP_DNS = "Đang DNS…"
VI_STEP_HTTP = "Đang HTTP…"
VI_STEP_BROWSER = "Đang Browser…"
VI_STEP_PHASE2 = "Phase 2 Deep…"

_TLS_DEAD_KINDS = frozenset({"tcp_refused", "cert_expired", "cert_mismatch"})

_TLS_FAIL_LABELS = {
    "sni_reset": "SNI Reset",
    "timeout": "TLS handshake timeout",
    "tcp_refused": "TCP Refused",
    "cert_expired": "Cert Expired",
    "cert_mismatch": "Cert Mismatch",
    "ssl_error": "SSL Error",
}

OnPartialCallback = Callable[[dict[str, Any]], Awaitable[None]]


async def _emit_partial(cb: Optional[OnPartialCallback], row: dict[str, str]) -> None:
    if cb:
        await cb(row)


def _text_implies_timeout(text: str) -> bool:
    low = (text or "").lower()
    return (
        "timeout" in low
        or "timed out" in low
        or "connection closed" in low
        or "err_connection_closed" in low
        or "sni reset" in low
        or "sni_reset" in low
    )


def _status_for_probe_failure(
    *,
    tls_result: Optional[TlsProbeResult] = None,
    fail_text: str = "",
    waf_suspected: bool = False,
) -> str:
    """Chưa chốt Blocked — mọi lỗi probe (SNI reset, connection closed, …) → TIMEOUT."""
    _ = tls_result
    if waf_suspected or _text_implies_timeout(fail_text):
        return STATUS_TIMEOUT
    if tls_result and tls_result.failure_kind in ("timeout", "sni_reset"):
        return STATUS_TIMEOUT
    return STATUS_TIMEOUT


def _status_for_http_kind(kind: str) -> str:
    if kind in (KIND_REDIRECT_LOOP, KIND_SERVER_DEAD, KIND_CLIENT_DEAD):
        return STATUS_DEAD
    if kind in (KIND_CENSORSHIP_BLOCK, KIND_ISP_REDIRECT_BLOCK):
        return STATUS_TIMEOUT
    return STATUS_LEAKED


def _tls_fields(result: Optional[TlsProbeResult]) -> dict[str, str]:
    if not result:
        return {"tls_version": "—", "tls_html": ""}
    return {
        "tls_version": format_tls_column(result),
        "tls_html": format_tls_html(result),
    }


def _dns_trace_summary(rcode: str, ips: list[str]) -> str:
    if ips:
        return f"{rcode} [{', '.join(ips[:3])}]"
    return rcode


def _pub_dns_kw(public_rcode: str, public_ips: list[str]) -> dict[str, Any]:
    return {
        "public_dns_rcode": public_rcode,
        "public_dns_ips": list(public_ips),
    }


def _tcp_probe_ip_list(
    probe_ips: list[str],
    public_ips: list[str],
    local_ips: list[str],
    evidence: LayerEvidence,
) -> list[str]:
    if probe_ips:
        return prefer_ipv4_first(real_ips_from_list(probe_ips))
    for ips in (public_ips, local_ips, evidence.google_doh_ips, evidence.cloudflare_doh_ips):
        real = real_ips_from_list(ips)
        if real:
            return prefer_ipv4_first(real)
    return []


async def _fill_tcp_evidence(
    evidence: LayerEvidence,
    ips: list[str],
    timeout: int,
) -> None:
    if not ips:
        return
    tcp_timeout = min(float(timeout), 8.0)
    evidence.tcp_80, evidence.tcp_443 = await probe_tcp_both(ips, timeout=tcp_timeout)


def _playwright_error_cell(browser: Optional[BrowserProbeResult], fail_text: str = "") -> str:
    raw = (fail_text or "").strip()
    if browser and not raw:
        raw = (browser.error or "").strip()
    if not raw:
        return ""
    return raw[:240]


def _row_dns_partial(
    original_label: str,
    local_rcode: str,
    local_ips: list[str],
    *,
    public_rcode: str,
    public_ips: list[str],
    pending_vi: str,
    dns_column_suffix: str = "",
    dns_preserve_from: Optional[dict[str, Any]] = None,
    **extra: Any,
) -> dict[str, str]:
    return build_live_row_dict(
        original_label,
        STATUS_DEAD,
        "",
        "—",
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
        pending_vi=pending_vi,
        dns_preserve_from=dns_preserve_from,
        **_pub_dns_kw(public_rcode, public_ips),
        **extra,
    )


def _row_dead_both_dns_empty(
    original_label: str,
    local_rcode: str,
    local_ips: list[str],
    *,
    public_rcode: str,
    public_ips: list[str],
    dns_column_suffix: str = "",
    evidence: Optional[LayerEvidence] = None,
) -> dict[str, str]:
    return build_live_row_dict(
        original_label,
        STATUS_DEAD,
        "",
        "—",
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
        evidence=evidence,
        result_source=SOURCE_DNS_A_AAAA,
        **_pub_dns_kw(public_rcode, public_ips),
    )


def _row_probe_timeout(
    original_label: str,
    local_rcode: str,
    local_ips: list[str],
    *,
    public_rcode: str,
    public_ips: list[str],
    dns_column_suffix: str = "",
    trace: str = "",
    http_version: str = "",
    tls_result: Optional[TlsProbeResult] = None,
    evidence: Optional[LayerEvidence] = None,
    playwright_error: str = "",
    dns_preserve_from: Optional[dict[str, Any]] = None,
    result_source: str = "",
) -> dict[str, str]:
    if evidence is not None and playwright_error:
        evidence.playwright_error = playwright_error
    return build_live_row_dict(
        original_label,
        STATUS_TIMEOUT,
        "—",
        "—",
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
        trace=trace,
        http_version=http_version,
        evidence=evidence,
        dns_preserve_from=dns_preserve_from,
        result_source=result_source,
        **_tls_fields(tls_result),
        **_pub_dns_kw(public_rcode, public_ips),
    )


def _probe_http_cols(probe: Optional[HttpProbeResult]) -> dict[str, str]:
    if probe is None:
        return {"http_version": "", "latency": ""}
    return {
        "http_version": probe.http_version_label,
        "latency": probe.latency_label,
    }


async def _probe_http_step2(
    session: AsyncSession,
    urls: list[str],
    *,
    timeout: int,
    proxy_url: Optional[str],
    retries: int,
    backoff_base: float,
    connect_host: str,
    connect_ips: Optional[list[str]] = None,
) -> Optional[HttpProbeResult]:
    """
    Bước 2 — thử từng URL (https rồi http) với retry đầy đủ.
    Chỉ ép IP (CURLOPT_RESOLVE) khi DNS nghi vấn; mặc định để curl resolve bình thường.
    """
    for url in urls:
        try:
            probe = await send_live_request_tcp_reference(
                session,
                url,
                timeout=timeout,
                proxy_url=proxy_url,
                retries=retries,
                backoff_base=backoff_base,
                connect_host=connect_host,
                connect_ips=connect_ips,
            )
            if probe.final_status > 0:
                return probe
        except Exception:
            continue
    return None


def _tls_failure_note(tls_result: TlsProbeResult) -> str:
    if tls_result.error:
        return tls_result.error
    kind = tls_result.failure_kind
    return _TLS_FAIL_LABELS.get(kind, kind or "TLS handshake fail")


def _browser_to_http_probe(browser: BrowserProbeResult) -> HttpProbeResult:
    return HttpProbeResult(
        first_status=browser.final_status,
        final_status=browser.final_status,
        final_url=browser.final_url or browser.document_url,
        via=browser.via,
        http_version_code=0,
        http_version_override=(browser.browser_http_ver or "").strip(),
    )


def _classify_local_http_response(
    original_label: str,
    host: str,
    probe: HttpProbeResult,
    local_rcode: str,
    local_ips: list[str],
    *,
    dns_column_suffix: str = "",
    tls_result: Optional[TlsProbeResult] = None,
    trace: str = "",
    dns_sinkhole: bool = False,
    public_rcode: str = "—",
    public_ips: Optional[list[str]] = None,
    evidence: Optional[LayerEvidence] = None,
    dns_preserve_from: Optional[dict[str, Any]] = None,
    result_source: str = SOURCE_HTTP_REFERENCE,
) -> dict[str, str]:
    """Bước 2: có mã HTTP → LEAKED trừ ngoại lệ ISP."""
    tls_kw = _tls_fields(tls_result)
    probe_kw = _probe_http_cols(probe)
    pub_kw = _pub_dns_kw(public_rcode, public_ips or [])

    kind = analyze_http_context(probe, original_host=host, dns_sinkhole=dns_sinkhole)
    status = _status_for_http_kind(kind)
    return build_live_row_dict(
        original_label,
        status,
        probe.http_display,
        probe.chain_display,
        local_rcode,
        local_ips,
        dns_column_suffix=dns_column_suffix,
        trace=trace,
        evidence=evidence,
        dns_preserve_from=dns_preserve_from,
        result_source=result_source,
        **tls_kw,
        **probe_kw,
        **pub_kw,
    )


async def _probe_tls_sequential(
    host: str,
    probe_ips: list[str],
    *,
    is_ip_target: bool,
    timeout: float,
) -> TlsProbeResult:
    if is_ip_target:
        return await probe_tls_version(host, connect_host=host, timeout=timeout)
    if probe_ips:
        return await probe_tls_on_ips(host, probe_ips, timeout=timeout)
    return TlsProbeResult(
        version="—",
        negotiated="",
        error="",
        attempt_log="",
        cert_status="—",
        issuer="—",
        hostname_match=True,
    )


async def _classify_playwright_step3(
    original_label: str,
    host: str,
    url: str,
    local_rcode: str,
    local_ips: list[str],
    probe_ips: list[str],
    public_ips: list[str],
    *,
    public_rcode: str = "—",
    timeout: int,
    tls_result: Optional[TlsProbeResult] = None,
    is_ip_target: bool = False,
    enable_trace: bool,
    browser_headed: bool = False,
    dns_column_suffix: str = "",
    dns_sinkhole_flag: bool = False,
    dns_step1_trace: str = "",
    session: Optional[AsyncSession] = None,
    proxy_url: Optional[str] = None,
    backoff_base: float = BACKOFF_BASE_SECONDS,
    evidence: Optional[LayerEvidence] = None,
    dns_preserve_from: Optional[dict[str, Any]] = None,
) -> dict[str, str]:
    """Bước 3 — Playwright: chỉ tin mã HTTP document; TLS lấy từ trình duyệt nếu có."""
    trace_text = (dns_step1_trace or "").strip()
    row_dns_kw = {
        "dns_column_suffix": dns_column_suffix,
        "evidence": evidence,
        "dns_preserve_from": dns_preserve_from,
        **_pub_dns_kw(public_rcode, public_ips),
    }
    tls_kw = _tls_fields(tls_result)
    profile = active_browser_profile()
    browser_source = browser_result_source(profile.id)

    if tls_result is not None:
        kind = tls_result.failure_kind
        if kind in _TLS_DEAD_KINDS or tls_result.cert_dead:
            return build_live_row_dict(
                original_label,
                STATUS_DEAD,
                "—",
                "—",
                local_rcode,
                local_ips,
                trace=trace_text,
                result_source=browser_source,
                **row_dns_kw,
                **tls_kw,
            )

    if enable_trace and session is not None:

        async def _http_probe():
            return await send_live_request_tcp_reference(
                session,
                url,
                timeout=timeout,
                proxy_url=proxy_url,
                connect_host=host,
                connect_ips=probe_ips or local_ips or None,
            )

        layer = await run_layer_trace(
            host,
            url,
            probe_ips or local_ips,
            dns_summary=_dns_trace_summary(local_rcode, local_ips),
            timeout=float(timeout),
            http_probe_coro=_http_probe,
        )
        trace_text = layer.format()

    timeout_ms = clamp_browser_timeout_ms(timeout)
    browser_via = profile.playwright_via_label
    try:
        browser = await probe_url_browser(
            url,
            timeout_ms=timeout_ms,
            headless=not browser_headed,
            connect_ips=probe_ips or local_ips,
            profile_id=profile.id,
        )
    except (FileNotFoundError, RuntimeError) as ex:
        note = f"Playwright không khởi chạy: {ex}"
        trace_merged = f"{trace_text} | {note}" if trace_text else note
        return _row_probe_timeout(
            original_label,
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            dns_column_suffix=dns_column_suffix,
            trace=trace_merged,
            http_version=browser_via,
            tls_result=tls_result,
            evidence=evidence,
            playwright_error=note,
            dns_preserve_from=dns_preserve_from,
            result_source=browser_source,
        )

    if browser.final_status > 0:
        if evidence is not None:
            pw_err = _playwright_error_cell(browser)
            if pw_err:
                evidence.playwright_error = pw_err
        probe = _browser_to_http_probe(browser)
        probe_kw = _probe_http_cols(probe)
        effective_tls = browser.browser_tls if browser.browser_tls else tls_result
        note = f"Playwright document HTTP {browser.final_status} ({browser.profile_mode})"
        if browser.browser_tls and browser.browser_tls.ok:
            note += f"; TLS via browser ({browser.browser_tls.version})"
        trace_merged = f"{trace_text} | {note}" if trace_text else note
        return _classify_local_http_response(
            original_label,
            host,
            probe,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
            tls_result=effective_tls,
            trace=trace_merged,
            dns_sinkhole=dns_sinkhole_flag,
            public_rcode=public_rcode,
            public_ips=public_ips,
            evidence=evidence,
            dns_preserve_from=dns_preserve_from,
            result_source=browser_source,
        )

    if tls_result is None:
        tls_result = await _probe_tls_sequential(
            host, probe_ips, is_ip_target=is_ip_target, timeout=float(timeout)
        )
        tls_kw = _tls_fields(tls_result)

    fail = browser.error or _tls_failure_note(tls_result)
    final_status = _status_for_probe_failure(
        tls_result=tls_result,
        fail_text=fail,
        waf_suspected=browser.waf_suspected,
    )
    if browser.waf_suspected:
        detail = "Playwright timeout — không lấy được mã document (test lại sau)"
    else:
        detail = f"HTTP+TLS fail — {fail}; không lấy được mã document (test lại sau)"
    trace_merged = f"{trace_text} | {detail}" if trace_text else detail
    pw_err = _playwright_error_cell(browser, fail)

    return _row_probe_timeout(
        original_label,
        local_rcode,
        local_ips,
        public_rcode=public_rcode,
        public_ips=public_ips,
        dns_column_suffix=dns_column_suffix,
        trace=trace_merged,
        http_version=browser_via,
        tls_result=tls_result,
        evidence=evidence,
        playwright_error=pw_err,
        dns_preserve_from=dns_preserve_from,
        result_source=browser_source,
    )


async def classify_phase2_deep_retry(
    raw_target: str,
    original_label: str,
    phase1_row: dict[str, Any],
    *,
    timeout_seconds: int,
    browser_profile: str,
    on_partial: Optional[OnPartialCallback] = None,
) -> dict[str, str]:
    """
    Phase 2 — chỉ chạy lại Playwright (headed, profile khác, deep scan).
    Giữ cột bằng chứng DNS/TCP từ Phase 1.
    """
    host, urls = extract_host_and_urls(raw_target)
    if not host or not urls:
        return dict(phase1_row)

    local_cell = str(phase1_row.get(COL_DNS_LOCAL) or phase1_row.get(COL_DNS, ""))
    public_cell = str(phase1_row.get(COL_DNS_PUBLIC) or phase1_row.get(COL_DNS, ""))
    local_rcode = _rcode_from_dns_cell(local_cell)
    local_ips = _ips_from_dns_cell(local_cell)
    public_rcode = _rcode_from_dns_cell(public_cell)
    public_ips = _ips_from_dns_cell(public_cell)
    prior_trace = str(phase1_row.get(COL_TRACE, "") or "").strip()
    profile = get_browser_profile(browser_profile)
    browser_via = profile.playwright_via_label
    p2_source = browser_result_source(browser_profile, phase2=True)
    dns_preserve_from = phase1_row

    await _emit_partial(
        on_partial,
        _row_dns_partial(
            original_label,
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            pending_vi=VI_STEP_PHASE2,
            http_version=browser_via,
            dns_preserve_from=dns_preserve_from,
        ),
    )

    timeout_ms = clamp_browser_timeout_ms(timeout_seconds, phase2=True)
    url = urls[0]
    try:
        browser = await probe_url_browser(
            url,
            timeout_ms=timeout_ms,
            headless=False,
            deep_scan=True,
            phase2=True,
            profile_id=browser_profile,
            connect_ips=None,
        )
    except (FileNotFoundError, RuntimeError) as ex:
        note = f"Phase 2 Playwright không khởi chạy ({profile.label}): {ex}"
        trace = f"{prior_trace} | {note}" if prior_trace else note
        phase2_row = _row_probe_timeout(
            original_label,
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            trace=trace,
            http_version=browser_via,
            playwright_error=note,
            dns_preserve_from=dns_preserve_from,
            result_source=p2_source,
        )
        return merge_phase2_result(phase1_row, phase2_row)

    if browser.final_status > 0:
        probe = _browser_to_http_probe(browser)
        effective_tls = browser.browser_tls
        note = (
            f"Phase 2 ({profile.label} headed {timeout_seconds}s): "
            f"HTTP {browser.final_status} ({browser.profile_mode})"
        )
        trace = f"{prior_trace} | {note}" if prior_trace else note
        phase2_row = _classify_local_http_response(
            original_label,
            host,
            probe,
            local_rcode,
            local_ips,
            tls_result=effective_tls,
            trace=trace,
            public_rcode=public_rcode,
            public_ips=public_ips,
            dns_preserve_from=dns_preserve_from,
            result_source=p2_source,
        )
        pw_err = _playwright_error_cell(browser)
        if pw_err:
            phase2_row[COL_PLAYWRIGHT_ERR] = pw_err
        return merge_phase2_result(phase1_row, phase2_row)

    tls_result = browser.browser_tls
    if tls_result is None:
        tls_result = await _probe_tls_sequential(
            host, local_ips, is_ip_target=is_ipv4(host), timeout=float(timeout_seconds)
        )

    fail = browser.error or (tls_result and _tls_failure_note(tls_result)) or "timeout"
    final_status = _status_for_probe_failure(
        tls_result=tls_result,
        fail_text=fail,
        waf_suspected=browser.waf_suspected,
    )
    pw_err = _playwright_error_cell(browser, fail)
    detail = (
        f"Phase 2 ({profile.label} headed {timeout_seconds}s): {PHASE2_FINAL_TIMEOUT_DETAIL}"
        if final_status == STATUS_TIMEOUT
        else f"Phase 2 ({profile.label}): {fail}"
    )
    trace = f"{prior_trace} | {detail}" if prior_trace else detail

    phase2_row = _row_probe_timeout(
        original_label,
        local_rcode,
        local_ips,
        public_rcode=public_rcode,
        public_ips=public_ips,
        trace=trace,
        http_version=browser_via,
        tls_result=tls_result,
        playwright_error=pw_err or PHASE2_FINAL_TIMEOUT_DETAIL,
        dns_preserve_from=dns_preserve_from,
        result_source=p2_source,
    )
    return merge_phase2_result(phase1_row, phase2_row)


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
    enable_trace: bool = False,
    browser_headed: bool = False,
    enable_step3: bool = True,
    on_partial: Optional[OnPartialCallback] = None,
) -> dict[str, str]:
    t0 = time.perf_counter()
    row = await _classify_live_domain_work(
        raw_target,
        original_label,
        session,
        resolver,
        public_resolver,
        timeout,
        proxy_url=proxy_url,
        follow_redirects=follow_redirects,
        dns_timeout=dns_timeout,
        retries=retries,
        backoff_base=backoff_base,
        enable_trace=enable_trace,
        browser_headed=browser_headed,
        enable_step3=enable_step3,
        on_partial=on_partial,
    )
    if not str(row.get(COL_LATENCY, "")).strip() or row.get(COL_LATENCY) == "—":
        row[COL_LATENCY] = f"{int((time.perf_counter() - t0) * 1000)}ms"
    return row


async def _classify_live_domain_work(
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
    enable_trace: bool = False,
    browser_headed: bool = False,
    enable_step3: bool = True,
    on_partial: Optional[OnPartialCallback] = None,
) -> dict[str, str]:
    _ = follow_redirects
    host, urls = extract_host_and_urls(raw_target)
    is_ip_target = is_ipv4(host)
    local_rcode = "—"
    local_ips: list[str] = []
    public_rcode = "—"
    public_ips: list[str] = []

    if not host or not urls:
        return build_live_row_dict(original_label, STATUS_DEAD, "", "—", "N/A", [])

    profile = active_browser_profile()
    probe_ips: list[str] = []
    dns_column_suffix = ""
    dns_step1_trace = ""
    dns_suspicion = False
    evidence = LayerEvidence()
    pub_kw = _pub_dns_kw(public_rcode, public_ips)

    if is_ip_target:
        local_rcode, local_ips = ("NOERROR", [host])
        probe_ips = [host]
        await _fill_tcp_evidence(evidence, [host], timeout)
        await _emit_partial(
            on_partial,
            _row_dns_partial(
                original_label,
                local_rcode,
                local_ips,
                public_rcode=public_rcode,
                public_ips=public_ips,
                pending_vi=VI_STEP_DNS,
            ),
        )
    else:
        await _emit_partial(
            on_partial,
            _row_dns_partial(
                original_label,
                "—",
                [],
                public_rcode="—",
                public_ips=[],
                pending_vi=VI_STEP_DNS,
            ),
        )
        (
            (local_rcode, local_ips, public_rcode, public_ips),
            (google_rcode, google_ips, cf_rcode, cf_ips),
        ) = await asyncio.gather(
            resolve_dns_step1_parallel(host, resolver, public_resolver, dns_timeout),
            resolve_doh_step1_parallel(host, dns_timeout),
        )
        evidence.google_doh_rcode = google_rcode
        evidence.google_doh_ips = list(google_ips)
        evidence.cloudflare_doh_rcode = cf_rcode
        evidence.cloudflare_doh_ips = list(cf_ips)
        pub_kw = _pub_dns_kw(public_rcode, public_ips)

        await _emit_partial(
            on_partial,
            _row_dns_partial(
                original_label,
                local_rcode,
                local_ips,
                public_rcode=public_rcode,
                public_ips=public_ips,
                pending_vi=VI_STEP_HTTP,
                evidence=evidence,
            ),
        )

        step1 = evaluate_dns_step1(local_rcode, local_ips, public_rcode, public_ips)
        dns_step1_trace = step1.trace_note

        if step1.outcome == "dead":
            return _row_dead_both_dns_empty(
                original_label,
                local_rcode,
                local_ips,
                public_rcode=public_rcode,
                public_ips=public_ips,
                dns_column_suffix=step1.dns_column_suffix,
                evidence=evidence,
            )

        if step1.outcome == "blocked":
            dns_column_suffix = step1.dns_column_suffix
            probe_ips = prefer_ipv4_first(real_ips_from_list(public_ips))
            if not probe_ips:
                probe_ips = prefer_ipv4_first(real_ips_from_list(local_ips))
            dns_suspicion = True
            if step1.trace_note:
                dns_step1_trace = (
                    f"{dns_step1_trace} | {step1.trace_note}"
                    if dns_step1_trace
                    else step1.trace_note
                )
        else:
            dns_suspicion = step1.dns_suspicion
            dns_column_suffix = step1.dns_column_suffix
            probe_ips = list(step1.probe_ips)
            if not probe_ips:
                probe_ips = prefer_ipv4_first(real_ips_from_list(local_ips))
            if not probe_ips:
                probe_ips = prefer_ipv4_first(real_ips_from_list(public_ips))

    if not is_ip_target and not probe_ips:
        probe_ips = list(local_ips)

    await _fill_tcp_evidence(
        evidence,
        _tcp_probe_ip_list(probe_ips, public_ips, local_ips, evidence),
        timeout,
    )

    dns_snapshot = dns_evidence_columns_dict(
        local_rcode,
        local_ips,
        public_rcode=public_rcode,
        public_ips=public_ips,
        evidence=evidence,
    )

    dns_sinkhole_flag = False
    if not is_ip_target and public_ips:
        try:
            dns_sinkhole_flag = detect_dns_sinkhole(local_ips, public_ips)
        except Exception:
            dns_sinkhole_flag = False

    primary_url = urls[0]

    # —— Bước 2: HTTP reference (TCP) ——
    await _emit_partial(
        on_partial,
        _row_dns_partial(
            original_label,
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            pending_vi=VI_STEP_HTTP,
            dns_column_suffix=dns_column_suffix,
            evidence=evidence,
            dns_preserve_from=dns_snapshot,
        ),
    )

    curl_connect_ips: Optional[list[str]] = None
    if dns_suspicion and probe_ips and not is_ip_target:
        curl_connect_ips = list(probe_ips)

    http_probe = await _probe_http_step2(
        session,
        urls,
        timeout=timeout,
        proxy_url=proxy_url,
        retries=retries,
        backoff_base=backoff_base,
        connect_host=host,
        connect_ips=curl_connect_ips,
    )

    if http_probe and http_probe.final_status > 0:
        tls_result = await _probe_tls_sequential(
            host, probe_ips, is_ip_target=is_ip_target, timeout=float(timeout)
        )
        return _classify_local_http_response(
            original_label,
            host,
            http_probe,
            local_rcode,
            local_ips,
            dns_column_suffix=dns_column_suffix,
            tls_result=tls_result,
            trace=dns_step1_trace,
            dns_sinkhole=dns_sinkhole_flag,
            public_rcode=public_rcode,
            public_ips=public_ips,
            evidence=evidence,
            dns_preserve_from=dns_snapshot,
        )

    if not enable_step3:
        tls_result = await _probe_tls_sequential(
            host, probe_ips, is_ip_target=is_ip_target, timeout=float(timeout)
        )
        if tls_result and (
            tls_result.failure_kind in _TLS_DEAD_KINDS or tls_result.cert_dead
        ):
            trace_merged = dns_step1_trace
            return build_live_row_dict(
                original_label,
                STATUS_DEAD,
                "—",
                "—",
                local_rcode,
                local_ips,
                dns_column_suffix=dns_column_suffix,
                trace=trace_merged,
                evidence=evidence,
                dns_preserve_from=dns_snapshot,
                result_source=SOURCE_HTTP_REFERENCE,
                **_pub_dns_kw(public_rcode, public_ips),
                **_tls_fields(tls_result),
            )
        note = "HTTP không có mã — Bước 3 Playwright tắt"
        trace_merged = f"{dns_step1_trace} | {note}" if dns_step1_trace else note
        return _row_probe_timeout(
            original_label,
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            dns_column_suffix=dns_column_suffix,
            trace=trace_merged,
            tls_result=tls_result,
            evidence=evidence,
            dns_preserve_from=dns_snapshot,
            result_source=SOURCE_HTTP_REFERENCE,
        )

    # —— Bước 3: Playwright ——
    profile = active_browser_profile()
    browser_via = profile.playwright_via_label
    playwright_ips = list(probe_ips)
    pw_dns_suffix = dns_column_suffix
    if not is_ip_target and not dns_suspicion:
        resolved_ips, suffix = await resolve_probe_ips(
            host, probe_ips or local_ips, profile, dns_timeout
        )
        if resolved_ips:
            playwright_ips = resolved_ips
        if suffix:
            pw_dns_suffix = (dns_column_suffix or "") + suffix

    await _emit_partial(
        on_partial,
        _row_dns_partial(
            original_label,
            local_rcode,
            local_ips,
            public_rcode=public_rcode,
            public_ips=public_ips,
            pending_vi=VI_STEP_BROWSER,
            dns_column_suffix=pw_dns_suffix,
            http_version=browser_via,
            evidence=evidence,
            dns_preserve_from=dns_snapshot,
        ),
    )

    return await _classify_playwright_step3(
        original_label,
        host,
        primary_url,
        local_rcode,
        local_ips,
        playwright_ips,
        public_ips,
        public_rcode=public_rcode,
        timeout=timeout,
        is_ip_target=is_ip_target,
        enable_trace=enable_trace,
        browser_headed=browser_headed,
        dns_column_suffix=pw_dns_suffix,
        dns_sinkhole_flag=dns_sinkhole_flag,
        dns_step1_trace=dns_step1_trace,
        session=session,
        proxy_url=proxy_url,
        backoff_base=backoff_base,
        evidence=evidence,
        dns_preserve_from=dns_snapshot,
    )
