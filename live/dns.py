"""DNS — resolve A/AAAA, Bước 1 (retry, chốt BLOCKED/DEAD, nghi vấn)."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Literal

import aiodns
from curl_cffi.requests import AsyncSession

from .browser_profiles import BrowserProfile
from .constants import DNS_QUERY_ATTEMPTS, DNS_RETRY_BACKOFF_SECONDS
from .doh import resolve_doh_a_aaaa
from .probe_config import curl_impersonate, curl_probe_kwargs

def _normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if not ip:
        return ""
    try:
        return ipaddress.ip_address(ip).compressed
    except ValueError:
        return ip


def _map_dns_exception(ex: Exception) -> str:
    if isinstance(ex, asyncio.TimeoutError):
        return "TIMEOUT"

    if isinstance(ex, aiodns.error.DNSError):
        code = ex.args[0] if ex.args else None
        if code in (1, 4):
            return "TIMEOUT"
        if code in (11,):
            return "NXDOMAIN"
        return "DNS_ERROR"

    return "DNS_ERROR"


async def resolve_a_records(
    domain: str,
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    prefer_os_getaddrinfo: bool = False,
) -> tuple[str, list[str]]:
    # Mặc định chỉ query qua resolver (aiodns) — không dùng getaddrinfo của OS.
    if prefer_os_getaddrinfo:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(loop.getaddrinfo(domain, None, family=socket.AF_INET), timeout=dns_timeout)
            ips = sorted({_normalize_ip(info[4][0]) for info in infos if info and len(info) >= 5 and info[4][0]})
            ips = [x for x in ips if x]
            if ips:
                return ("NOERROR", ips)
        except Exception:
            pass

    try:
        answers = await asyncio.wait_for(resolver.query(domain, "A"), timeout=dns_timeout)
        ips = sorted({_normalize_ip(getattr(item, "host", "")) for item in answers if getattr(item, "host", "")})
        ips = [x for x in ips if x]
        if ips:
            return ("NOERROR", ips)
        return ("NOERROR", [])
    except Exception as ex:
        return (_map_dns_exception(ex), [])


async def resolve_aaaa_records(
    domain: str,
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    prefer_os_getaddrinfo: bool = False,
) -> tuple[str, list[str]]:
    if prefer_os_getaddrinfo:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(loop.getaddrinfo(domain, None, family=socket.AF_INET6), timeout=dns_timeout)
            ips = sorted({_normalize_ip(info[4][0]) for info in infos if info and len(info) >= 5 and info[4][0]})
            ips = [x for x in ips if x]
            if ips:
                return ("NOERROR", ips)
        except Exception:
            pass

    try:
        answers = await asyncio.wait_for(resolver.query(domain, "AAAA"), timeout=dns_timeout)
        ips = sorted({_normalize_ip(getattr(item, "host", "")) for item in answers if getattr(item, "host", "")})
        ips = [x for x in ips if x]
        if ips:
            return ("NOERROR", ips)
        return ("NOERROR", [])
    except Exception as ex:
        return (_map_dns_exception(ex), [])


def _merge_dns_rcode_no_ips(ra: str, r6: str) -> str:
    if ra == "NXDOMAIN" and r6 == "NXDOMAIN":
        return "NXDOMAIN"
    if ra == "NXDOMAIN" and r6 not in ("NXDOMAIN", "NOERROR"):
        return r6
    if r6 == "NXDOMAIN" and ra not in ("NXDOMAIN", "NOERROR"):
        return ra
    if ra in ("TIMEOUT", "DNS_ERROR") or r6 in ("TIMEOUT", "DNS_ERROR"):
        return ra if ra in ("TIMEOUT", "DNS_ERROR") else r6
    return ra if ra != "NOERROR" else r6


_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_junk_sinkhole_ip(ip: str) -> bool:
    # 0/127/RFC1918/::1 — so với public
    n = _normalize_ip(ip)
    if not n:
        return False
    if n in ("0.0.0.0", "::", "::1"):
        return True
    try:
        a = ipaddress.ip_address(n)
        if a.version == 4:
            if a == ipaddress.ip_address("0.0.0.0") or a in ipaddress.ip_network("127.0.0.0/8"):
                return True
            return any(a in net for net in _RFC1918_NETS)
        return a == ipaddress.ip_address("::1")
    except ValueError:
        return False


async def resolve_a_and_aaaa_with_rcodes(
    domain: str,
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    prefer_os_getaddrinfo: bool = False,
) -> tuple[str, list[str], str, str]:
    (ra, ia), (r6, i6) = await asyncio.gather(
        resolve_a_records(domain, resolver, dns_timeout, prefer_os_getaddrinfo=prefer_os_getaddrinfo),
        resolve_aaaa_records(domain, resolver, dns_timeout, prefer_os_getaddrinfo=prefer_os_getaddrinfo),
    )
    merged = sorted(set(ia + i6))
    if merged:
        return ("NOERROR", merged, ra, r6)
    if ra == "NXDOMAIN" or r6 == "NXDOMAIN":
        return ("NXDOMAIN", [], ra, r6)
    return (_merge_dns_rcode_no_ips(ra, r6), [], ra, r6)


async def resolve_a_and_aaaa_with_retries(
    domain: str,
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    max_attempts: int = DNS_QUERY_ATTEMPTS,
    backoff_seconds: float = DNS_RETRY_BACKOFF_SECONDS,
    prefer_os_getaddrinfo: bool = False,
) -> tuple[str, list[str], str, str]:
    """Query A+AAAA; retry khi TIMEOUT/DNS_ERROR (mạng chập chờn)."""
    attempts = max(1, int(max_attempts))
    last: tuple[str, list[str], str, str] = ("DNS_ERROR", [], "DNS_ERROR", "DNS_ERROR")
    for attempt in range(attempts):
        last = await resolve_a_and_aaaa_with_rcodes(
            domain,
            resolver,
            dns_timeout,
            prefer_os_getaddrinfo=prefer_os_getaddrinfo,
        )
        rcode, ips, _ra, _r6 = last
        if ips:
            return last
        if rcode not in ("TIMEOUT", "DNS_ERROR"):
            return last
        if attempt < attempts - 1:
            await asyncio.sleep(backoff_seconds * (2**attempt))
    return last


async def resolve_a_and_aaaa(
    domain: str,
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    prefer_os_getaddrinfo: bool = False,
) -> tuple[str, list[str]]:
    rcode, ips, _ra, _r6 = await resolve_a_and_aaaa_with_rcodes(
        domain, resolver, dns_timeout, prefer_os_getaddrinfo=prefer_os_getaddrinfo
    )
    return rcode, ips


async def resolve_dns_step1_parallel(
    host: str,
    local_resolver: aiodns.DNSResolver,
    public_resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    max_attempts: int = DNS_QUERY_ATTEMPTS,
) -> tuple[str, list[str], str, list[str]]:
    """
    Bước 1: local + public song song; mỗi bên query A+AAAA (có retry).
    Trả (local_rcode, local_ips, public_rcode, public_ips).
    """
    (local_rcode, local_ips, _ra_l, _r6_l), (public_rcode, public_ips, _ra_p, _r6_p) = await asyncio.gather(
        resolve_a_and_aaaa_with_retries(
            host, local_resolver, dns_timeout, max_attempts=max_attempts
        ),
        resolve_a_and_aaaa_with_retries(
            host, public_resolver, dns_timeout, max_attempts=max_attempts
        ),
    )
    return local_rcode, local_ips, public_rcode, public_ips


async def resolve_doh_step1_parallel(
    host: str,
    dns_timeout: int,
) -> tuple[str, list[str], str, list[str]]:
    """Google DoH + Cloudflare DoH song song (Bước 1 — bằng chứng OONI)."""
    (google_rcode, google_ips), (cf_rcode, cf_ips) = await asyncio.gather(
        resolve_doh_a_aaaa(host, "google", dns_timeout),
        resolve_doh_a_aaaa(host, "cloudflare", dns_timeout),
    )
    return google_rcode, google_ips, cf_rcode, cf_ips


async def resolve_ns_records(domain: str, resolver: aiodns.DNSResolver, dns_timeout: int) -> list[str]:
    try:
        answers = await asyncio.wait_for(resolver.query(domain, "NS"), timeout=dns_timeout)
        return sorted({getattr(item, "host", "").lower() for item in answers if getattr(item, "host", "")})
    except Exception:
        return []


def detect_dns_sinkhole(local_ips: list[str], public_ips: list[str]) -> bool:
    if not public_ips:
        return False

    local_set = {_normalize_ip(x) for x in local_ips if x}
    public_set = {_normalize_ip(x) for x in public_ips if x}
    has_public_real = any(not _is_junk_sinkhole_ip(ip) for ip in public_set)
    local_is_sinkhole = bool(local_set) and all(_is_junk_sinkhole_ip(ip) for ip in local_set)
    return has_public_real and local_is_sinkhole


def public_has_real_ips(public_ips: list[str]) -> bool:
    return any(not _is_junk_sinkhole_ip(ip) for ip in public_ips if ip)


def local_has_real_ips(local_ips: list[str]) -> bool:
    return any(not _is_junk_sinkhole_ip(ip) for ip in local_ips if ip)


def real_ips_from_list(ips: list[str]) -> list[str]:
    out = [_normalize_ip(ip) for ip in ips if ip and not _is_junk_sinkhole_ip(ip)]
    return sorted(set(x for x in out if x))


def prefer_ipv4_first(ips: list[str]) -> list[str]:
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).version == 4:
                v4.append(ip)
            else:
                v6.append(ip)
        except ValueError:
            continue
    return sorted(v4) + sorted(v6)


_DNS_SUSPICION_SUFFIX = " | Nghi vấn DNS (local TIMEOUT/DNS_ERROR)"
_DNS_TIMEOUT_CONTINUE_SUFFIX = " | Nghi vấn DNS (TIMEOUT/DNS_ERROR — tiếp HTTP/Playwright)"


def _both_authoritative_nxdomain(
    local_rcode: str,
    public_rcode: str,
    local_real: list[str],
    public_real: list[str],
) -> bool:
    """Chỉ chốt Dead sớm khi cả hai resolver khẳng định NXDOMAIN và không có IP."""
    if local_real or public_real:
        return False
    return local_rcode == "NXDOMAIN" and public_rcode == "NXDOMAIN"


def _dns_timeout_or_error(rcode: str) -> bool:
    return (rcode or "").strip() in ("TIMEOUT", "DNS_ERROR")


def _both_dns_timeout_or_error_no_ips(
    local_rcode: str,
    public_rcode: str,
    local_real: list[str],
    public_real: list[str],
) -> bool:
    """Cả hai resolver TIMEOUT/DNS_ERROR và không có IP thật — domain chết trên Internet."""
    if local_real or public_real:
        return False
    return _dns_timeout_or_error(local_rcode) and _dns_timeout_or_error(public_rcode)


def _continue_without_ips(
    local_rcode: str,
    public_rcode: str,
    *,
    public_real: list[str] | None = None,
) -> DnsStep1Decision:
    """Không có IP — nhưng không chốt Dead (trừ cả hai NXDOMAIN); thử HTTP/Playwright."""
    pub = list(public_real or [])
    suspicion = _dns_timeout_or_error(local_rcode) or _dns_timeout_or_error(public_rcode)
    suffix = _DNS_TIMEOUT_CONTINUE_SUFFIX if suspicion else ""
    note = (
        f"DNS không có IP (local={local_rcode}, public={public_rcode}) — "
        "không chốt Dead sớm, thử HTTP/Playwright"
    )
    if pub:
        probe = prefer_ipv4_first(pub)
        note = (
            f"Nghi vấn DNS: local={local_rcode}, public={public_rcode} — "
            f"probe Bước 2 qua IP public ({', '.join(probe[:4])})"
        )
        return DnsStep1Decision(
            outcome="continue",
            probe_ips=probe,
            dns_column_suffix=suffix or _DNS_SUSPICION_SUFFIX,
            dns_suspicion=True,
            trace_note=note,
        )
    return DnsStep1Decision(
        outcome="continue",
        probe_ips=[],
        dns_column_suffix=suffix,
        dns_suspicion=suspicion,
        trace_note=note,
    )


@dataclass(frozen=True)
class DnsStep1Decision:
    outcome: Literal["blocked", "dead", "continue"]
    probe_ips: list[str]
    dns_column_suffix: str = ""
    dns_suspicion: bool = False
    trace_note: str = ""


def evaluate_dns_step1(
    local_rcode: str,
    local_ips: list[str],
    public_rcode: str,
    public_ips: list[str],
) -> DnsStep1Decision:
    """
    Luồng Bước 1 sau khi resolve (đã retry):
    - blocked: sinkhole NXDOMAIN / IP rác + public có IP thật
    - dead: cả local lẫn public NXDOMAIN; hoặc cả hai TIMEOUT/DNS_ERROR không IP
    - continue: có IP, nghi vấm TIMEOUT, hoặc DNS mơ hồ → Bước 2/3
    """
    local_rcode = (local_rcode or "").strip() or "—"
    public_rcode = (public_rcode or "").strip() or "—"
    local_real = real_ips_from_list(local_ips)
    public_real = real_ips_from_list(public_ips)

    if _both_authoritative_nxdomain(local_rcode, public_rcode, local_real, public_real):
        return DnsStep1Decision(outcome="dead", probe_ips=[])

    if not local_real and not public_real:
        if _both_dns_timeout_or_error_no_ips(local_rcode, public_rcode, local_real, public_real):
            return DnsStep1Decision(
                outcome="dead",
                probe_ips=[],
                trace_note=(
                    f"DNS không có IP thật (local={local_rcode}, public={public_rcode}) — "
                    "cả hai TIMEOUT/DNS_ERROR, chốt Dead sớm"
                ),
            )
        return _continue_without_ips(local_rcode, public_rcode, public_real=public_real)

    if public_real and _dns_timeout_or_error(local_rcode) and not local_real:
        probe = prefer_ipv4_first(public_real)
        note = (
            f"Nghi vấn DNS: local={local_rcode}, public=NOERROR — "
            f"probe Bước 2 qua IP public ({', '.join(probe[:4])})"
        )
        return DnsStep1Decision(
            outcome="continue",
            probe_ips=probe,
            dns_column_suffix=_DNS_SUSPICION_SUFFIX,
            dns_suspicion=True,
            trace_note=note,
        )

    if public_real and _local_dns_sinkhole_block(local_rcode, local_ips, local_real):
        return DnsStep1Decision(outcome="blocked", probe_ips=[])

    if local_real:
        return DnsStep1Decision(
            outcome="continue",
            probe_ips=prefer_ipv4_first(local_real),
        )

    if public_real:
        return DnsStep1Decision(
            outcome="continue",
            probe_ips=prefer_ipv4_first(public_real),
            trace_note="Local không có IP thật — probe Bước 2 qua IP public",
        )

    return _continue_without_ips(local_rcode, public_rcode, public_real=public_real)


def _local_dns_sinkhole_block(
    local_rcode: str,
    local_ips: list[str],
    local_real: list[str],
) -> bool:
    """Local NXDOMAIN, IP rác, hoặc NOERROR rỗng — nhà mạng chặn/sinkhole."""
    if local_rcode == "NXDOMAIN":
        return True
    if local_ips and not local_real:
        return True
    if not local_ips and local_rcode == "NOERROR":
        return True
    return False


def isp_dns_blocks_resolution(
    local_ips: list[str],
    public_ips: list[str],
    *,
    local_rcode: str = "",
) -> bool:
    """Sinkhole DNS (không gồm TIMEOUT/DNS_ERROR — đó là nghi vấn, đi Bước 2)."""
    if not public_has_real_ips(public_ips):
        return False
    rc = (local_rcode or "").strip()
    if rc in ("TIMEOUT", "DNS_ERROR"):
        return False
    if not rc:
        rc = "NXDOMAIN" if not local_ips else "NOERROR"
    return _local_dns_sinkhole_block(rc, local_ips, real_ips_from_list(local_ips))


def detect_dns_sparse_local(local_ips: list[str], public_ips: list[str]) -> bool:
    # gợi ý: local 1 IP, public ≥2
    local_set = {_normalize_ip(x) for x in local_ips if x}
    public_set = {_normalize_ip(x) for x in public_ips if x}
    return len(local_set) == 1 and len(public_set) >= 2


async def detect_public_ip_async(timeout: int = 5) -> str:
    try:
        od = aiodns.DNSResolver(nameservers=["208.67.222.222"], timeout=timeout, tries=1)
        answers = await asyncio.wait_for(od.query("myip.opendns.com", "A"), timeout=timeout)
        ips = [getattr(a, "host", "") for a in answers if getattr(a, "host", "")]
        if ips:
            return ips[0]
    except Exception:
        pass

    try:
        async with AsyncSession(impersonate=curl_impersonate()) as session:
            r = await session.get(
                "https://api.ipify.org",
                **curl_probe_kwargs(timeout=timeout),
            )
            if r.status_code < 400:
                return (r.text or "").strip()
    except Exception:
        pass

    return "Không xác định"


async def run_network_preflight(
    dns_servers: list[str],
    dns_timeout: int,
    timeout: int,
    *,
    local_dns_servers: list[str] | None = None,
) -> dict[str, str]:
    diagnostics = {
        "local_dns": "FAIL",
        "public_dns": "FAIL",
        "http": "FAIL",
    }

    local_ns = local_dns_servers or []
    if local_ns:
        try:
            local_resolver = aiodns.DNSResolver(nameservers=local_ns, timeout=dns_timeout, tries=1)
            answers = await asyncio.wait_for(local_resolver.query("example.com", "A"), timeout=dns_timeout)
            diagnostics["local_dns"] = "OK" if answers else "FAIL"
        except Exception:
            diagnostics["local_dns"] = "FAIL"
    else:
        diagnostics["local_dns"] = "SKIP (chưa cấu hình DNS nhà mạng)"

    try:
        public_resolver = aiodns.DNSResolver(nameservers=dns_servers, timeout=dns_timeout, tries=1)
        answers = await asyncio.wait_for(public_resolver.query("example.com", "A"), timeout=dns_timeout)
        diagnostics["public_dns"] = "OK" if answers else "FAIL"
    except Exception:
        diagnostics["public_dns"] = "FAIL"

    try:
        async with AsyncSession(impersonate=curl_impersonate()) as session:
            r = await session.get(
                "https://example.com",
                **curl_probe_kwargs(timeout=timeout),
            )
            diagnostics["http"] = "OK" if r.status_code < 500 else f"HTTP_{r.status_code}"
    except Exception:
        diagnostics["http"] = "FAIL"

    return diagnostics


async def resolve_probe_ips(
    host: str,
    local_ips: list[str],
    profile: BrowserProfile,
    dns_timeout: int,
) -> tuple[list[str], str]:
    """
    IP dùng cho TCP/TLS/HTTP probe theo profile trình duyệt.
    Edge (DoH): resolve qua Secure DNS; Cốc Cốc: dùng IP từ DNS ISP.
    """
    if profile.probe_dns_mode != "doh" or not profile.doh_provider:
        return list(local_ips), ""

    _rcode, doh_ips = await resolve_doh_a_aaaa(host, profile.doh_provider, dns_timeout)
    if doh_ips:
        return doh_ips, f" | probe {profile.doh_label}"
    return list(local_ips), ""


async def resolve_doh_ips_if_needed(
    host: str,
    profile: BrowserProfile,
    dns_timeout: int,
) -> tuple[list[str], str]:
    """Chỉ DoH — khi ISP DNS chặn nhưng trình duyệt bật Secure DNS."""
    if profile.probe_dns_mode != "doh" or not profile.doh_provider:
        return [], ""
    _rcode, ips = await resolve_doh_a_aaaa(host, profile.doh_provider, dns_timeout)
    if ips:
        return ips, f" | probe {profile.doh_label} (bypass ISP DNS)"
    return [], ""

