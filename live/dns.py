import asyncio
import ipaddress
import socket

import aiodns
from curl_cffi.requests import AsyncSession

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
    prefer_os_getaddrinfo: bool = True,
) -> tuple[str, list[str]]:
    # public resolver: luôn query (không getaddrinfo) để khác OS
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
    prefer_os_getaddrinfo: bool = True,
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
    prefer_os_getaddrinfo: bool = True,
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


async def resolve_a_and_aaaa(
    domain: str,
    resolver: aiodns.DNSResolver,
    dns_timeout: int,
    *,
    prefer_os_getaddrinfo: bool = True,
) -> tuple[str, list[str]]:
    rcode, ips, _ra, _r6 = await resolve_a_and_aaaa_with_rcodes(
        domain, resolver, dns_timeout, prefer_os_getaddrinfo=prefer_os_getaddrinfo
    )
    return rcode, ips


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
        async with AsyncSession() as session:
            r = await session.get(
                "https://api.ipify.org",
                timeout=timeout,
                verify=False,
                impersonate="chrome",
            )
            if r.status_code < 400:
                return (r.text or "").strip()
    except Exception:
        pass

    return "Không xác định"


async def run_network_preflight(dns_servers: list[str], dns_timeout: int, timeout: int) -> dict[str, str]:
    diagnostics = {
        "local_dns": "FAIL",
        "public_dns": "FAIL",
        "http": "FAIL",
    }

    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(loop.getaddrinfo("example.com", 443, family=socket.AF_INET), timeout=dns_timeout)
        diagnostics["local_dns"] = "OK" if infos else "FAIL"
    except Exception:
        diagnostics["local_dns"] = "FAIL"

    try:
        public_resolver = aiodns.DNSResolver(nameservers=dns_servers, timeout=dns_timeout, tries=1)
        answers = await asyncio.wait_for(public_resolver.query("example.com", "A"), timeout=dns_timeout)
        diagnostics["public_dns"] = "OK" if answers else "FAIL"
    except Exception:
        diagnostics["public_dns"] = "FAIL"

    try:
        async with AsyncSession() as session:
            r = await session.get(
                "https://example.com",
                timeout=timeout,
                verify=False,
                impersonate="chrome",
            )
            diagnostics["http"] = "OK" if r.status_code < 500 else f"HTTP_{r.status_code}"
    except Exception:
        diagnostics["http"] = "FAIL"

    return diagnostics
