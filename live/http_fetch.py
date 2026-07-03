import asyncio
import ipaddress
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

from .constants import (
    BACKOFF_BASE_SECONDS,
    HTTP_RETRIES,
    MAX_HTTP_REDIRECTS,
    REDIRECT_STATUS_CODES,
)
from .probe_config import curl_probe_kwargs
from .http_models import HttpProbeResult, RedirectHop


def extract_host_and_urls(raw_target: str) -> tuple[str, list[str]]:
    original = raw_target.strip().lstrip("\ufeff")
    if not original:
        return "", []

    if "://" in original:
        parsed = urlsplit(original)
        host = parsed.hostname or ""
        urls = [original]
    else:
        parsed = urlsplit(f"//{original}")
        host = parsed.hostname or parsed.netloc or ""
        urls = [f"https://{original}", f"http://{original}"]

    return host.strip().rstrip("."), urls


def _request_headers() -> dict[str, str]:
    from .probe_config import probe_request_headers

    return probe_request_headers()


def _header_get(headers: object, name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if callable(getter):
        val = getter(name) or getter(name.lower()) or getter(name.title()) or ""
        return str(val).strip()
    return ""


def is_cloudflare_server(server_header: str) -> bool:
    return "cloudflare" in (server_header or "").lower()


def build_curl_resolve_options(host: str, connect_ips: list[str]) -> Optional[dict]:
    """CURLOPT_RESOLVE — ép curl kết nối tới IP đã biết (Bước 1 nghi vấn / probe IP)."""
    if not host or not connect_ips:
        return None
    try:
        from curl_cffi import CurlOpt
    except ImportError:
        return None

    entries: list[str] = []
    for raw in connect_ips[:8]:
        ip = (raw or "").strip()
        if not ip:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 6:
            bracket = addr.compressed
            entries.append(f"{host}:443:[{bracket}]")
            entries.append(f"{host}:80:[{bracket}]")
        else:
            entries.append(f"{host}:443:{addr.compressed}")
            entries.append(f"{host}:80:{addr.compressed}")
    if not entries:
        return None
    return {CurlOpt.RESOLVE: entries}


async def _curl_single_hop(
    session: AsyncSession,
    url: str,
    *,
    timeout: int,
    proxy_url: Optional[str],
    http_version: Any = None,
    curl_options: Optional[dict] = None,
) -> tuple[int, str, str, str, str, int, float]:
    """Một hop HTTP, không auto-follow redirect."""
    kwargs = curl_probe_kwargs(timeout=timeout, proxy_url=proxy_url)
    if http_version is not None:
        kwargs["http_version"] = http_version
    if curl_options:
        kwargs["curl_options"] = curl_options
    response = await session.get(url, **kwargs)
    body = response.text if response.text is not None else ""
    location = _header_get(response.headers, "Location")
    server = _header_get(response.headers, "Server")
    retry_after = _header_get(response.headers, "Retry-After")
    http_ver = int(getattr(response, "http_version", 0) or 0)
    elapsed = getattr(response, "elapsed", None)
    latency_ms = elapsed.total_seconds() * 1000.0 if elapsed is not None else 0.0
    return response.status_code, str(response.url), location, server, body, http_ver, latency_ms, retry_after


async def probe_http_manual_redirect(
    session: AsyncSession,
    url: str,
    *,
    timeout: int,
    proxy_url: Optional[str] = None,
    max_redirects: int = MAX_HTTP_REDIRECTS,
    via: str = "curl/hop-by-hop",
    http_version: Any = None,
    curl_options: Optional[dict] = None,
) -> HttpProbeResult:
    """
    Theo dõi redirect từng hop: ghi URL, mã 3xx, Location, Server.
    Phát hiện vòng lặp redirect.
    """
    current = url
    seen: set[str] = {url}
    hops: list[RedirectHop] = []
    body = ""
    redirect_loop = False
    total_latency_ms = 0.0
    http_version_code = 0
    retry_after = ""

    for _ in range(max_redirects + 1):
        status, resp_url, location, server, body, hop_ver, hop_ms, hop_retry = await _curl_single_hop(
            session,
            current,
            timeout=timeout,
            proxy_url=proxy_url,
            http_version=http_version,
            curl_options=curl_options,
        )
        total_latency_ms += hop_ms
        if hop_ver > 0:
            http_version_code = hop_ver
        if hop_retry:
            retry_after = hop_retry
        hops.append(RedirectHop(url=current, status=status, location=location, server=server))

        if status in REDIRECT_STATUS_CODES and location:
            next_url = urljoin(current, location)
            if next_url in seen:
                redirect_loop = True
                break
            seen.add(next_url)
            current = next_url
            continue
        current = resp_url or current
        break
    else:
        redirect_loop = True

    first_status = hops[0].status if hops else 0
    final_status = hops[-1].status if hops else 0
    final_server = hops[-1].server if hops else ""
    return HttpProbeResult(
        first_status=first_status,
        final_status=final_status,
        final_url=current,
        hops=hops,
        body=(body or "")[:4096],
        server_header=final_server,
        is_cloudflare=is_cloudflare_server(final_server)
        or any(is_cloudflare_server(h.server) for h in hops),
        redirect_loop=redirect_loop,
        via=via,
        http_version_code=http_version_code,
        latency_ms=total_latency_ms if total_latency_ms > 0 else None,
        retry_after=retry_after,
    )


async def send_live_request_tcp_reference(
    session: AsyncSession,
    url: str,
    timeout: int,
    proxy_url: Optional[str] = None,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
    *,
    connect_host: str = "",
    connect_ips: Optional[list[str]] = None,
) -> HttpProbeResult:
    """Bước 2: HTTP qua TCP (443/80) — không thử QUIC; H3/ECH dành cho bypass."""
    is_https = url.lower().startswith("https://")
    via = "curl/https" if is_https else "curl/http"
    host = (connect_host or "").strip() or urlsplit(url).hostname or ""
    resolve_opts = build_curl_resolve_options(host, list(connect_ips or []))
    errors: list[Exception] = []
    for attempt in range(retries + 1):
        try:
            result = await probe_http_manual_redirect(
                session,
                url,
                timeout=timeout,
                proxy_url=proxy_url,
                via=via,
                curl_options=resolve_opts,
            )
            if result.final_status > 0:
                return result
        except (asyncio.TimeoutError, TimeoutError, RequestsError, OSError, ConnectionError) as ex:
            errors.append(ex)
        if attempt < retries:
            await asyncio.sleep(backoff_base * (2**attempt))
    if errors:
        raise errors[-1]
    raise RuntimeError("HTTP TCP probe failed")
