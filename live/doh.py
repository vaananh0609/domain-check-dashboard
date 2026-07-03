"""DNS over HTTPS — mô phỏng Secure DNS của trình duyệt."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import quote

from curl_cffi.requests import AsyncSession

from .probe_config import curl_impersonate


def _extract_ips_google(data: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for ans in data.get("Answer") or []:
        if not isinstance(ans, dict):
            continue
        if int(ans.get("type") or 0) in (1, 28):
            ip = str(ans.get("data") or "").strip()
            if ip:
                out.append(ip)
    return out


def _extract_ips_cloudflare(data: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for ans in data.get("Answer") or []:
        if not isinstance(ans, dict):
            continue
        if int(ans.get("type") or 0) in (1, 28):
            ip = str(ans.get("data") or "").strip()
            if ip:
                out.append(ip)
    return out


async def _fetch_json(url: str, *, headers: dict[str, str], timeout: int) -> dict[str, Any]:
    async with AsyncSession(impersonate=curl_impersonate()) as session:
        response = await asyncio.wait_for(
            session.get(url, headers=headers, timeout=timeout, verify=False),
            timeout=float(timeout) + 2,
        )
        return response.json()


async def resolve_doh_a_aaaa(
    domain: str,
    provider: str,
    timeout: int,
) -> tuple[str, list[str]]:
    """Resolve A + AAAA qua DoH JSON API."""
    domain = (domain or "").strip().rstrip(".")
    if not domain:
        return "NXDOMAIN", []

    ips: list[str] = []
    provider = (provider or "google").strip().lower()

    try:
        if provider == "cloudflare":
            base = "https://cloudflare-dns.com/dns-query"
            headers = {"Accept": "application/dns-json"}
            for rtype in ("A", "AAAA"):
                url = f"{base}?name={quote(domain)}&type={rtype}"
                data = await _fetch_json(url, headers=headers, timeout=timeout)
                ips.extend(_extract_ips_cloudflare(data))
        else:
            for rtype in (1, 28):
                url = f"https://dns.google/resolve?name={quote(domain)}&type={rtype}"
                data = await _fetch_json(url, headers={}, timeout=timeout)
                ips.extend(_extract_ips_google(data))
    except asyncio.TimeoutError:
        return "TIMEOUT", []
    except Exception:
        return "DNS_ERROR", []

    uniq = sorted({ip for ip in ips if ip})
    if uniq:
        return "NOERROR", uniq
    return "NXDOMAIN", []
