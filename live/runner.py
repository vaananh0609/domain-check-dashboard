import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, Optional

import aiodns
import pandas as pd
from curl_cffi.requests import AsyncSession

from .classify import classify_live_domain
from .constants import (
    ASYNC_CONCURRENCY,
    BACKOFF_BASE_SECONDS,
    COL_CHAIN,
    COL_DETAIL,
    COL_DNS,
    COL_FINAL_URL,
    COL_FINAL_VI,
    COL_HTTP,
    COL_TLS,
    COL_ORIGINAL,
    DNS_TIMEOUT_SECONDS,
    HTTP_RETRIES,
    PUBLIC_DNS_SERVERS,
    STATUS_DEAD,
)
from .labels import final_status_vietnamese


def _coerce_target_pairs(items: list[str] | list[tuple[str, str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for item in items:
        if isinstance(item, tuple) and len(item) == 2:
            o, d = str(item[0]).strip().lstrip("\ufeff"), str(item[1]).strip().lstrip("\ufeff")
            if d:
                out.append((o or d, d))
        else:
            s = str(item).strip().lstrip("\ufeff")
            if s:
                out.append((s, s))
    return out


RESULT_DF_COLUMNS = [
    "STT",
    COL_ORIGINAL,
    COL_FINAL_VI,
    COL_HTTP,
    COL_TLS,
    COL_CHAIN,
    COL_FINAL_URL,
    COL_DNS,
    COL_DETAIL,
    "Trạng_Thái",
]

OnRowCallback = Callable[[Dict[str, Any], int, int], Awaitable[None]]


async def run_live_test_from_lines_async(
    lines: list[str] | list[tuple[str, str]],
    timeout: int,
    max_domains: int,
    proxy_url: Optional[str] = None,
    follow_redirects: bool = True,
    concurrency: int = ASYNC_CONCURRENCY,
    dns_timeout: int = DNS_TIMEOUT_SECONDS,
    retries: int = HTTP_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
    public_dns_servers: Optional[list[str]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
    on_row: Optional[OnRowCallback] = None,
) -> tuple[pd.DataFrame, float]:
    target_pairs = _coerce_target_pairs(list(lines))

    if not target_pairs:
        return pd.DataFrame(columns=RESULT_DF_COLUMNS), 0.0

    limited_targets = target_pairs[:max_domains]
    total = len(limited_targets)
    start_time = time.perf_counter()

    if on_progress:
        on_progress(0, total)

    results: dict[int, dict[str, str | int]] = {}
    completed_count = 0
    semaphore = asyncio.Semaphore(concurrency)
    active_public_dns = public_dns_servers or PUBLIC_DNS_SERVERS
    resolver = aiodns.DNSResolver(timeout=dns_timeout, tries=1)
    public_resolver = aiodns.DNSResolver(nameservers=active_public_dns, timeout=dns_timeout, tries=1)

    async with AsyncSession() as session:
        async def process_one(idx: int, original_label: str, domain: str) -> tuple[int, dict[str, str | int]]:
            async with semaphore:
                try:
                    row = await classify_live_domain(
                        domain,
                        original_label,
                        session=session,
                        resolver=resolver,
                        public_resolver=public_resolver,
                        timeout=timeout,
                        proxy_url=proxy_url,
                        follow_redirects=follow_redirects,
                        dns_timeout=dns_timeout,
                        retries=retries,
                        backoff_base=backoff_base,
                    )
                    row["STT"] = idx
                    return idx, row
                except Exception:
                    return idx, {
                        "STT": idx,
                        COL_ORIGINAL: original_label,
                        COL_FINAL_VI: final_status_vietnamese(STATUS_DEAD),
                        COL_HTTP: "",
                        COL_CHAIN: "—",
                        COL_FINAL_URL: "",
                        COL_DNS: "—",
                        COL_DETAIL: "",
                        "Trạng_Thái": STATUS_DEAD,
                    }

        tasks = [
            asyncio.create_task(process_one(idx, orig, dom))
            for idx, (orig, dom) in enumerate(limited_targets, start=1)
        ]

        for task in asyncio.as_completed(tasks):
            idx, row = await task
            results[idx] = row
            completed_count += 1
            if on_row:
                await on_row(row, completed_count, total)
            if on_progress:
                on_progress(completed_count, total)

    if on_progress:
        on_progress(total, total)
    elapsed_seconds = time.perf_counter() - start_time

    sorted_results = [results[i] for i in sorted(results.keys())]
    df = pd.DataFrame(sorted_results)
    df = df.fillna("")
    for c in RESULT_DF_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    df = df[RESULT_DF_COLUMNS]
    return df, elapsed_seconds
