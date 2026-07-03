import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, Optional

import aiodns
import pandas as pd

from .classify import classify_live_domain, classify_phase2_deep_retry
from .constants import (
    ASYNC_CONCURRENCY,
    BACKOFF_BASE_SECONDS,
    COL_CHAIN,
    COL_DNS,
    COL_FINAL_VI,
    COL_RESULT_SOURCE,
    COL_HTTP,
    COL_HTTP_VER,
    COL_LATENCY,
    COL_ORIGINAL,
    COL_PLAYWRIGHT_ERR,
    COL_TCP_443,
    COL_TCP_80,
    COL_TLS,
    COL_TRACE,
    DNS_TIMEOUT_SECONDS,
    HTTP_RETRIES,
    PUBLIC_DNS_SERVERS,
    STATUS_DEAD,
    STATUS_TIMEOUT,
)
from .labels import final_status_vietnamese
from .phase2 import clamp_phase2_timeout_seconds, merge_phase2_result, phase2_browser_profiles
from .probe_config import parse_local_dns_servers
from .probe_session import isolated_probe_process_env, make_probe_session


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
    COL_RESULT_SOURCE,
    COL_DNS,
    COL_TCP_80,
    COL_TCP_443,
    COL_HTTP,
    COL_HTTP_VER,
    COL_TLS,
    COL_CHAIN,
    COL_PLAYWRIGHT_ERR,
    COL_LATENCY,
    COL_TRACE,
    "Trạng_Thái",
]

OnRowCallback = Callable[[Dict[str, Any], int, int], Awaitable[None]]
OnRowPatchCallback = Callable[[Dict[str, Any], int, int], Awaitable[None]]


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
    local_dns_servers: Optional[list[str]] = None,
    enable_trace: bool = False,
    browser_headed: bool = False,
    enable_step3: bool = True,
    browser_profile: str = "edge",
    coccoc_user_data: str = "",
    edge_user_data: str = "",
    chrome_user_data: str = "",
    on_progress: Optional[Callable[[int, int], None]] = None,
    on_row: Optional[OnRowCallback] = None,
    on_row_patch: Optional[OnRowPatchCallback] = None,
    enable_phase2: bool = False,
    phase2_timeout_seconds: int = 60,
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
    active_local_dns = local_dns_servers if local_dns_servers is not None else parse_local_dns_servers(None)
    if active_local_dns:
        resolver = aiodns.DNSResolver(nameservers=active_local_dns, timeout=dns_timeout, tries=1)
    else:
        resolver = aiodns.DNSResolver(timeout=dns_timeout, tries=1)
    public_resolver = aiodns.DNSResolver(nameservers=active_public_dns, timeout=dns_timeout, tries=1)

    with isolated_probe_process_env(
        browser_profile=browser_profile,
        coccoc_user_data=coccoc_user_data,
        edge_user_data=edge_user_data,
        chrome_user_data=chrome_user_data,
    ):
        async with make_probe_session() as session:

            async def process_one(idx: int, original_label: str, domain: str) -> tuple[int, dict[str, str | int]]:
                async with semaphore:

                    async def _on_partial(partial: dict[str, Any]) -> None:
                        partial["STT"] = idx
                        if on_row_patch:
                            await on_row_patch(partial, idx, total)

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
                            enable_trace=enable_trace,
                            browser_headed=browser_headed,
                            enable_step3=enable_step3,
                            on_partial=_on_partial if on_row_patch else None,
                        )
                        row["STT"] = idx
                        return idx, row
                    except Exception:
                        return idx, {
                            "STT": idx,
                            COL_ORIGINAL: original_label,
                            COL_DNS: "—",
                            COL_FINAL_VI: final_status_vietnamese(STATUS_DEAD),
                            COL_RESULT_SOURCE: "—",
                            COL_TCP_80: "—",
                            COL_TCP_443: "—",
                            COL_HTTP: "",
                            COL_HTTP_VER: "—",
                            COL_TLS: "",
                            COL_CHAIN: "—",
                            COL_PLAYWRIGHT_ERR: "—",
                            COL_LATENCY: "—",
                            COL_DNS: "—",
                            COL_TRACE: "",
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

    if enable_phase2 and enable_step3:
        phase2_timeout = clamp_phase2_timeout_seconds(phase2_timeout_seconds)
        p2_profiles = phase2_browser_profiles(browser_profile)
        timeout_indices = sorted(
            idx
            for idx, row in results.items()
            if str(row.get("Trạng_Thái", "")).strip() == STATUS_TIMEOUT
        )

        for idx in timeout_indices:
            phase1_row = results[idx]
            _orig, domain = limited_targets[idx - 1]
            final_row = dict(phase1_row)

            for p2_profile in p2_profiles:

                async def _on_phase2_partial(
                    partial: dict[str, Any], *, _stt: int = idx
                ) -> None:
                    partial["STT"] = _stt
                    if on_row_patch:
                        await on_row_patch(partial, _stt, total)

                try:
                    with isolated_probe_process_env(
                        browser_profile=p2_profile,
                        coccoc_user_data=coccoc_user_data,
                        edge_user_data=edge_user_data,
                        chrome_user_data=chrome_user_data,
                    ):
                        attempt = await classify_phase2_deep_retry(
                            domain,
                            _orig,
                            dict(phase1_row),
                            timeout_seconds=phase2_timeout,
                            browser_profile=p2_profile,
                            on_partial=_on_phase2_partial if on_row_patch else None,
                        )
                    final_row = merge_phase2_result(phase1_row, attempt)
                except Exception:
                    continue

                if str(final_row.get("Trạng_Thái", "")).strip() != STATUS_TIMEOUT:
                    break

            final_row["STT"] = idx
            results[idx] = final_row
            if on_row_patch:
                await on_row_patch(results[idx], idx, total)
            if on_progress:
                on_progress(total, total)

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
