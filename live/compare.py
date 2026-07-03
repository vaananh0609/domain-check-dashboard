"""So sánh nhiều phiên kết quả đã lưu theo từng domain."""

from __future__ import annotations

from typing import Any, Callable, Optional

import pandas as pd

from .constants import (
    COL_FINAL_VI,
    COL_HTTP,
    COL_HTTP_VER,
    COL_ORIGINAL,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_TIMEOUT,
)

MAX_COMPARE_SESSIONS = 5
MIN_COMPARE_SESSIONS = 2

_STATUS_ORDER = {STATUS_BLOCKED: 0, STATUS_LEAKED: 1, STATUS_TIMEOUT: 2, STATUS_DEAD: 3}


def _domain_key(row: dict[str, Any]) -> str:
    raw = str(row.get(COL_ORIGINAL) or "").strip().lower()
    if raw and raw != "—":
        return raw
    return ""


def _row_dict(df: pd.DataFrame, idx: int) -> dict[str, Any]:
    return {str(k): ("" if v is None else v) for k, v in df.iloc[idx].items()}


def _session_label(entry: dict[str, Any], rid: str) -> str:
    stem = str(entry.get("upload_stem") or "domains")
    when = str(entry.get("created_label") or rid[:8])
    return f"{when} — {stem}"


def _session_meta(entry: dict[str, Any], rid: str) -> dict[str, Any]:
    from .browser_profiles import get_browser_profile

    snap = entry.get("form_snapshot") or {}
    summary = entry.get("summary") or {}
    profile = str(snap.get("browser_profile") or "").strip().lower()
    bp = get_browser_profile(profile)
    profile_label = f"{bp.label} · {bp.dns_mode_label}"
    return {
        "id": rid,
        "label": _session_label(entry, rid),
        "created_label": str(entry.get("created_label") or ""),
        "upload_stem": str(entry.get("upload_stem") or "domains"),
        "elapsed_seconds": float(entry.get("elapsed") or 0),
        "browser_profile": profile,
        "browser_profile_label": profile_label,
        "total": int(summary.get("total") or 0),
        "blocked": int(summary.get(STATUS_BLOCKED) or 0),
        "leaked": int(summary.get(STATUS_LEAKED) or 0),
        "dead": int(summary.get(STATUS_DEAD) or 0),
        "timeout": int(summary.get(STATUS_TIMEOUT) or 0),
    }


def build_comparison(
    sessions: list[tuple[str, pd.DataFrame, dict[str, Any]]],
    *,
    q: str = "",
    only_changed: bool = False,
) -> dict[str, Any]:
    """
  sessions: [(result_id, dataframe, store_entry), ...]
  Trả về cấu trúc cho template compare.html.
    """
    if len(sessions) < MIN_COMPARE_SESSIONS:
        raise ValueError(f"Cần ít nhất {MIN_COMPARE_SESSIONS} phiên để so sánh.")

    session_metas: list[dict[str, Any]] = []
    domain_maps: list[dict[str, dict[str, Any]]] = []

    for rid, df, entry in sessions:
        session_metas.append(_session_meta(entry, rid))
        by_domain: dict[str, dict[str, Any]] = {}
        for i in range(len(df)):
            row = _row_dict(df, i)
            key = _domain_key(row)
            if not key:
                continue
            if key not in by_domain:
                by_domain[key] = row
        domain_maps.append(by_domain)

    all_domains = sorted({d for m in domain_maps for d in m})

    kw = str(q or "").strip().lower()
    compare_rows: list[dict[str, Any]] = []
    changed_count = 0
    same_count = 0
    missing_any = 0

    for domain in all_domains:
        if kw and kw not in domain:
            continue

        cells: list[dict[str, Any]] = []
        statuses: list[str] = []
        present = 0
        for m in domain_maps:
            row = m.get(domain)
            if row:
                present += 1
                status = str(row.get("Trạng_Thái") or "").strip()
                statuses.append(status)
                cells.append(
                    {
                        "present": True,
                        "status": status,
                        "final_vi": str(row.get(COL_FINAL_VI) or "—"),
                        "http": str(row.get(COL_HTTP) or "—"),
                        "http_ver": str(row.get(COL_HTTP_VER) or "—"),
                    }
                )
            else:
                cells.append(
                    {
                        "present": False,
                        "status": "",
                        "final_vi": "—",
                        "http": "—",
                        "http_ver": "—",
                    }
                )

        unique_statuses = {s for s in statuses if s}
        is_changed = len(unique_statuses) > 1
        is_partial = present < len(sessions)
        if is_changed:
            changed_count += 1
        elif present == len(sessions) and len(unique_statuses) == 1:
            same_count += 1
        if is_partial:
            missing_any += 1

        if only_changed and not is_changed:
            continue

        compare_rows.append(
            {
                "domain": domain,
                "cells": cells,
                "changed": is_changed,
                "partial": is_partial,
                "statuses": statuses,
            }
        )

    return {
        "sessions": session_metas,
        "rows": compare_rows,
        "stats": {
            "total_domains": len(compare_rows),
            "changed": changed_count,
            "unchanged": same_count,
            "partial": missing_any,
            "all_domains_union": len(all_domains),
        },
    }


def parse_compare_ids(raw: str) -> list[str]:
    parts = [p.strip() for p in str(raw or "").split(",")]
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        if not p or p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= MAX_COMPARE_SESSIONS:
            break
    return out


def load_sessions_for_compare(
    ids: list[str],
    get_entry: Callable[[str], Optional[dict[str, Any]]],
    df_from_entry: Callable[[dict[str, Any]], pd.DataFrame],
) -> list[tuple[str, pd.DataFrame, dict[str, Any]]]:
    sessions: list[tuple[str, pd.DataFrame, dict[str, Any]]] = []
    for rid in ids:
        entry = get_entry(rid)
        if entry is None:
            continue
        df = df_from_entry(entry)
        sessions.append((rid, df, entry))
    return sessions
