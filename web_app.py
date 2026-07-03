from __future__ import annotations

import asyncio
import io
import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

# Playwright subprocess trên Windows cần ProactorEventLoop.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from live.parsing import browse_url_for_cell, cell_link_html
from live.compare import (
    MAX_COMPARE_SESSIONS,
    MIN_COMPARE_SESSIONS,
    build_comparison,
    load_sessions_for_compare,
    parse_compare_ids,
)
from live.browser_profiles import list_browser_profile_ids
from live.probe_config import (
    CHROME_USER_DATA_ENV,
    COCCOC_USER_DATA_ENV,
    DEFAULT_CHROME_USER_DATA_DIR,
    DEFAULT_COCCOC_USER_DATA_DIR,
    DEFAULT_EDGE_USER_DATA_DIR,
    DEFAULT_LOCAL_DNS,
    EDGE_USER_DATA_ENV,
    parse_local_dns_servers,
)
from live.constants import clamp_phase1_timeout_seconds
from live.constants import COL_DNS, COL_DNS_LEGACY_KEYS
from live.result_store import PersistentResultStore
from live.tls_probe import tls_column_to_html

from dynamic_live_core import (
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
    EXPECTED_GUEST_IP,
    HTTP_RETRIES,
    PREFLIGHT_TIMEOUT_SECONDS,
    PUBLIC_DNS_SERVERS,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
    STATUS_TIMEOUT,
    ASYNC_CONCURRENCY,
    BACKOFF_BASE_SECONDS,
    detect_public_ip_async,
    live_pie_chart,
    normalize_target,
    parse_dns_servers,
    read_uploaded_text_lines,
    RESULT_DF_COLUMNS,
    run_live_test_from_lines_async,
    run_network_preflight,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "saved_results"
SAVED_RESULTS_PAGE_SIZE = 10

# Cột xuất báo cáo — khớp thứ tự bảng Data Table (không gồm DNS / Trace / mã nội bộ)
EXPORT_COLUMN_DEFS: list[dict[str, str]] = [
    {"slug": "stt", "key": "STT", "label": "STT"},
    {"slug": "goc", "key": COL_ORIGINAL, "label": COL_ORIGINAL},
    {"slug": "trang_thai_cuoi", "key": COL_FINAL_VI, "label": COL_FINAL_VI},
    {"slug": "nguon_ket_luan", "key": COL_RESULT_SOURCE, "label": COL_RESULT_SOURCE},
    {"slug": "dns", "key": COL_DNS, "label": COL_DNS},
    {"slug": "tcp_80", "key": COL_TCP_80, "label": COL_TCP_80},
    {"slug": "tcp_443", "key": COL_TCP_443, "label": COL_TCP_443},
    {"slug": "ma_http", "key": COL_HTTP, "label": COL_HTTP},
    {"slug": "http_ver", "key": COL_HTTP_VER, "label": COL_HTTP_VER},
    {"slug": "tls", "key": COL_TLS, "label": COL_TLS},
    {"slug": "chuoi", "key": COL_CHAIN, "label": COL_CHAIN},
    {"slug": "pw_err", "key": COL_PLAYWRIGHT_ERR, "label": COL_PLAYWRIGHT_ERR},
    {"slug": "latency", "key": COL_LATENCY, "label": COL_LATENCY},
]
EXPORT_SLUG_TO_KEY = {d["slug"]: d["key"] for d in EXPORT_COLUMN_DEFS}
EXPORT_DEFAULT_KEYS = [d["key"] for d in EXPORT_COLUMN_DEFS]

EXPORT_STATE_DEFS: list[dict[str, str]] = [
    {"value": STATUS_BLOCKED, "label": "blocked", "slug": "blocked"},
    {"value": STATUS_LEAKED, "label": "leaked", "slug": "leaked"},
    {"value": STATUS_DEAD, "label": "dead", "slug": "dead"},
    {"value": STATUS_TIMEOUT, "label": "timeout", "slug": "timeout"},
]
_EXPORT_STATE_CODES = frozenset(d["value"] for d in EXPORT_STATE_DEFS)

_STATUS_LABEL_TO_INTERNAL: dict[str, str] = {
    "blocked": STATUS_BLOCKED,
    "leaked": STATUS_LEAKED,
    "dead": STATUS_DEAD,
    "timeout": STATUS_TIMEOUT,
}

# Mặc định form: timeout HTTP (giây); không proxy — xem _prepare_live_run
DEFAULT_UI_HTTP_TIMEOUT = 10

_INVALID_UPLOAD_STEM_CHARS = frozenset('<>:"/\\|?*\n\r\t')


def _sanitize_upload_stem(filename: Optional[str]) -> str:
    if not filename or not str(filename).strip():
        return "domains"
    base = Path(str(filename)).name
    stem = Path(base).stem or "domains"
    cleaned = "".join(c if c not in _INVALID_UPLOAD_STEM_CHARS else "_" for c in stem)
    cleaned = re.sub(r"_+", "_", cleaned).strip("._ ") or "domains"
    return cleaned[:120]


def _export_state_slug(export_state: str) -> str:
    """Tiền tố file xuất khi lọc theo state (ALL / nhiều state = không thêm hoặc gộp slug)."""
    raw = (export_state or "").strip()
    if not raw or raw.upper() == "ALL":
        return ""
    m = {
        STATUS_BLOCKED: "blocked",
        STATUS_LEAKED: "leaked",
        STATUS_DEAD: "dead",
        STATUS_TIMEOUT: "timeout",
    }
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    codes = [p for p in parts if p in _EXPORT_STATE_CODES]
    if not codes or set(codes) >= _EXPORT_STATE_CODES:
        return ""
    slugs = sorted(m.get(code, re.sub(r"[^\w]+", "_", code.lower()).strip("_")) for code in codes)
    slugs = [s for s in slugs if s]
    return ("_".join(slugs) + "_") if slugs else ""


def _parse_export_states(state_param: str) -> Optional[list[str]]:
    """None = xuất tất cả; ngược lại danh sách mã Trạng_Thái đã chọn."""
    raw = (state_param or "").strip()
    if not raw or raw.upper() == "ALL":
        return None
    selected = [p.strip() for p in raw.split(",") if p.strip() in _EXPORT_STATE_CODES]
    if not selected or set(selected) >= _EXPORT_STATE_CODES:
        return None
    return selected


def _export_status_series(df: pd.DataFrame) -> pd.Series:
    """Mã trạng thái nội bộ — fallback cột Status (phiên CSV cũ)."""
    if "Trạng_Thái" in df.columns:
        internal = df["Trạng_Thái"].astype(str).str.strip()
    else:
        internal = pd.Series([""] * len(df), index=df.index, dtype=str)
    missing = internal.isin(("", "—", "nan", "none", "NaN", "<NA>"))
    if missing.any() and COL_FINAL_VI in df.columns:
        vi = df[COL_FINAL_VI].astype(str).str.strip()
        mapped = vi.str.lower().map(_STATUS_LABEL_TO_INTERNAL)
        internal = internal.where(~missing, mapped.fillna(""))
    return internal


def _export_file_base_name(entry: dict[str, Any], export_state: str = "ALL") -> str:
    stem = entry.get("upload_stem") or "domains"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = _export_state_slug(export_state)
    return f"output_{prefix}{stem}_{ts}"


def _attachment_content_disposition(filename: str) -> str:
    ascii_name = "".join(
        c if 32 <= ord(c) < 127 and c not in '\\"/' else "_" for c in filename
    )
    ascii_name = re.sub(r"_+", "_", ascii_name).strip("._") or "output"
    if len(ascii_name) > 180:
        ascii_name = ascii_name[:180]
    encoded = quote(filename, safe="")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"


app = FastAPI(title="Dynamic Live Testing")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Lưu kết quả ra đĩa — giữ lại sau khi restart uvicorn
_MAX_STORE = 200
_result_store = PersistentResultStore(DATA_DIR, max_items=_MAX_STORE)


def _summary_from_df(df: pd.DataFrame) -> dict[str, int]:
    status = _export_status_series(df)
    return {
        "total": len(df),
        STATUS_BLOCKED: int((status == STATUS_BLOCKED).sum()),
        STATUS_LEAKED: int((status == STATUS_LEAKED).sum()),
        STATUS_DEAD: int((status == STATUS_DEAD).sum()),
        STATUS_TIMEOUT: int((status == STATUS_TIMEOUT).sum()),
    }


def _store_result(payload: dict[str, Any]) -> str:
    rid = str(uuid.uuid4())
    now = datetime.now()
    payload = dict(payload)
    payload["created_at"] = now.isoformat(timespec="seconds")
    payload["created_label"] = now.strftime("%d/%m/%Y %H:%M:%S")
    try:
        payload["summary"] = _summary_from_df(_df_from_store(payload))
    except Exception:
        payload["summary"] = {"total": 0, STATUS_BLOCKED: 0, STATUS_LEAKED: 0, STATUS_DEAD: 0, STATUS_TIMEOUT: 0}
    _result_store.put(rid, payload)
    return rid


def _saved_result_item(rid: str, entry: dict[str, Any]) -> dict[str, Any]:
    summary = entry.get("summary") or {}
    snap = entry.get("form_snapshot") or {}
    profile = str(snap.get("browser_profile") or "").strip().lower()
    from live.browser_profiles import get_browser_profile

    bp = get_browser_profile(profile)
    profile_label = f"{bp.label} · {bp.dns_mode_label}"
    return {
        "id": rid,
        "title": entry.get("upload_stem") or "domains",
        "created_label": entry.get("created_label") or "",
        "elapsed_seconds": float(entry.get("elapsed") or 0),
        "total": int(summary.get("total") or 0),
        "blocked": int(summary.get(STATUS_BLOCKED) or 0),
        "leaked": int(summary.get(STATUS_LEAKED) or 0),
        "dead": int(summary.get(STATUS_DEAD) or 0),
        "timeout": int(summary.get(STATUS_TIMEOUT) or 0),
        "browser_profile": profile,
        "browser_profile_label": profile_label,
    }


def _list_saved_results_paginated(
    page: int = 1,
    per_page: int = SAVED_RESULTS_PAGE_SIZE,
) -> tuple[list[dict[str, Any]], int]:
    _result_store.ensure_loaded()
    ordered = _result_store.list_newest_first()
    total = len(ordered)
    page = max(1, page)
    per_page = max(1, min(int(per_page), 100))
    start = (page - 1) * per_page
    items: list[dict[str, Any]] = []
    for rid, _meta in ordered[start : start + per_page]:
        entry = _result_store.get(rid)
        if entry is None:
            continue
        items.append(_saved_result_item(rid, entry))
    return items, total


def _saved_results_page_for_id(rid: str, per_page: int = SAVED_RESULTS_PAGE_SIZE) -> int:
    if not rid:
        return 1
    _result_store.ensure_loaded()
    for i, (item_rid, _) in enumerate(_result_store.list_newest_first()):
        if item_rid == rid:
            return i // per_page + 1
    return 1


def _get_result(rid: str) -> dict[str, Any]:
    _result_store.ensure_loaded()
    entry = _result_store.get(rid)
    if entry is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy phiên kết quả (có thể đã bị xóa).")
    _result_store.touch(rid)
    return entry


def _normalize_df_dns_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Gộp 4 cột DNS cũ / DNS resolution → một cột DNS."""
    from live.labels import primary_dns_display_from_row

    legacy = [c for c in COL_DNS_LEGACY_KEYS if c in df.columns]
    if COL_DNS not in df.columns:
        df[COL_DNS] = ""
    needs_merge = bool(legacy)
    if not needs_merge:
        empty = df[COL_DNS].astype(str).str.strip().isin(("", "—", "nan"))
        needs_merge = bool(empty.all())
    if needs_merge:
        df[COL_DNS] = df.apply(lambda r: primary_dns_display_from_row(r.to_dict()), axis=1)
    drop_cols = [c for c in legacy if c in df.columns and c != COL_DNS]
    if drop_cols:
        df = df.drop(columns=drop_cols)
    return df


def _df_from_store(entry: dict[str, Any]) -> pd.DataFrame:
    df = pd.read_csv(
        io.StringIO(entry["df_csv"]),
        keep_default_na=False,
    )
    df = _normalize_df_dns_columns(df)
    for c in RESULT_DF_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    return df


def _upload_line_display(raw_line: str) -> str:
    s = raw_line.strip()
    if not s:
        return ""
    if "\t" in s:
        return s.split("\t", 1)[0].strip()[:2000]
    if "," in s:
        return s.split(",", 1)[0].strip()[:2000]
    return s[:2000]


def _filter_df_by_search(df: pd.DataFrame, q: str) -> pd.DataFrame:
    if not q or not str(q).strip():
        return df
    kw = str(q).strip().lower()
    m1 = df[COL_ORIGINAL].astype(str).str.lower().str.contains(kw, na=False)
    masks = [m1]
    for col in (COL_DNS, COL_CHAIN, COL_PLAYWRIGHT_ERR):
        if col in df.columns:
            masks.append(df[col].astype(str).str.lower().str.contains(kw, na=False))
    for col in COL_DNS_LEGACY_KEYS:
        if col in df.columns:
            masks.append(df[col].astype(str).str.lower().str.contains(kw, na=False))
    if len(masks) == 1:
        return df[m1]
    combined = masks[0]
    for m in masks[1:]:
        combined = combined | m
    return df[combined]


def status_row_class(status: str) -> str:
    return {
        STATUS_BLOCKED: "blocked",
        STATUS_LEAKED: "leaked",
        STATUS_DEAD: "dead",
        STATUS_TIMEOUT: "timeout",
    }.get(status, "")


def tls_cell(value: object) -> str:
    """Render COL_TLS flat text as badge HTML (kết quả đã lưu CSV)."""
    s = str(value or "").strip()
    if not s or s == "—":
        return ""
    html_out = tls_column_to_html(s)
    return html_out if html_out else s


templates.env.filters["status_row_class"] = status_row_class
templates.env.filters["urlquote"] = lambda s: quote(str(s or ""), safe="")
templates.env.filters["browse_url"] = lambda s: browse_url_for_cell(str(s or ""))
templates.env.filters["cell_link"] = lambda s: cell_link_html(str(s or ""))
templates.env.filters["tls_cell"] = tls_cell


@app.on_event("startup")
def _load_saved_results_on_startup() -> None:
    _result_store.ensure_loaded()
    n = _result_store.count()
    if n:
        print(f"[saved-results] Đã nạp {n} phiên từ {DATA_DIR}")


def _sse_encode(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n".encode("utf-8")


def _form_checkbox(form: Any, key: str, *, default: bool = False) -> bool:
    """Đọc checkbox HTML (hỗ trợ hidden 0 + checkbox 1)."""
    getlist = getattr(form, "getlist", None)
    if callable(getlist):
        vals = [str(v).strip().lower() for v in getlist(key) if v is not None and str(v).strip()]
        if not vals:
            return default
        return any(v in ("1", "true", "on", "yes") for v in vals)
    raw = form.get(key)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "on", "yes")


async def _prepare_live_run(request: Request) -> tuple[Optional[dict[str, Any]], Optional[str], dict[str, Any]]:
    current_public_ip = await detect_public_ip_async(timeout=3)
    defaults = {
        "default_public_dns": ",".join(PUBLIC_DNS_SERVERS),
        "default_local_dns": os.environ.get("PROBE_LOCAL_DNS", DEFAULT_LOCAL_DNS),
        "default_coccoc_user_data": os.environ.get(
            COCCOC_USER_DATA_ENV,
            DEFAULT_COCCOC_USER_DATA_DIR,
        ),
        "default_edge_user_data": os.environ.get(
            EDGE_USER_DATA_ENV,
            DEFAULT_EDGE_USER_DATA_DIR,
        ),
        "default_chrome_user_data": os.environ.get(
            CHROME_USER_DATA_ENV,
            DEFAULT_CHROME_USER_DATA_DIR,
        ),
        "default_concurrency": ASYNC_CONCURRENCY,
        "default_dns_timeout": DNS_TIMEOUT_SECONDS,
        "default_preflight_timeout": PREFLIGHT_TIMEOUT_SECONDS,
        "default_retries": HTTP_RETRIES,
        "default_backoff": BACKOFF_BASE_SECONDS,
        "current_public_ip": current_public_ip,
        "expected_guest_ip": EXPECTED_GUEST_IP,
        "COL_ORIGINAL": COL_ORIGINAL,
        "COL_DNS": COL_DNS,
        "COL_FINAL_VI": COL_FINAL_VI,
        "COL_RESULT_SOURCE": COL_RESULT_SOURCE,
        "COL_TCP_80": COL_TCP_80,
        "COL_TCP_443": COL_TCP_443,
        "COL_HTTP": COL_HTTP,
        "COL_HTTP_VER": COL_HTTP_VER,
        "COL_TLS": COL_TLS,
        "COL_CHAIN": COL_CHAIN,
        "COL_PLAYWRIGHT_ERR": COL_PLAYWRIGHT_ERR,
        "COL_LATENCY": COL_LATENCY,
        "COL_TRACE": COL_TRACE,
        "form_enable_trace": True,
        "form_enable_step3": True,
        "form_browser_headed": True,
        "form_enable_phase2": True,
        "form_phase2_timeout": 60,
        "form_browser_profile": "edge",
    }
    form = await request.form()
    upload = form.get("domain_file")
    if upload is None:
        return None, "Thiếu file domain.", defaults
    raw = await upload.read()
    filename = getattr(upload, "filename", None) or "file"

    input_lines = read_uploaded_text_lines(raw)
    target_pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_line in input_lines:
        domain = normalize_target(raw_line)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        target_pairs.append((_upload_line_display(raw_line), domain))

    if not target_pairs:
        return None, "File domain rỗng hoặc không hợp lệ.", defaults

    try:
        timeout_seconds = clamp_phase1_timeout_seconds(
            int(form.get("timeout_seconds") or DEFAULT_UI_HTTP_TIMEOUT)
        )
    except (TypeError, ValueError):
        timeout_seconds = clamp_phase1_timeout_seconds(DEFAULT_UI_HTTP_TIMEOUT)
    try:
        max_domains = int(form.get("max_domains") or 1000)
    except (TypeError, ValueError):
        max_domains = 1000
    try:
        concurrency = int(form.get("concurrency") or ASYNC_CONCURRENCY)
    except (TypeError, ValueError):
        concurrency = ASYNC_CONCURRENCY
    try:
        dns_timeout_seconds = int(form.get("dns_timeout_seconds") or DNS_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        dns_timeout_seconds = DNS_TIMEOUT_SECONDS
    try:
        preflight_timeout_seconds = int(form.get("preflight_timeout_seconds") or PREFLIGHT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        preflight_timeout_seconds = PREFLIGHT_TIMEOUT_SECONDS
    try:
        retries = int(form.get("retries") or HTTP_RETRIES)
    except (TypeError, ValueError):
        retries = HTTP_RETRIES
    try:
        backoff_seconds = float(form.get("backoff_seconds") or BACKOFF_BASE_SECONDS)
    except (TypeError, ValueError):
        backoff_seconds = BACKOFF_BASE_SECONDS

    public_dns_raw = str(form.get("public_dns_raw") or ",".join(PUBLIC_DNS_SERVERS))
    local_dns_raw = str(
        form.get("local_dns_raw") or os.environ.get("PROBE_LOCAL_DNS", DEFAULT_LOCAL_DNS)
    )
    enable_trace = _form_checkbox(form, "enable_trace", default=True)
    enable_step3 = _form_checkbox(form, "enable_step3", default=True)
    browser_headed = _form_checkbox(form, "browser_headed", default=True)
    enable_phase2 = _form_checkbox(form, "enable_phase2", default=True) and enable_step3
    try:
        from live.phase2 import PHASE2_DEFAULT_TIMEOUT_SECONDS, clamp_phase2_timeout_seconds

        phase2_timeout_seconds = clamp_phase2_timeout_seconds(
            int(form.get("phase2_timeout_seconds") or PHASE2_DEFAULT_TIMEOUT_SECONDS)
        )
    except (TypeError, ValueError):
        from live.phase2 import PHASE2_DEFAULT_TIMEOUT_SECONDS

        phase2_timeout_seconds = PHASE2_DEFAULT_TIMEOUT_SECONDS
    browser_profile = str(form.get("browser_profile") or "edge").strip().lower()
    valid_profiles = set(list_browser_profile_ids())
    if browser_profile not in valid_profiles:
        browser_profile = "edge"
    coccoc_user_data = str(
        form.get("coccoc_user_data")
        or os.environ.get(COCCOC_USER_DATA_ENV, DEFAULT_COCCOC_USER_DATA_DIR)
    ).strip()
    edge_user_data = str(
        form.get("edge_user_data")
        or os.environ.get(EDGE_USER_DATA_ENV, DEFAULT_EDGE_USER_DATA_DIR)
    ).strip()
    chrome_user_data = str(
        form.get("chrome_user_data")
        or os.environ.get(CHROME_USER_DATA_ENV, DEFAULT_CHROME_USER_DATA_DIR)
    ).strip()
    active_public_dns = parse_dns_servers(public_dns_raw)
    active_local_dns = parse_local_dns_servers(local_dns_raw)
    preflight = await run_network_preflight(
        active_public_dns,
        dns_timeout=int(dns_timeout_seconds),
        timeout=int(preflight_timeout_seconds),
        local_dns_servers=active_local_dns,
    )

    params: dict[str, Any] = {
        "target_pairs": target_pairs,
        "upload_filename": filename,
        "timeout_seconds": timeout_seconds,
        "max_domains": max_domains,
        "concurrency": concurrency,
        "dns_timeout_seconds": dns_timeout_seconds,
        "retries": retries,
        "backoff_seconds": backoff_seconds,
        "active_public_dns": active_public_dns,
        "active_local_dns": active_local_dns,
        "public_dns_raw": public_dns_raw,
        "local_dns_raw": local_dns_raw,
        "preflight": preflight,
        "current_public_ip": current_public_ip,
        "preflight_timeout_seconds": preflight_timeout_seconds,
        "enable_trace": enable_trace,
        "enable_step3": enable_step3,
        "browser_headed": browser_headed,
        "enable_phase2": enable_phase2,
        "phase2_timeout_seconds": phase2_timeout_seconds,
        "browser_profile": browser_profile,
        "coccoc_user_data": coccoc_user_data,
        "edge_user_data": edge_user_data,
        "chrome_user_data": chrome_user_data,
    }

    return params, None, defaults


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, saved: str = "", highlight: str = ""):
    current_public_ip = await detect_public_ip_async(timeout=3)
    highlight_id = highlight or saved or ""
    initial_page = _saved_results_page_for_id(highlight_id) if highlight_id else 1
    saved_results, saved_results_total = _list_saved_results_paginated(initial_page)
    return templates.TemplateResponse(
    request=request,
    name="index.html", 
    context={          
        "current_public_ip": current_public_ip,
        "expected_guest_ip": EXPECTED_GUEST_IP,
        "default_public_dns": ",".join(PUBLIC_DNS_SERVERS),
        "default_local_dns": os.environ.get("PROBE_LOCAL_DNS", DEFAULT_LOCAL_DNS),
        "default_coccoc_user_data": os.environ.get(
            COCCOC_USER_DATA_ENV,
            DEFAULT_COCCOC_USER_DATA_DIR,
        ),
        "default_edge_user_data": os.environ.get(
            EDGE_USER_DATA_ENV,
            DEFAULT_EDGE_USER_DATA_DIR,
        ),
        "default_chrome_user_data": os.environ.get(
            CHROME_USER_DATA_ENV,
            DEFAULT_CHROME_USER_DATA_DIR,
        ),
        "default_concurrency": ASYNC_CONCURRENCY,
        "default_dns_timeout": DNS_TIMEOUT_SECONDS,
        "default_preflight_timeout": PREFLIGHT_TIMEOUT_SECONDS,
        "default_retries": HTTP_RETRIES,
        "default_backoff": BACKOFF_BASE_SECONDS,
        "form_enable_trace": True,
        "form_enable_step3": True,
        "form_browser_headed": True,
        "form_enable_phase2": True,
        "form_phase2_timeout": 60,
        "form_browser_profile": "edge",
        "error": None,
        "saved_results": saved_results,
        "saved_results_total": saved_results_total,
        "saved_results_page": initial_page,
        "saved_results_page_size": SAVED_RESULTS_PAGE_SIZE,
        "highlight_result_id": highlight_id,
        "COL_ORIGINAL": COL_ORIGINAL,
        "COL_DNS": COL_DNS,
        "COL_FINAL_VI": COL_FINAL_VI,
        "COL_RESULT_SOURCE": COL_RESULT_SOURCE,
        "COL_TCP_80": COL_TCP_80,
        "COL_TCP_443": COL_TCP_443,
        "COL_HTTP": COL_HTTP,
        "COL_HTTP_VER": COL_HTTP_VER,
        "COL_TLS": COL_TLS,
        "COL_CHAIN": COL_CHAIN,
        "COL_PLAYWRIGHT_ERR": COL_PLAYWRIGHT_ERR,
        "COL_LATENCY": COL_LATENCY,
        "COL_TRACE": COL_TRACE,
        },
    )


@app.get("/api/saved-results")
async def api_saved_results(page: int = 1, per_page: int = SAVED_RESULTS_PAGE_SIZE):
    items, total = _list_saved_results_paginated(page, per_page)
    per_page = max(1, min(int(per_page), 100))
    page = max(1, page)
    page_count = max(1, (total + per_page - 1) // per_page) if total else 1
    return JSONResponse(
        {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "page_count": page_count,
        }
    )


@app.post("/api/saved-results/delete")
async def api_delete_saved_results(request: Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        body = {}
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Payload không hợp lệ.")

    _result_store.ensure_loaded()

    if body.get("all") is True:
        deleted_count = _result_store.delete_all()
        if deleted_count <= 0:
            raise HTTPException(status_code=404, detail="Không có phiên nào để xóa.")
        return JSONResponse({"ok": True, "deleted": [], "deleted_count": deleted_count, "all": True})

    ids = body.get("ids")
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="Chưa chọn phiên nào để xóa.")
    deleted: list[str] = []
    for raw in ids:
        rid = str(raw or "").strip()
        if rid and _result_store.delete(rid):
            deleted.append(rid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Không tìm thấy phiên kết quả.")
    return JSONResponse({"ok": True, "deleted": deleted, "deleted_count": len(deleted)})


@app.get("/compare", response_class=HTMLResponse)
async def compare_results(
    request: Request,
    ids: str = "",
    q: str = "",
    only_changed: str = "",
):
    id_list = parse_compare_ids(ids)
    only_changed_on = str(only_changed or "").lower() in ("1", "true", "on", "yes")
    empty_ctx: dict[str, Any] = {
        "request": request,
        "error": None,
        "sessions": [],
        "rows": [],
        "stats": {
            "total_domains": 0,
            "changed": 0,
            "unchanged": 0,
            "partial": 0,
            "all_domains_union": 0,
        },
        "ids_param": ",".join(id_list),
        "q": q,
        "only_changed": only_changed_on,
    }
    if len(id_list) < MIN_COMPARE_SESSIONS:
        empty_ctx["error"] = (
            f"Chọn từ {MIN_COMPARE_SESSIONS} đến {MAX_COMPARE_SESSIONS} phiên trong danh sách đã lưu "
            f"(mục 2 trên trang chủ), hoặc mở URL /compare?ids=uuid1,uuid2."
        )
        return templates.TemplateResponse(
            request=request,
            name="compare.html",
            context=empty_ctx,
        )

    sessions = load_sessions_for_compare(id_list, _result_store.get, _df_from_store)
    if len(sessions) < MIN_COMPARE_SESSIONS:
        found = {rid for rid, _, _ in sessions}
        missing = [rid for rid in id_list if rid not in found]
        empty_ctx["error"] = (
            f"Không tìm thấy đủ phiên để so sánh"
            + (f" (thiếu: {', '.join(missing[:3])}{'…' if len(missing) > 3 else ''})." if missing else ".")
        )
        return templates.TemplateResponse(
            request=request,
            name="compare.html",
            context=empty_ctx,
        )

    data = build_comparison(sessions, q=q, only_changed=only_changed_on)
    return templates.TemplateResponse(
        request=request,
        name="compare.html",
        context={
            "error": None,
            "sessions": data["sessions"],
            "rows": data["rows"],
            "stats": data["stats"],
            "ids_param": ",".join(id_list),
            "q": q,
            "only_changed": only_changed_on,
        },
    )


@app.post("/run", response_class=HTMLResponse)
async def run_live(request: Request):
    params, err, defaults = await _prepare_live_run(request)
    if err:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={**defaults, "error": err},
            status_code=400,
        )
    assert params is not None

    live_df, elapsed_seconds = await run_live_test_from_lines_async(
        params["target_pairs"],
        timeout=int(params["timeout_seconds"]),
        max_domains=int(params["max_domains"]),
        proxy_url=None,
        follow_redirects=True,
        concurrency=int(params["concurrency"]),
        dns_timeout=int(params["dns_timeout_seconds"]),
        retries=int(params["retries"]),
        backoff_base=float(params["backoff_seconds"]),
        public_dns_servers=params["active_public_dns"],
        local_dns_servers=params["active_local_dns"],
        enable_trace=bool(params.get("enable_trace", True)),
        enable_step3=bool(params.get("enable_step3", True)),
        browser_headed=bool(params.get("browser_headed", True)),
        browser_profile=str(params.get("browser_profile") or "edge"),
        coccoc_user_data=str(params.get("coccoc_user_data") or ""),
        edge_user_data=str(params.get("edge_user_data") or ""),
        chrome_user_data=str(params.get("chrome_user_data") or ""),
        enable_phase2=bool(params.get("enable_phase2", False)),
        phase2_timeout_seconds=int(params.get("phase2_timeout_seconds") or 60),
    )

    if live_df.empty:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={**defaults, "error": "Không có domain hợp lệ để kiểm thử."},
            status_code=400,
        )

    upload_stem = _sanitize_upload_stem(params["upload_filename"])
    form_snapshot = {
        "timeout_seconds": int(params["timeout_seconds"]),
        "max_domains": int(params["max_domains"]),
        "concurrency": int(params["concurrency"]),
        "dns_timeout_seconds": int(params["dns_timeout_seconds"]),
        "preflight_timeout_seconds": int(params["preflight_timeout_seconds"]),
        "retries": int(params["retries"]),
        "backoff_seconds": float(params["backoff_seconds"]),
        "public_dns_raw": str(params.get("public_dns_raw") or ",".join(PUBLIC_DNS_SERVERS)),
        "local_dns_raw": str(params.get("local_dns_raw") or ""),
        "enable_trace": bool(params.get("enable_trace", True)),
        "enable_step3": bool(params.get("enable_step3", True)),
        "browser_headed": bool(params.get("browser_headed", True)),
        "browser_profile": str(params.get("browser_profile") or "edge"),
        "enable_phase2": bool(params.get("enable_phase2", False)),
        "phase2_timeout_seconds": int(params.get("phase2_timeout_seconds") or 60),
        "coccoc_user_data": str(params.get("coccoc_user_data") or ""),
        "edge_user_data": str(params.get("edge_user_data") or ""),
        "chrome_user_data": str(params.get("chrome_user_data") or ""),
    }
    rid = _store_result(
        {
            "df_csv": live_df.to_csv(index=False, na_rep=""),
            "elapsed": float(elapsed_seconds),
            "upload_stem": upload_stem,
            "preflight": params["preflight"],
            "form_snapshot": form_snapshot,
        }
    )
    return RedirectResponse(url=f"/?saved={rid}#saved-results", status_code=303)


@app.post("/run-stream")
async def run_live_stream(request: Request):
    params, err, _defaults = await _prepare_live_run(request)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    assert params is not None

    total_planned = min(len(params["target_pairs"]), max(1, int(params["max_domains"])))

    async def event_gen():
        q: asyncio.Queue = asyncio.Queue()

        async def on_row(row: dict[str, Any], done: int, total: int) -> None:
            await q.put(("row", row, done, total))

        async def on_row_patch(row: dict[str, Any], _idx: int, total: int) -> None:
            await q.put(("patch", row, total))

        async def worker() -> None:
            try:
                live_df, elapsed_seconds = await run_live_test_from_lines_async(
                    params["target_pairs"],
                    timeout=int(params["timeout_seconds"]),
                    max_domains=int(params["max_domains"]),
                    proxy_url=None,
                    follow_redirects=True,
                    concurrency=int(params["concurrency"]),
                    dns_timeout=int(params["dns_timeout_seconds"]),
                    retries=int(params["retries"]),
                    backoff_base=float(params["backoff_seconds"]),
                    public_dns_servers=params["active_public_dns"],
                    local_dns_servers=params["active_local_dns"],
                    enable_trace=bool(params.get("enable_trace", True)),
                    enable_step3=bool(params.get("enable_step3", True)),
                    browser_headed=bool(params.get("browser_headed", True)),
                    browser_profile=str(params.get("browser_profile") or "edge"),
                    coccoc_user_data=str(params.get("coccoc_user_data") or ""),
                    edge_user_data=str(params.get("edge_user_data") or ""),
                    chrome_user_data=str(params.get("chrome_user_data") or ""),
                    enable_phase2=bool(params.get("enable_phase2", False)),
                    phase2_timeout_seconds=int(params.get("phase2_timeout_seconds") or 60),
                    on_row=on_row,
                    on_row_patch=on_row_patch,
                )
                if live_df.empty:
                    await q.put(("empty",))
                    return
                upload_stem = _sanitize_upload_stem(params["upload_filename"])
                form_snapshot = {
                    "timeout_seconds": int(params["timeout_seconds"]),
                    "max_domains": int(params["max_domains"]),
                    "concurrency": int(params["concurrency"]),
                    "dns_timeout_seconds": int(params["dns_timeout_seconds"]),
                    "preflight_timeout_seconds": int(params["preflight_timeout_seconds"]),
                    "retries": int(params["retries"]),
                    "backoff_seconds": float(params["backoff_seconds"]),
                    "public_dns_raw": str(params.get("public_dns_raw") or ",".join(PUBLIC_DNS_SERVERS)),
                    "local_dns_raw": str(params.get("local_dns_raw") or ""),
                    "enable_trace": bool(params.get("enable_trace", True)),
                    "enable_step3": bool(params.get("enable_step3", True)),
                    "browser_headed": bool(params.get("browser_headed", True)),
                    "browser_profile": str(params.get("browser_profile") or "edge"),
                    "enable_phase2": bool(params.get("enable_phase2", False)),
                    "phase2_timeout_seconds": int(params.get("phase2_timeout_seconds") or 60),
                    "coccoc_user_data": str(params.get("coccoc_user_data") or ""),
                    "edge_user_data": str(params.get("edge_user_data") or ""),
                    "chrome_user_data": str(params.get("chrome_user_data") or ""),
                }
                entry_payload = {
                    "df_csv": live_df.to_csv(index=False, na_rep=""),
                    "elapsed": float(elapsed_seconds),
                    "upload_stem": upload_stem,
                    "preflight": params["preflight"],
                    "form_snapshot": form_snapshot,
                }
                rid = _store_result(entry_payload)
                stored = _result_store.get(rid) or entry_payload
                item = _saved_result_item(rid, stored)
                await q.put(("done", rid, float(elapsed_seconds), item))
            except Exception as ex:
                msg = str(ex).strip() or type(ex).__name__
                await q.put(("fatal", msg))

        yield _sse_encode(
            "meta",
            {"total": total_planned, "preflight": params["preflight"]},
        )
        task = asyncio.create_task(worker())
        try:
            while True:
                item = await q.get()
                if item[0] == "row":
                    _, row, done, tot = item
                    yield _sse_encode("row", {"row": row, "done": done, "total": tot})
                elif item[0] == "patch":
                    _, row, tot = item
                    yield _sse_encode("row_patch", {"row": row, "total": tot})
                elif item[0] == "empty":
                    yield _sse_encode("error", {"message": "Không có domain hợp lệ để kiểm thử."})
                    break
                elif item[0] == "done":
                    _, rid, elapsed, saved_item = item
                    yield _sse_encode(
                        "complete",
                        {
                            "result_id": rid,
                            "elapsed_seconds": elapsed,
                            "saved_item": saved_item,
                        },
                    )
                    break
                elif item[0] == "fatal":
                    yield _sse_encode("error", {"message": item[1]})
                    break
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _plotly_div(summary: dict[str, int]) -> str:
    fig = live_pie_chart(summary)
    return fig.to_html(full_html=False, include_plotlyjs="cdn", config={"displayModeBar": True})


def _enrich_table_row(row: dict[str, Any]) -> dict[str, Any]:
    """Tiền render HTML cột link/TLS — không phụ thuộc Jinja filter khi hot-reload."""
    r = dict(row)
    r["_domain_html"] = cell_link_html(str(r.get(COL_ORIGINAL) or ""))
    if not r.get("_tls_html"):
        tls_text = str(r.get(COL_TLS) or "").strip()
        if tls_text:
            r["_tls_html"] = tls_column_to_html(tls_text)
    return r


async def _results_template_context(request: Request, result_id: str, q: str = "") -> dict[str, Any]:
    entry = _get_result(result_id)
    df = _df_from_store(entry)
    current_public_ip = await detect_public_ip_async(timeout=3)
    summary = _summary_from_df(df)
    filtered = _filter_df_by_search(df, q)
    chart_div = _plotly_div(summary)
    state_options = ["ALL", STATUS_BLOCKED, STATUS_LEAKED, STATUS_TIMEOUT, STATUS_DEAD]
    snap = entry.get("form_snapshot") or {}
    return {
        "request": request,
        "result_id": result_id,
        "live_df": df,
        "table_rows": [_enrich_table_row(r) for r in filtered.to_dict(orient="records")],
        "summary": summary,
        "elapsed_seconds": entry["elapsed"],
        "preflight": entry.get("preflight"),
        "chart_div": chart_div,
        "q": q,
        "total_rows": len(df),
        "shown_rows": len(filtered),
        "state_options": state_options,
        "export_state_defs": EXPORT_STATE_DEFS,
        "COL_ORIGINAL": COL_ORIGINAL,
        "COL_DNS": COL_DNS,
        "COL_FINAL_VI": COL_FINAL_VI,
        "COL_RESULT_SOURCE": COL_RESULT_SOURCE,
        "COL_TCP_80": COL_TCP_80,
        "COL_TCP_443": COL_TCP_443,
        "COL_HTTP": COL_HTTP,
        "COL_HTTP_VER": COL_HTTP_VER,
        "COL_TLS": COL_TLS,
        "COL_CHAIN": COL_CHAIN,
        "COL_PLAYWRIGHT_ERR": COL_PLAYWRIGHT_ERR,
        "COL_LATENCY": COL_LATENCY,
        "COL_TRACE": COL_TRACE,
        "current_public_ip": current_public_ip,
        "expected_guest_ip": EXPECTED_GUEST_IP,
        "form_http_timeout": int(snap.get("timeout_seconds", DEFAULT_UI_HTTP_TIMEOUT)),
        "form_max_domains": int(snap.get("max_domains", 1000)),
        "default_public_dns": snap.get("public_dns_raw") or ",".join(PUBLIC_DNS_SERVERS),
        "default_local_dns": snap.get("local_dns_raw")
        or os.environ.get("PROBE_LOCAL_DNS", DEFAULT_LOCAL_DNS),
        "default_concurrency": int(snap.get("concurrency", ASYNC_CONCURRENCY)),
        "default_dns_timeout": int(snap.get("dns_timeout_seconds", DNS_TIMEOUT_SECONDS)),
        "default_preflight_timeout": int(snap.get("preflight_timeout_seconds", PREFLIGHT_TIMEOUT_SECONDS)),
        "default_retries": int(snap.get("retries", HTTP_RETRIES)),
        "default_backoff": float(snap.get("backoff_seconds", BACKOFF_BASE_SECONDS)),
        "form_enable_trace": bool(snap.get("enable_trace", True)),
        "form_enable_step3": bool(snap.get("enable_step3", True)),
        "form_browser_headed": bool(snap.get("browser_headed", True)),
        "form_enable_phase2": bool(snap.get("enable_phase2", True)),
        "form_browser_profile": str(snap.get("browser_profile") or "edge"),
        "default_coccoc_user_data": snap.get("coccoc_user_data")
        or os.environ.get(
            COCCOC_USER_DATA_ENV,
            DEFAULT_COCCOC_USER_DATA_DIR,
        ),
        "default_edge_user_data": snap.get("edge_user_data")
        or os.environ.get(
            EDGE_USER_DATA_ENV,
            DEFAULT_EDGE_USER_DATA_DIR,
        ),
        "default_chrome_user_data": snap.get("chrome_user_data")
        or os.environ.get(
            CHROME_USER_DATA_ENV,
            DEFAULT_CHROME_USER_DATA_DIR,
        ),
        "export_column_defs": EXPORT_COLUMN_DEFS,
        "export_state_defs": EXPORT_STATE_DEFS,
        "home_url": "/",
    }


@app.get("/results/{result_id}", response_class=HTMLResponse)
async def results_get(request: Request, result_id: str, q: str = ""):
    ctx = await _results_template_context(request, result_id, q=q)
    return templates.TemplateResponse(
        request=request,      # Tham số bắt buộc ở phiên bản mới
        name="results.html",  # Tên file template
        context=ctx           # Dictionary chứa dữ liệu
    )


def _export_df_for_entry(
    entry: dict[str, Any],
    states: Optional[list[str]],
) -> pd.DataFrame:
    df = _df_from_store(entry)
    if states:
        status = _export_status_series(df)
        df = df[status.isin(states)]
    return df


def _subset_export_columns(df: pd.DataFrame, cols_param: Optional[str]) -> pd.DataFrame:
    if not cols_param or not str(cols_param).strip():
        keys = [k for k in EXPORT_DEFAULT_KEYS if k in df.columns]
        return df[keys] if keys else df
    keys: list[str] = []
    for slug in str(cols_param).split(","):
        slug = slug.strip()
        k = EXPORT_SLUG_TO_KEY.get(slug)
        if k and k in df.columns and k not in keys:
            keys.append(k)
    if not keys:
        keys = [k for k in EXPORT_DEFAULT_KEYS if k in df.columns]
    if not keys and len(df.columns):
        keys = list(df.columns)
    return df[keys] if keys else df


@app.get("/export/{result_id}/csv")
async def export_csv(result_id: str, state: str = "ALL", cols: str = ""):
    entry = _get_result(result_id)
    states = _parse_export_states(state)
    df = _export_df_for_entry(entry, states)
    df = _subset_export_columns(df, cols)
    body = df.to_csv(index=False, na_rep="").encode("utf-8-sig")
    fname = f"{_export_file_base_name(entry, state)}.csv"
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": _attachment_content_disposition(fname)},
    )


@app.get("/export/{result_id}/txt")
async def export_txt(result_id: str, state: str = "ALL", cols: str = ""):
    entry = _get_result(result_id)
    states = _parse_export_states(state)
    df = _export_df_for_entry(entry, states)
    df = _subset_export_columns(df, cols)
    body = df.to_csv(index=False, sep="\t", na_rep="").encode("utf-8-sig")
    fname = f"{_export_file_base_name(entry, state)}.txt"
    return Response(
        content=body,
        media_type="text/plain",
        headers={"Content-Disposition": _attachment_content_disposition(fname)},
    )
