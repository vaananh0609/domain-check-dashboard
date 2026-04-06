from __future__ import annotations

import asyncio
import io
import json
import re
import uuid
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from live.parsing import browse_url_for_cell

from dynamic_live_core import (
    COL_CHAIN,
    COL_DETAIL,
    COL_DNS,
    COL_FINAL_URL,
    COL_FINAL_VI,
    COL_HTTP,
    COL_TLS,
    COL_ORIGINAL,
    DNS_TIMEOUT_SECONDS,
    EXPECTED_GUEST_IP,
    HTTP_RETRIES,
    PREFLIGHT_TIMEOUT_SECONDS,
    PUBLIC_DNS_SERVERS,
    STATUS_BLOCKED,
    STATUS_DEAD,
    STATUS_LEAKED,
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

BASE_DIR = str(Path(__file__).resolve().parent)

# Slug ngắn cho URL; thứ tự mặc định khi xuất đủ cột
EXPORT_COLUMN_DEFS: list[dict[str, str]] = [
    {"slug": "stt", "key": "STT", "label": "STT"},
    {"slug": "goc", "key": COL_ORIGINAL, "label": COL_ORIGINAL},
    {"slug": "trang_thai_cuoi", "key": COL_FINAL_VI, "label": COL_FINAL_VI},
    {"slug": "ma_http", "key": COL_HTTP, "label": COL_HTTP},
    {"slug": "tls", "key": COL_TLS, "label": COL_TLS},
    {"slug": "chuoi", "key": COL_CHAIN, "label": COL_CHAIN},
    {"slug": "url_dich", "key": COL_FINAL_URL, "label": COL_FINAL_URL},
    {"slug": "dns", "key": COL_DNS, "label": COL_DNS},
    {"slug": "detail", "key": COL_DETAIL, "label": COL_DETAIL},
    {"slug": "status", "key": "Trạng_Thái", "label": "Trạng_Thái (mã nội bộ)"},
]
EXPORT_SLUG_TO_KEY = {d["slug"]: d["key"] for d in EXPORT_COLUMN_DEFS}

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
    """Tiền tố file xuất khi lọc theo state (ALL = không thêm)."""
    if not export_state or export_state == "ALL":
        return ""
    m = {
        STATUS_BLOCKED: "blocked",
        STATUS_LEAKED: "leaked",
        STATUS_DEAD: "dead",
    }
    if export_state in m:
        return m[export_state] + "_"
    safe = re.sub(r"[^\w]+", "_", str(export_state).lower()).strip("_")
    return (safe + "_") if safe else ""


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
app.mount("/static", StaticFiles(directory=f"{BASE_DIR}/static"), name="static")
templates = Jinja2Templates(directory=f"{BASE_DIR}/templates")

# Lưu kết quả trong RAM (dùng local / single-user)
_MAX_STORE = 64
_result_store: "OrderedDict[str, dict[str, Any]]" = OrderedDict()


def _store_result(payload: dict[str, Any]) -> str:
    rid = str(uuid.uuid4())
    if len(_result_store) >= _MAX_STORE:
        _result_store.popitem(last=False)
    _result_store[rid] = payload
    return rid


def _get_result(rid: str) -> dict[str, Any]:
    if rid not in _result_store:
        raise HTTPException(status_code=404, detail="Không tìm thấy phiên kết quả (có thể đã hết hạn).")
    _result_store.move_to_end(rid)
    return _result_store[rid]


def _df_from_store(entry: dict[str, Any]) -> pd.DataFrame:
    df = pd.read_csv(
        io.StringIO(entry["df_csv"]),
        keep_default_na=False,
    )
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
    if COL_FINAL_URL in df.columns:
        m2 = df[COL_FINAL_URL].astype(str).str.lower().str.contains(kw, na=False)
        return df[m1 | m2]
    return df[m1]


def status_row_class(status: str) -> str:
    return {
        STATUS_BLOCKED: "blocked",
        STATUS_LEAKED: "leaked",
        STATUS_DEAD: "dead",
    }.get(status, "")


templates.env.filters["status_row_class"] = status_row_class
templates.env.filters["urlquote"] = lambda s: quote(str(s or ""), safe="")
templates.env.filters["browse_url"] = lambda s: browse_url_for_cell(str(s or ""))


def _sse_encode(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n".encode("utf-8")


async def _prepare_live_run(request: Request) -> tuple[Optional[dict[str, Any]], Optional[str], dict[str, Any]]:
    current_public_ip = await detect_public_ip_async(timeout=3)
    defaults = {
        "default_public_dns": ",".join(PUBLIC_DNS_SERVERS),
        "default_concurrency": ASYNC_CONCURRENCY,
        "default_dns_timeout": DNS_TIMEOUT_SECONDS,
        "default_preflight_timeout": PREFLIGHT_TIMEOUT_SECONDS,
        "default_retries": HTTP_RETRIES,
        "default_backoff": BACKOFF_BASE_SECONDS,
        "current_public_ip": current_public_ip,
        "expected_guest_ip": EXPECTED_GUEST_IP,
        "COL_ORIGINAL": COL_ORIGINAL,
        "COL_FINAL_VI": COL_FINAL_VI,
        "COL_HTTP": COL_HTTP,
        "COL_TLS": COL_TLS,
        "COL_CHAIN": COL_CHAIN,
        "COL_FINAL_URL": COL_FINAL_URL,
        "COL_DNS": COL_DNS,
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
        timeout_seconds = int(form.get("timeout_seconds") or DEFAULT_UI_HTTP_TIMEOUT)
    except (TypeError, ValueError):
        timeout_seconds = DEFAULT_UI_HTTP_TIMEOUT
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
    active_public_dns = parse_dns_servers(public_dns_raw)
    preflight = await run_network_preflight(
        active_public_dns,
        dns_timeout=int(dns_timeout_seconds),
        timeout=int(preflight_timeout_seconds),
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
        "public_dns_raw": public_dns_raw,
        "preflight": preflight,
        "current_public_ip": current_public_ip,
        "preflight_timeout_seconds": preflight_timeout_seconds,
    }

    return params, None, defaults


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    current_public_ip = await detect_public_ip_async(timeout=3)
    return templates.TemplateResponse(
    request=request,  # Đưa request ra ngoài làm tham số riêng (BẮT BUỘC)
    name="index.html", 
    context={          
        "current_public_ip": current_public_ip,
        "expected_guest_ip": EXPECTED_GUEST_IP,
        "default_public_dns": ",".join(PUBLIC_DNS_SERVERS),
        "default_concurrency": ASYNC_CONCURRENCY,
        "default_dns_timeout": DNS_TIMEOUT_SECONDS,
        "default_preflight_timeout": PREFLIGHT_TIMEOUT_SECONDS,
        "default_retries": HTTP_RETRIES,
        "default_backoff": BACKOFF_BASE_SECONDS,
        "error": None,
        "COL_ORIGINAL": COL_ORIGINAL,
        "COL_FINAL_VI": COL_FINAL_VI,
        "COL_HTTP": COL_HTTP,
        "COL_TLS": COL_TLS,
        "COL_CHAIN": COL_CHAIN,
        "COL_FINAL_URL": COL_FINAL_URL,
        "COL_DNS": COL_DNS,
        "COL_DETAIL": COL_DETAIL,
        },
    )


@app.post("/run", response_class=HTMLResponse)
async def run_live(request: Request):
    params, err, defaults = await _prepare_live_run(request)
    if err:
        return templates.TemplateResponse(
            "index.html",
            {**defaults, "request": request, "error": err},
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
    )

    if live_df.empty:
        return templates.TemplateResponse(
            "index.html",
            {**defaults, "request": request, "error": "Không có domain hợp lệ để kiểm thử."},
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
    return RedirectResponse(url=f"/results/{rid}", status_code=303)


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
                    on_row=on_row,
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
                await q.put(("done", rid, float(elapsed_seconds)))
            except Exception as ex:
                await q.put(("fatal", str(ex)))

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
                elif item[0] == "empty":
                    yield _sse_encode("error", {"message": "Không có domain hợp lệ để kiểm thử."})
                    break
                elif item[0] == "done":
                    _, rid, elapsed = item
                    yield _sse_encode("complete", {"result_id": rid, "elapsed_seconds": elapsed})
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


async def _results_template_context(request: Request, result_id: str, q: str = "") -> dict[str, Any]:
    entry = _get_result(result_id)
    df = _df_from_store(entry)
    current_public_ip = await detect_public_ip_async(timeout=3)
    summary = {
        STATUS_BLOCKED: int((df["Trạng_Thái"] == STATUS_BLOCKED).sum()),
        STATUS_LEAKED: int((df["Trạng_Thái"] == STATUS_LEAKED).sum()),
        STATUS_DEAD: int((df["Trạng_Thái"] == STATUS_DEAD).sum()),
    }
    filtered = _filter_df_by_search(df, q)
    chart_div = _plotly_div(summary)
    state_options = ["ALL", STATUS_BLOCKED, STATUS_LEAKED, STATUS_DEAD]
    snap = entry.get("form_snapshot") or {}
    return {
        "request": request,
        "result_id": result_id,
        "live_df": df,
        "table_rows": filtered.to_dict(orient="records"),
        "summary": summary,
        "elapsed_seconds": entry["elapsed"],
        "preflight": entry.get("preflight"),
        "chart_div": chart_div,
        "q": q,
        "total_rows": len(df),
        "shown_rows": len(filtered),
        "state_options": state_options,
        "COL_ORIGINAL": COL_ORIGINAL,
        "COL_FINAL_VI": COL_FINAL_VI,
        "COL_HTTP": COL_HTTP,
        "COL_TLS": COL_TLS,
        "COL_CHAIN": COL_CHAIN,
        "COL_FINAL_URL": COL_FINAL_URL,
        "COL_DNS": COL_DNS,
        "COL_DETAIL": COL_DETAIL,
        "current_public_ip": current_public_ip,
        "expected_guest_ip": EXPECTED_GUEST_IP,
        "form_http_timeout": int(snap.get("timeout_seconds", DEFAULT_UI_HTTP_TIMEOUT)),
        "form_max_domains": int(snap.get("max_domains", 1000)),
        "default_public_dns": snap.get("public_dns_raw") or ",".join(PUBLIC_DNS_SERVERS),
        "default_concurrency": int(snap.get("concurrency", ASYNC_CONCURRENCY)),
        "default_dns_timeout": int(snap.get("dns_timeout_seconds", DNS_TIMEOUT_SECONDS)),
        "default_preflight_timeout": int(snap.get("preflight_timeout_seconds", PREFLIGHT_TIMEOUT_SECONDS)),
        "default_retries": int(snap.get("retries", HTTP_RETRIES)),
        "default_backoff": float(snap.get("backoff_seconds", BACKOFF_BASE_SECONDS)),
        "export_column_defs": EXPORT_COLUMN_DEFS,
    }


@app.get("/results/{result_id}", response_class=HTMLResponse)
async def results_get(request: Request, result_id: str, q: str = ""):
    ctx = await _results_template_context(request, result_id, q=q)
    return templates.TemplateResponse(
        request=request,      # Tham số bắt buộc ở phiên bản mới
        name="results.html",  # Tên file template
        context=ctx           # Dictionary chứa dữ liệu
    )


def _export_df_for_entry(entry: dict[str, Any], state: Optional[str], q: str) -> pd.DataFrame:
    df = _df_from_store(entry)
    df = _filter_df_by_search(df, q)
    if state and state != "ALL":
        df = df[df["Trạng_Thái"] == state]
    return df


def _subset_export_columns(df: pd.DataFrame, cols_param: Optional[str]) -> pd.DataFrame:
    if not cols_param or not str(cols_param).strip():
        return df
    keys: list[str] = []
    for slug in str(cols_param).split(","):
        slug = slug.strip()
        k = EXPORT_SLUG_TO_KEY.get(slug)
        if k and k in df.columns and k not in keys:
            keys.append(k)
    if not keys:
        return df
    return df[keys]


@app.get("/export/{result_id}/csv")
async def export_csv(result_id: str, state: str = "ALL", q: str = "", cols: str = ""):
    entry = _get_result(result_id)
    df = _export_df_for_entry(entry, state if state != "ALL" else None, q=q)
    df = _subset_export_columns(df, cols)
    body = df.to_csv(index=False, na_rep="").encode("utf-8-sig")
    fname = f"{_export_file_base_name(entry, state)}.csv"
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": _attachment_content_disposition(fname)},
    )


@app.get("/export/{result_id}/txt")
async def export_txt(result_id: str, state: str = "ALL", q: str = "", cols: str = ""):
    entry = _get_result(result_id)
    df = _export_df_for_entry(entry, state if state != "ALL" else None, q=q)
    df = _subset_export_columns(df, cols)
    body = df.to_csv(index=False, sep="\t", na_rep="").encode("utf-8-sig")
    fname = f"{_export_file_base_name(entry, state)}.txt"
    return Response(
        content=body,
        media_type="text/plain",
        headers={"Content-Disposition": _attachment_content_disposition(fname)},
    )
