import io
import importlib
import ipaddress
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict
from urllib.parse import urlsplit

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from requests.exceptions import ConnectionError, Timeout
from urllib3.exceptions import InsecureRequestWarning

with st.sidebar:
    st.markdown("### Điều hướng")
    st.page_link("app.py", label="Trang chủ", icon="🏠")
    st.page_link("pages/1_Static_Analysis.py", label="Static Analysis", icon="📊")
    st.page_link("pages/2_Dynamic_Live_Testing.py", label="Dynamic Live Testing", icon="🌐")

st.markdown(
    """
<style>
[data-testid="stSidebar"] {
    background: linear-gradient(160deg, #0f3d66 0%, #155c8f 55%, #1f8ca8 100%);
    border-right: 1px solid rgba(255, 255, 255, 0.2);
}

[data-testid="stSidebar"] .stMarkdown h3 {
    color: #f4fbff;
    font-weight: 700;
    letter-spacing: 0.3px;
}

[data-testid="stSidebar"] a {
    color: #eaf6ff !important;
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.24);
    border-radius: 10px;
    padding: 0.42rem 0.65rem;
    margin: 0.22rem 0;
    text-decoration: none !important;
    transition: all 0.18s ease-in-out;
}

[data-testid="stSidebar"] a p,
[data-testid="stSidebar"] a span,
[data-testid="stSidebar"] [data-testid="stPageLink"] p,
[data-testid="stSidebar"] [data-testid="stPageLink"] span {
    color: #ffffff !important;
}

[data-testid="stSidebar"] a:hover {
    background: rgba(255, 255, 255, 0.28);
    color: #ffffff !important;
    transform: translateX(2px);
}

[data-testid="stSidebar"] a[aria-current="page"] {
    background: #ffffff;
    color: #0f4c81 !important;
    font-weight: 700;
    border-color: #ffffff;
    box-shadow: 0 5px 16px rgba(0, 0, 0, 0.15);
}

[data-testid="stSidebar"] a[aria-current="page"] p,
[data-testid="stSidebar"] a[aria-current="page"] span {
    color: #0f4c81 !important;
    font-weight: 700;
}
</style>
""",
    unsafe_allow_html=True,
)

try:
    aggrid_module = importlib.import_module("st_aggrid")
    aggrid_shared_module = importlib.import_module("st_aggrid.shared")
    AgGrid = aggrid_module.AgGrid
    GridOptionsBuilder = aggrid_module.GridOptionsBuilder
    JsCode = aggrid_shared_module.JsCode
    AGGRID_AVAILABLE = True
except Exception:
    AgGrid = None
    GridOptionsBuilder = None
    JsCode = None
    AGGRID_AVAILABLE = False

STATUS_BLOCKED = "BLOCKED"
STATUS_LEAKED = "LEAKED"
STATUS_DEAD = "DEAD DOMAIN"


def register_pdf_vietnamese_font() -> bool:
    # Try common system fonts and register under a single name 'VietFont'
    font_candidates = [
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\times.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/DejaVuSans.ttf",
    ]
    viet_font_registered = False
    for path in font_candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont("VietFont", path))
                viet_font_registered = True
                break
            except Exception:
                continue
    return viet_font_registered


viet_font_registered = register_pdf_vietnamese_font()
PDF_FONT_NAME = "VietFont" if viet_font_registered else "Helvetica"

IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def read_uploaded_text_lines(uploaded_file) -> list[str]:
    raw = uploaded_file.getvalue()
    if not raw:
        return []

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="ignore")

    rows = []
    for line in text.splitlines():
        val = line.strip()
        if not val:
            continue
        rows.append(val)
    return rows


def normalize_target(raw_value: str) -> str:
    value = raw_value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]

    if "@" in value:
        value = value.rsplit("@", 1)[-1]

    if ":" in value and value.count(":") == 1:
        host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            value = host

    return value.rstrip(".")


def is_ipv4(value: str) -> bool:
    if not IPV4_REGEX.match(value):
        return False
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def can_resolve_dns(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def extract_host_and_urls(raw_target: str) -> tuple[str, list[str]]:
    original = raw_target.strip()
    if not original:
        return "", []

    # Keep the original input for display; parse only for request behavior.
    if "://" in original:
        parsed = urlsplit(original)
        host = parsed.hostname or ""
        urls = [original]
    else:
        parsed = urlsplit(f"//{original}")
        host = parsed.hostname or parsed.netloc or ""
        urls = [f"https://{original}", f"http://{original}"]

    return host.strip().rstrip("."), urls


def classify_live_domain(raw_target: str, timeout: int) -> str:
    host, urls = extract_host_and_urls(raw_target)

    if not host or not urls:
        return STATUS_DEAD

    if is_ipv4(host):
        return STATUS_BLOCKED

    if not can_resolve_dns(host):
        return STATUS_DEAD

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "GatewayLiveTester/1.0"},
            )
            if response.status_code in {200, 301, 302}:
                return STATUS_LEAKED
            return STATUS_LEAKED
        except Timeout:
            return STATUS_BLOCKED
        except ConnectionError:
            return STATUS_BLOCKED
        except Exception:
            continue

    return STATUS_BLOCKED


def run_live_test_from_lines(lines: list[str], timeout: int, max_domains: int) -> tuple[pd.DataFrame, float]:
    raw_targets = [line.strip() for line in lines if line.strip()]

    if not raw_targets:
        return pd.DataFrame(columns=["STT", "Domain", "Trạng_Thái"]), 0.0

    limited_targets = raw_targets[:max_domains]
    total = len(limited_targets)
    start_time = time.perf_counter()

    progress_bar = st.progress(0, text="Bắt đầu kiểm thử live với multithreading...")
    progress_text = st.empty()
    
    # Dictionary to store results in order
    results = {}
    completed_count = 0
    
    # Use ThreadPoolExecutor with 50 workers for parallel testing
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Map each domain to a future
        future_to_domain = {
            executor.submit(classify_live_domain, domain, timeout): (idx, domain)
            for idx, domain in enumerate(limited_targets, start=1)
        }
        
        # Process completed futures as they finish
        for future in as_completed(future_to_domain):
            idx, domain = future_to_domain[future]
            try:
                status = future.result(timeout=timeout + 5)
                results[idx] = {"STT": idx, "Domain": domain, "Trạng_Thái": status}
                completed_count += 1
                
                # Update progress
                progress = completed_count / total
                progress_bar.progress(progress, text=f"Đang test {completed_count}/{total}...")
                progress_text.text(f"Hoàn thành: {completed_count}/{total} domain")
            except Exception as e:
                results[idx] = {"STT": idx, "Domain": domain, "Trạng_Thái": STATUS_BLOCKED}
                completed_count += 1
                progress = completed_count / total
                progress_bar.progress(progress, text=f"Đang test {completed_count}/{total}...")

    progress_bar.progress(1.0, text="Đã hoàn tất kiểm thử live.")
    progress_text.empty()
    elapsed_seconds = time.perf_counter() - start_time
    
    # Sort results by STT and convert to DataFrame
    sorted_results = [results[i] for i in sorted(results.keys())]
    return pd.DataFrame(sorted_results), elapsed_seconds


def live_pie_chart(summary: Dict[str, int]):
    data = pd.DataFrame({"Trạng thái": list(summary.keys()), "Số lượng": list(summary.values())})
    color_map = {
        STATUS_BLOCKED: "#2e7d32",
        STATUS_LEAKED: "#c62828",
        STATUS_DEAD: "#9e9e9e",
    }

    fig = px.pie(
        data,
        names="Trạng thái",
        values="Số lượng",
        color="Trạng thái",
        color_discrete_map=color_map,
        title="Tỷ lệ kiểm thử live Gateway",
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    fig.update_layout(margin=dict(l=10, r=10, t=60, b=10))
    return fig


def to_excel_bytes(df: pd.DataFrame, sheet_name: str) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)
    output.seek(0)
    return output.getvalue()


MM_TO_PT = 2.83465
LEFT_MARGIN_PT = 32 * MM_TO_PT  # 32mm
RIGHT_MARGIN_PT = 18 * MM_TO_PT  # 18mm
TOP_MARGIN_PT = 22 * MM_TO_PT  # 22mm
BOTTOM_MARGIN_PT = 22 * MM_TO_PT  # 22mm


def build_pdf_pie_chart(summary: Dict[str, int], avail_width: float = None) -> Drawing:
    # Build a drawing sized to available width and center the pie chart inside it
    if avail_width is None:
        page_width = A4[0]
        avail_width = page_width - LEFT_MARGIN_PT - RIGHT_MARGIN_PT
    drawing_width = max(300, avail_width)
    drawing = Drawing(drawing_width, 260)
    total = (
        summary.get(STATUS_BLOCKED, 0)
        + summary.get(STATUS_LEAKED, 0)
        + summary.get(STATUS_DEAD, 0)
    )

    if total <= 0:
        drawing.add(String(drawing_width / 2 - 100, 130, "Không có dữ liệu để vẽ biểu đồ", fontSize=12, fontName=PDF_FONT_NAME))
        return drawing

    pie = Pie()
    # center pie inside drawing
    pie_size = min(240, drawing_width * 0.45)
    pie.width = pie_size
    pie.height = pie_size
    pie.x = (drawing_width - pie_size) / 2
    pie.y = 20
    pie.data = [summary.get(STATUS_BLOCKED, 0), summary.get(STATUS_LEAKED, 0), summary.get(STATUS_DEAD, 0)]
    pie.labels = [
        f"BLOCKED ({summary.get(STATUS_BLOCKED, 0)})",
        f"LEAKED ({summary.get(STATUS_LEAKED, 0)})",
        f"DEAD DOMAIN ({summary.get(STATUS_DEAD, 0)})",
    ]
    pie.slices[0].fillColor = colors.HexColor("#A5D6A7")
    pie.slices[1].fillColor = colors.HexColor("#FFCDD2")
    pie.slices[2].fillColor = colors.HexColor("#CFD8DC")
    pie.slices.strokeWidth = 0.5
    pie.sideLabels = True
    drawing.add(String(drawing_width / 2 - 80, 235, "Biểu đồ tỷ lệ trạng thái", fontSize=12, fontName=PDF_FONT_NAME))
    drawing.add(pie)
    return drawing


def to_pdf_bytes(df: pd.DataFrame, summary: Dict[str, int], elapsed_seconds: float) -> bytes:

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=RIGHT_MARGIN_PT,
        leftMargin=LEFT_MARGIN_PT,
        topMargin=TOP_MARGIN_PT,
        bottomMargin=BOTTOM_MARGIN_PT,
    )
    styles = getSampleStyleSheet()
    centered_title_style = ParagraphStyle(
        "CenteredTitle",
        parent=styles["Title"],
        fontName=PDF_FONT_NAME,
        alignment=TA_CENTER,
    )
    centered_info_style = ParagraphStyle(
        "CenteredInfo",
        parent=styles["Normal"],
        fontName=PDF_FONT_NAME,
        alignment=TA_CENTER,
        leading=15,
    )
    table_style_font = PDF_FONT_NAME if PDF_FONT_NAME != "Helvetica" else "Helvetica"
    elements = [Paragraph("BÁO CÁO THỐNG KÊ TRẠNG THÁI CHẶN/LỌC TÊN MIỀN", centered_title_style), Spacer(1, 10)]

    info_text = (
        f"Tổng domain: {len(df):,} | BLOCKED: {summary.get(STATUS_BLOCKED, 0):,} | "
        f"LEAKED: {summary.get(STATUS_LEAKED, 0):,} | DEAD DOMAIN: {summary.get(STATUS_DEAD, 0):,} | "
        f"Thời gian chạy: {elapsed_seconds:.2f} giây"
    )
    elements.append(Paragraph(info_text, centered_info_style))
    elements.append(Spacer(1, 10))
    # center the pie chart using available width
    avail_width = A4[0] - LEFT_MARGIN_PT - RIGHT_MARGIN_PT
    elements.append(build_pdf_pie_chart(summary, avail_width=avail_width))
    elements.append(Spacer(1, 14))

    max_rows = 1000000
    safe_df = df.head(max_rows).copy()

    # Prepare table with Paragraphs to support wrapping and Vietnamese font
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle(
        "cell",
        parent=styles["Normal"],
        fontName=PDF_FONT_NAME,
        fontSize=8,
        leading=10,
    )
    header_style = ParagraphStyle(
        "header",
        parent=styles["Normal"],
        fontName=PDF_FONT_NAME,
        fontSize=9,
        leading=11,
        alignment=TA_CENTER,
    )

    headers = [str(h) for h in safe_df.columns]
    table_data = [[Paragraph(h, header_style) for h in headers]]
    for _, row in safe_df.iterrows():
        table_data.append([Paragraph(str(v), cell_style) for v in row.values.tolist()])

    if safe_df.empty:
        elements.append(Paragraph("Không có dữ liệu theo State đã chọn để xuất báo cáo.", centered_info_style))
        doc.build(elements)
        output.seek(0)
        return output.getvalue()

    # Auto-fit column widths based on max text length per column
    num_cols = len(headers)
    text_max = [0] * num_cols
    for r in table_data:
        for i, c in enumerate(r):
            txt = getattr(c, 'text', str(c))
            text_max[i] = max(text_max[i], len(txt))

    avail_width = A4[0] - LEFT_MARGIN_PT - RIGHT_MARGIN_PT
    total = sum(text_max) if sum(text_max) > 0 else num_cols
    col_widths = []
    min_w = 40
    for t in text_max:
        w = max(min_w, avail_width * (t / total))
        col_widths.append(w)

    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    table_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), table_style_font),
        ("FONTNAME", (0, 1), (-1, -1), table_style_font),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]

    if "Trạng_Thái" in safe_df.columns:
        for row_idx, status in enumerate(safe_df["Trạng_Thái"].tolist(), start=1):
            if status == STATUS_BLOCKED:
                table_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#A5D6A7")))
                table_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#1B5E20")))
            elif status == STATUS_LEAKED:
                table_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#FFCDD2")))
                table_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#B71C1C")))
            elif status == STATUS_DEAD:
                table_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#CFD8DC")))
                table_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#455A64")))

    table.setStyle(TableStyle(table_styles))
    elements.append(table)
    doc.build(elements)
    output.seek(0)
    return output.getvalue()


def render_live_table(df: pd.DataFrame) -> None:
    if not AGGRID_AVAILABLE:
        st.info("Để có bảng có search/filter tốt hơn, vui lòng cài streamlit-aggrid.")
        st.dataframe(df, use_container_width=True, height=460)
        return

    status_row_style = JsCode(
        """
        function(params) {
            const status = params.data && params.data["Trạng_Thái"] ? params.data["Trạng_Thái"] : "";
            if (status === "BLOCKED") {
                return {
                    'backgroundColor': '#A5D6A7',
                    'color': '#1B5E20',
                    'fontWeight': '500'
                };
            }
            if (status === "LEAKED") {
                return {
                    'backgroundColor': '#FFCDD2',
                    'color': '#B71C1C',
                    'fontWeight': '500'
                };
            }
            if (status === "DEAD DOMAIN") {
                return {
                    'backgroundColor': '#CFD8DC',
                    'color': '#455A64',
                    'fontWeight': '500'
                };
            }
            return null;
        }
        """
    )

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(
        wrapText=True,
        autoHeight=True,
        resizable=True,
        sortable=True,
        filter=True,
    )
    gb.configure_column("STT", width=90)
    gb.configure_column("Domain", width=320)
    gb.configure_column("Trạng_Thái", width=180)
    gb.configure_grid_options(suppressRowTransform=True, quickFilterText="", getRowStyle=status_row_style)

    AgGrid(
        df,
        gridOptions=gb.build(),
        fit_columns_on_grid_load=False,
        theme="streamlit",
        height=500,
        allow_unsafe_jscode=True,
    )


def main():
    st.title("Dynamic Live Testing")
    st.caption("Chạy kiểm thử trực tiếp trên giao diện để đánh giá tỷ lệ chặn thực tế của Gateway")
    
    # Modern CSS for the page
    st.markdown("""
    <style>
        .main {
            background: linear-gradient(180deg, #ffffff 0%, #f8f9fa 100%);
        }

        .block-container {
            max-width: 1280px;
            margin: 0 auto;
            padding-top: 2.8rem;
            padding-left: 1rem;
            padding-right: 1rem;
        }
        
        [data-testid="stMetricDelta"] {
            display: none;
        }
        
        .metric-card {
            background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(30, 136, 229, 0.05) 100%);
            border: 1px solid rgba(0, 188, 212, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        .section-title {
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(135deg, #00BCD4 0%, #1E88E5 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-top: 2rem;
            margin-bottom: 1rem;
            letter-spacing: -0.5px;
        }
        
        .stFileUploader {
            border: 2px dashed #00BCD4 !important;
            border-radius: 12px !important;
            padding: 1.5rem !important;
            background: rgba(0, 188, 212, 0.05) !important;
            transition: all 0.3s ease;
        }
        
        .stFileUploader:hover {
            background: rgba(0, 188, 212, 0.1) !important;
            border-color: #1E88E5 !important;
        }
        
        .stButton > button {
            border-radius: 8px;
            font-weight: 600;
            padding: 0.6rem 1.5rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border: none;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 188, 212, 0.3);
        }
        
        .stButton > button[type="primary"] {
            background: linear-gradient(135deg, #00BCD4 0%, #0097A7 100%) !important;
            color: white !important;
        }
        
        .stDataFrame {
            border-radius: 12px !important;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }
        
        .downloaded {
            animation: slideIn 0.4s ease-out;
        }

        .back-home-link {
            text-decoration: none;
            font-weight: 600;
            color: #1E88E5;
            font-style: italic;
            display: inline-block;
            margin-bottom: 0.25rem;
        }

        .back-home-link:hover {
            color: #1565C0;
            text-decoration: underline;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        [data-testid="stElementToolbar"] {
            display: none;
        }
    </style>
    """, unsafe_allow_html=True)
    st.markdown(
        '<a class="back-home-link" href="/" target="_self">← Quay về trang chọn tính năng</a>',
        unsafe_allow_html=True,
    )

    if "live_df" not in st.session_state:
        st.session_state.live_df = None
    if "live_elapsed_seconds" not in st.session_state:
        st.session_state.live_elapsed_seconds = 0.0

    st.subheader("1) Chạy kiểm thử trực tiếp trên giao diện")
    col_a, col_b = st.columns([2, 1])
    with col_a:
        uploaded_domain_list = st.file_uploader(
            "Upload danh sách domain/URL để test live (.txt/.csv)",
            type=["txt", "csv"],
            key="uploaded_domain_list",
        )
    with col_b:
        timeout_seconds = st.number_input(
            "Timeout (giây)",
            min_value=3,
            max_value=30,
            value=3,
            step=1,
            key="live_timeout_seconds",
        )
        max_domains = st.number_input(
            "Số domain cần test",
            min_value=1,
            max_value=10000,
            value=1000,
            step=1,
            key="live_max_domains",
            help="Hệ thống sẽ lấy tối đa N dòng đầu tiên và giữ nguyên domain theo input.",
        )

    run_live_btn = st.button("Run Live Testing", type="primary", use_container_width=True)

    if run_live_btn:
        if uploaded_domain_list is None:
            st.error("Vui lòng upload file danh sách domain trước khi chạy Live Testing.")
            return

        lines = read_uploaded_text_lines(uploaded_domain_list)
        if not lines:
            st.error("File domain rỗng hoặc không hợp lệ.")
            return

        with st.spinner("Đang thực hiện kiểm thử live qua Gateway..."):
            live_df, elapsed_seconds = run_live_test_from_lines(
                lines,
                timeout=int(timeout_seconds),
                max_domains=int(max_domains),
            )

        if live_df.empty:
            st.error("Không có domain hợp lệ để kiểm thử.")
            return

        st.session_state.live_df = live_df
        st.session_state.live_elapsed_seconds = elapsed_seconds
        success_box = st.empty()
        success_box.success(f"Đã chạy kiểm thử live trực tiếp thành công trong {elapsed_seconds:.2f} giây.")
        time.sleep(1)
        success_box.empty()

    if st.session_state.live_df is not None:
        live_df = st.session_state.live_df
        elapsed_seconds = float(st.session_state.live_elapsed_seconds)

        st.subheader("2) Summary Charts")
        summary = {
            STATUS_BLOCKED: int((live_df["Trạng_Thái"] == STATUS_BLOCKED).sum()),
            STATUS_LEAKED: int((live_df["Trạng_Thái"] == STATUS_LEAKED).sum()),
            STATUS_DEAD: int((live_df["Trạng_Thái"] == STATUS_DEAD).sum()),
        }

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Tổng domain", f"{len(live_df):,}")
        c2.metric("Blocked by Gateway", f"{summary[STATUS_BLOCKED]:,}")
        c3.metric("Leaked", f"{summary[STATUS_LEAKED]:,}")
        c4.metric("Dead Domains", f"{summary[STATUS_DEAD]:,}")
        st.info(f"Tổng thời gian chạy: {elapsed_seconds:.2f} giây")

        chart_fig = live_pie_chart(summary)
        st.plotly_chart(chart_fig, use_container_width=True)

        st.subheader("3) Data Table")
        search_text = st.text_input("Search domain", value="", placeholder="Nhập domain cần tìm...")

        filtered_df = live_df
        if search_text.strip():
            keyword = search_text.strip().lower()
            filtered_df = live_df[live_df["Domain"].str.contains(keyword, na=False)]

        st.caption(f"Đang hiển thị {len(filtered_df):,} / {len(live_df):,} domain")
        render_live_table(filtered_df)

        st.subheader("4) Export Report")
        state_options = ["ALL", STATUS_BLOCKED, STATUS_LEAKED, STATUS_DEAD]
        export_state = st.selectbox("Chọn State để xuất file", options=state_options, index=0)

        export_df = filtered_df
        if export_state != "ALL":
            export_df = filtered_df[filtered_df["Trạng_Thái"] == export_state]

        st.caption(f"Xuất theo state: {export_state} | Số dòng: {len(export_df):,}")

        csv_bytes = export_df.to_csv(index=False).encode("utf-8-sig")
        xlsx_bytes = to_excel_bytes(export_df, "dynamic_live_testing")
        export_summary = {
            STATUS_BLOCKED: int((export_df["Trạng_Thái"] == STATUS_BLOCKED).sum()),
            STATUS_LEAKED: int((export_df["Trạng_Thái"] == STATUS_LEAKED).sum()),
            STATUS_DEAD: int((export_df["Trạng_Thái"] == STATUS_DEAD).sum()),
        }
        pdf_bytes = to_pdf_bytes(export_df, export_summary, elapsed_seconds)

        d1, d2, d3 = st.columns(3)
        d1.download_button(
            "Export to CSV",
            data=csv_bytes,
            file_name="live_gateway_testing_report.csv",
            mime="text/csv",
            use_container_width=True,
        )
        d2.download_button(
            "Export to Excel",
            data=xlsx_bytes,
            file_name="live_gateway_testing_report.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )
        d3.download_button(
            "Export to PDF",
            data=pdf_bytes,
            file_name="live_gateway_testing_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )


if __name__ == "__main__":
    main()
