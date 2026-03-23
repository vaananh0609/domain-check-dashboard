import io
import importlib
import ipaddress
import os
import re
import time
from typing import Dict, List, Tuple
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, Image as RLImage
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import pandas as pd
import plotly.express as px
import streamlit as st

# Margin helpers (mm => points)
MM_TO_PT = 2.83465
LEFT_MARGIN_PT = 32 * MM_TO_PT
RIGHT_MARGIN_PT = 18 * MM_TO_PT
TOP_MARGIN_PT = 22 * MM_TO_PT
BOTTOM_MARGIN_PT = 22 * MM_TO_PT

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

LABEL_DIRECT_IP = "Direct IP Access"
LABEL_NOT_IN_BL = "Domain Not In Blacklist"
LABEL_MATCHED = "Matched - Potential DoH/Cache Bypass"

TECH_NOTE_BY_LABEL = {
    LABEL_DIRECT_IP: "Nằm ngoài phạm vi chặn của DNS Gateway (Chỉ lọc Domain, không lọc IP).",
    LABEL_NOT_IN_BL: "Tên miền biến tướng mới, chưa có trong tập luật cung cấp.",
    LABEL_MATCHED: "Gateway cấu hình đúng. Khả năng người dùng dùng DNS over HTTPS (DoH) hoặc truy cập từ cache trình duyệt cũ.",
}

IPV4_REGEX = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

# Register Unicode font for Vietnamese support
# Prefer a bundled font at `fonts/NotoSans-Regular.ttf` so PDF renders on hosted servers
viet_font_registered = False
try:
    bundled_font_path = os.path.join(os.path.dirname(__file__), "..", "fonts", "NotoSans-Regular.ttf")
    bundled_font_path = os.path.normpath(bundled_font_path)
    if os.path.exists(bundled_font_path):
        try:
            pdfmetrics.registerFont(TTFont("VietFont", bundled_font_path))
            viet_font_registered = True
        except Exception:
            viet_font_registered = False

    if not viet_font_registered:
        font_candidates = [
            "C:\\Windows\\Fonts\\arial.ttf",
            "C:\\Windows\\Fonts\\times.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/DejaVuSans.ttf",
        ]
        for font_path in font_candidates:
            if os.path.exists(font_path):
                try:
                    pdfmetrics.registerFont(TTFont("VietFont", font_path))
                    viet_font_registered = True
                    break
                except Exception:
                    continue
except Exception:
    viet_font_registered = False


def iter_clean_lines(uploaded_file) -> List[str]:
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
        if "," in val:
            val = val.split(",", 1)[0].strip()
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


def normalize_blacklist_entry(raw_line: str) -> str:
    # Only strip trailing source tags like CATTT or A05P*-CV*-*.
    # Do not trim protocol/path/domain content.
    value = raw_line.strip()
    if not value:
        return ""

    value = re.sub(r"\s+(?:CATTT|A05P\d+-CV\d+-\d+)\s*$", "", value, flags=re.IGNORECASE)
    return value.strip()


def deduplicate_leaked_lines(leaked_lines: List[str]) -> List[str]:
    unique_lines: List[str] = []
    seen_normalized = set()

    for line in leaked_lines:
        normalized = normalize_target(line)
        if not normalized or normalized in seen_normalized:
            continue
        seen_normalized.add(normalized)
        unique_lines.append(line)

    return unique_lines


def is_ipv4(value: str) -> bool:
    if not IPV4_REGEX.match(value):
        return False
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


@st.cache_data(show_spinner=False)
def build_blacklist_set(lines: List[str]) -> set:
    normalized = set()
    for line in lines:
        val = normalize_blacklist_entry(line)
        if val:
            normalized.add(val)
    return normalized


def classify_target(target: str, blacklist_set: set) -> Tuple[str, str, str]:
    if is_ipv4(target):
        return "Not Found", LABEL_DIRECT_IP, TECH_NOTE_BY_LABEL[LABEL_DIRECT_IP]

    # Exact match only (Set lookup)
    if target in blacklist_set:
        return "Found", LABEL_MATCHED, TECH_NOTE_BY_LABEL[LABEL_MATCHED]

    return "Not Found", LABEL_NOT_IN_BL, TECH_NOTE_BY_LABEL[LABEL_NOT_IN_BL]


def run_validation(blacklist_lines: List[str], leaked_lines: List[str]) -> Tuple[pd.DataFrame, Dict[str, int], int, int]:
    blacklist_set = build_blacklist_set(blacklist_lines)
    deduped_leaked = deduplicate_leaked_lines(leaked_lines)
    duplicate_count = len(leaked_lines) - len(deduped_leaked)

    rows = []
    for idx, original in enumerate(deduped_leaked, start=1):
        normalized_target = normalize_target(original)
        status, label, note = classify_target(normalized_target, blacklist_set)
        rows.append(
            {
                "STT": idx,
                "Original URL": original,
                "Normalized Target": normalized_target,
                "Status in Blacklist": status,
                "Root Cause (Label)": label,
                "Technical Note": note,
            }
        )

    df = pd.DataFrame(rows)
    summary = {
        LABEL_DIRECT_IP: int((df["Root Cause (Label)"] == LABEL_DIRECT_IP).sum()) if not df.empty else 0,
        LABEL_NOT_IN_BL: int((df["Root Cause (Label)"] == LABEL_NOT_IN_BL).sum()) if not df.empty else 0,
        LABEL_MATCHED: int((df["Root Cause (Label)"] == LABEL_MATCHED).sum()) if not df.empty else 0,
    }

    return df, summary, len(blacklist_set), duplicate_count


def pie_chart(summary: Dict[str, int]):
    data = pd.DataFrame({"Label": list(summary.keys()), "Count": list(summary.values())})

    color_map = {
        LABEL_DIRECT_IP: "#c62828",
        LABEL_NOT_IN_BL: "#f9a825",
        LABEL_MATCHED: "#5d6d7e",
    }

    fig = px.pie(
        data,
        names="Label",
        values="Count",
        color="Label",
        color_discrete_map=color_map,
        title="Tỷ lệ phân loại nguyên nhân lọt",
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    # Try to set Plotly font to the registered PDF font name so exported PNGs contain Vietnamese glyphs
    if viet_font_registered:
        fig.update_layout(font=dict(family="VietFont"), margin=dict(l=10, r=10, t=60, b=10))
    else:
        fig.update_layout(margin=dict(l=10, r=10, t=60, b=10))
    return fig


def fig_to_png_bytes(fig) -> bytes | None:
    try:
        img_bytes = fig.to_image(format="png")
        return img_bytes
    except Exception:
        try:
            # fallback
            buf = io.BytesIO()
            fig.write_image(buf, format="png")
            buf.seek(0)
            return buf.read()
        except Exception:
            return None


def to_pdf_bytes_with_chart(df: pd.DataFrame, fig) -> bytes:
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
    
    # Custom style for Vietnamese text
    title_style = styles["Title"]
    if viet_font_registered:
        title_style.fontName = "VietFont"
    
    elements = [
        Paragraph("BÁO CÁO PHÂN TÍCH DỮ LIỆU TĨNH: ĐỐI SOÁT DANH SÁCH RÒ RỈ", title_style),
        Spacer(1, 0.2 * inch),
    ]

    # Add pie chart if available
    img = None
    if fig is not None:
        img = fig_to_png_bytes(fig)
    if img:
        try:
            img_buf = io.BytesIO(img)
            # scale image to fit portrait A4 usable width
            avail_width = A4[0] - (LEFT_MARGIN_PT + RIGHT_MARGIN_PT)
            img_width = avail_width * 0.9
            rl_img = RLImage(img_buf, width=img_width, height=3 * inch)
            rl_img.hAlign = "CENTER"
            elements.append(rl_img)
            elements.append(Spacer(1, 0.2 * inch))
        except Exception:
            pass

    # Table with better formatting for long data
    max_rows = 1500
    safe_df = df.head(max_rows).copy()
    
    # Convert to string and handle Vietnamese encoding
    table_data = []
    headers = [str(col) for col in safe_df.columns]
    table_data.append(headers)
    
    for idx, row in safe_df.iterrows():
        row_data = [str(val) for val in row.values]
        table_data.append(row_data)

    # Calculate column widths to fit portrait A4 and autofit based on content
    num_cols = len(headers)
    # Available width in points for portrait A4
    page_w = A4[0]
    avail_width = page_w - (LEFT_MARGIN_PT + RIGHT_MARGIN_PT)

    # Use Paragraph cells to support wrapping
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle(
        "cell",
        parent=styles["Normal"],
        fontName=("VietFont" if viet_font_registered else "Helvetica"),
        fontSize=8,
        leading=10,
    )
    header_style = ParagraphStyle(
        "header",
        parent=styles["Normal"],
        fontName=("VietFont" if viet_font_registered else "Helvetica-Bold"),
        fontSize=9,
        leading=11,
        alignment=TA_CENTER,
    )

    # Build table data with Paragraphs
    table_data = [[Paragraph(h, header_style) for h in headers]]
    col_max = [0] * num_cols
    for _, row in safe_df.iterrows():
        row_items = []
        for i, v in enumerate(row.values.tolist()):
            s = str(v)
            col_max[i] = max(col_max[i], len(s))
            row_items.append(Paragraph(s, cell_style))
        table_data.append(row_items)

    total = sum(col_max) if sum(col_max) > 0 else num_cols
    min_w = 40
    col_widths = [max(min_w, avail_width * (m / total)) for m in col_max]

    table = Table(table_data, colWidths=col_widths, repeatRows=1)

    # Font name for table
    table_font = "VietFont" if viet_font_registered else "Helvetica"
    table_font_bold = "VietFont" if viet_font_registered else "Helvetica-Bold"

    # Base table styles
    table_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), table_font_bold),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (-1, -1), table_font),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]

    # Preserve the row-color convention from the UI if column exists
    if "Root Cause (Label)" in safe_df.columns:
        for row_idx, label in enumerate(safe_df["Root Cause (Label)"].tolist(), start=1):
            if label == LABEL_DIRECT_IP:
                table_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#FFCDD2")))
                table_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#B71C1C")))
            elif label == LABEL_NOT_IN_BL:
                table_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#FFE0B2")))
                table_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#E65100")))
            elif label == LABEL_MATCHED:
                table_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#BBDEFB")))
                table_styles.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor("#0D47A1")))

    # Fallback alternating backgrounds if no label column
    else:
        table_styles.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]))

    table.setStyle(TableStyle(table_styles))
    elements.append(table)
    
    try:
        doc.build(elements)
    except Exception as e:
        # Fallback: if there's an issue with Vietnamese, try without it
        if viet_font_registered:
            # Retry without forcing Vietnamese font
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 6),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                        ("LEFTPADDING", (0, 0), (-1, -1), 2),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )
            doc.build(elements)
        else:
            raise
    
    output.seek(0)
    return output.getvalue()


def to_excel_bytes(df: pd.DataFrame, sheet_name: str) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)
    output.seek(0)
    return output.getvalue()


def render_result_table(df: pd.DataFrame) -> None:
    if not AGGRID_AVAILABLE:
        st.info("Để hiển thị xuống dòng trong ô bảng, vui lòng cài thêm streamlit-aggrid.")
        st.dataframe(df, use_container_width=True, height=420)
        return

    root_cause_row_style = JsCode(
        """
        function(params) {
            const value = params.data && params.data["Root Cause (Label)"] ? params.data["Root Cause (Label)"] : "";
            if (value === "Direct IP Access") {
                return {
                    'backgroundColor': '#FFCDD2',
                    'color': '#B71C1C',
                    'fontWeight': '500'
                };
            }
            if (value === "Domain Not In Blacklist") {
                return {
                    'backgroundColor': '#FFE0B2',
                    'color': '#E65100',
                    'fontWeight': '500'
                };
            }
            if (value === "Matched - Potential DoH/Cache Bypass") {
                return {
                    'backgroundColor': '#BBDEFB',
                    'color': '#0D47A1',
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
    gb.configure_column("Original URL", width=260)
    gb.configure_column("Normalized Target", width=180)
    gb.configure_column("Status in Blacklist", width=190)
    gb.configure_column("Root Cause (Label)", width=340)
    gb.configure_column("Technical Note", width=620)
    gb.configure_grid_options(suppressRowTransform=True, getRowStyle=root_cause_row_style)

    AgGrid(
        df,
        gridOptions=gb.build(),
        fit_columns_on_grid_load=False,
        theme="streamlit",
        height=460,
        allow_unsafe_jscode=True,
    )


def main():
    st.title("Static Analysis")
    st.caption("Đối soát log lọt với blacklist bằng so khớp tuyệt đối")
    
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
            background: linear-gradient(135deg, rgba(30, 136, 229, 0.1) 0%, rgba(0, 188, 212, 0.05) 100%);
            border: 1px solid rgba(30, 136, 229, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        .section-title {
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(135deg, #1E88E5 0%, #00BCD4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-top: 2rem;
            margin-bottom: 1rem;
            letter-spacing: -0.5px;
        }
        
        .stFileUploader {
            border: 2px dashed #1E88E5 !important;
            border-radius: 12px !important;
            padding: 1.5rem !important;
            background: rgba(30, 136, 229, 0.05) !important;
            transition: all 0.3s ease;
        }
        
        .stFileUploader:hover {
            background: rgba(30, 136, 229, 0.1) !important;
            border-color: #00BCD4 !important;
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
            box-shadow: 0 8px 24px rgba(30, 136, 229, 0.3);
        }
        
        .stButton > button[type="primary"] {
            background: linear-gradient(135deg, #1E88E5 0%, #1565C0 100%) !important;
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

    if "static_result_df" not in st.session_state:
        st.session_state.static_result_df = None
    if "static_summary" not in st.session_state:
        st.session_state.static_summary = None
    if "static_total_blacklist" not in st.session_state:
        st.session_state.static_total_blacklist = 0
    if "static_duplicate_count" not in st.session_state:
        st.session_state.static_duplicate_count = 0

    st.subheader("1) Upload Data")
    col1, col2 = st.columns(2)
    with col1:
        blacklist_file = st.file_uploader(
            "Upload File Blacklist (.txt/.csv)",
            type=["txt", "csv"],
            key="blacklist_file",
        )
    with col2:
        leaked_file = st.file_uploader(
            "Upload File Log Lọt (.txt/.csv)",
            type=["txt", "csv"],
            key="leaked_file",
        )

    run_btn = st.button("Run Validation", type="primary", use_container_width=True)

    if run_btn:
        if blacklist_file is None or leaked_file is None:
            st.error("Vui lòng upload đủ cả 2 file trước khi chạy validation.")
            return

        with st.spinner("Đang xử lý và đối soát dữ liệu..."):
            blacklist_lines = iter_clean_lines(blacklist_file)
            leaked_lines = iter_clean_lines(leaked_file)
            result_df, summary, total_blacklist, duplicate_count = run_validation(blacklist_lines, leaked_lines)

        st.session_state.static_result_df = result_df
        st.session_state.static_summary = summary
        st.session_state.static_total_blacklist = total_blacklist
        st.session_state.static_duplicate_count = duplicate_count

    if st.session_state.static_result_df is not None:
        result_df = st.session_state.static_result_df
        summary = st.session_state.static_summary
        total_blacklist = st.session_state.static_total_blacklist
        duplicate_count = st.session_state.static_duplicate_count

        if run_btn:
            success_box = st.empty()
            info_box = st.empty()
            success_box.success("Validation hoàn tất.")
            info_box.info(f"Đã loại bỏ {duplicate_count:,} dòng log trùng lặp trước khi phân tích.")
            time.sleep(1)
            success_box.empty()
            info_box.empty()

        st.subheader("2) Summary Dashboard")
        c1, c2, c3 = st.columns(3)
        c1.metric("Tổng số dòng Blacklist (đã xử lý)", f"{total_blacklist:,}")
        c2.metric("Tổng số URL lọt (sau loại trùng)", f"{len(result_df):,}")
        c3.metric("Số nhãn khác nhau", "3")

        st.plotly_chart(pie_chart(summary), use_container_width=True)

        st.subheader("3) Data Table")
        render_result_table(result_df)

        st.subheader("4) Export Report")
        csv_bytes = result_df.to_csv(index=False).encode("utf-8-sig")
        xlsx_bytes = to_excel_bytes(result_df, "static_analysis")

        d1, d2, d3 = st.columns(3)
        d1.download_button(
            "Export to CSV",
            data=csv_bytes,
            file_name="dns_static_analysis_report.csv",
            mime="text/csv",
            use_container_width=True,
        )
        d2.download_button(
            "Export to Excel",
            data=xlsx_bytes,
            file_name="dns_static_analysis_report.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )
        # PDF export with chart
        d3.download_button(
            "Export to PDF",
            data=to_pdf_bytes_with_chart(result_df, pie_chart(summary)),
            file_name="dns_static_analysis_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

        st.markdown("#### Bảng tổng hợp")
        sum_df = pd.DataFrame(
            [
                {"Label": k, "Count": v, "Percent": f"{(v / len(result_df) * 100):.2f}%" if len(result_df) else "0.00%"}
                for k, v in summary.items()
            ]
        )
        st.table(sum_df)


if __name__ == "__main__":
    main()
