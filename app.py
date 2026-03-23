import streamlit as st

st.set_page_config(page_title="Security Validation Dashboard", layout="wide")

with st.sidebar:
    st.markdown("### Điều hướng")
    st.page_link("app.py", label="Trang chủ", icon="🏠")
    st.page_link("pages/1_Static_Analysis.py", label="Static Analysis", icon="📊")
    st.page_link("pages/2_Dynamic_Live_Testing.py", label="Dynamic Live Testing", icon="🌐")

# Modern Dashboard Theme & Styling
st.markdown("""
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        min-height: 100vh;
        padding: 2rem 0;
    }
    
    .main {
        background: linear-gradient(180deg, #ffffff 0%, #f8f9fa 100%);
        padding: 3rem 2rem;
    }

    .block-container {
        max-width: 1280px;
        margin: 0 auto;
        padding-top: 2.6rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }
    
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    }
    
    /* Header Section */
    .header-section {
        text-align: center;
        margin-bottom: 4rem;
        animation: slideDown 0.6s ease-out;
    }
    
    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .app-title {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(135deg, #1E88E5 0%, #00BCD4 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
        letter-spacing: -1px;
    }
    
    .app-subtitle {
        font-size: 1.1rem;
        color: #666;
        font-weight: 500;
        letter-spacing: 0.5px;
    }
    
    /* Card Container */
    .card-wrapper {
        display: flex;
        gap: 2rem;
        justify-content: center;
        flex-wrap: wrap;
        margin-top: 3rem;
        animation: fadeIn 0.8s ease-out 0.2s both;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
        }
        to {
            opacity: 1;
        }
    }
    
    /* Feature Cards */
    .feature-card {
        width: min(100%, 520px);
        padding: 2.5rem 2rem;
        border-radius: 20px;
        backdrop-filter: blur(10px);
        background: rgba(255, 255, 255, 0.95);
        border: 1px solid rgba(255, 255, 255, 0.6);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
        cursor: pointer;
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
        margin: 0 auto;
    }

    .card-center {
        display: flex;
        justify-content: center;
    }
    
    .feature-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, currentColor, transparent);
        opacity: 0;
        transition: opacity 0.4s ease;
    }
    
    .feature-card:hover {
        transform: translateY(-12px) scale(1.02);
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
        background: rgba(255, 255, 255, 1);
    }
    
    .feature-card-static::before {
        background: linear-gradient(90deg, #1E88E5, transparent);
    }
    
    .feature-card-dynamic::before {
        background: linear-gradient(90deg, #00BCD4, transparent);
    }
    
    .feature-card:hover::before {
        opacity: 1;
    }
    
    /* Icon Section */
    .feature-icon {
        font-size: 3.5rem;
        margin-bottom: 1.5rem;
        display: inline-block;
        transition: transform 0.4s ease;
    }
    
    .feature-card:hover .feature-icon {
        transform: scale(1.15) rotate(5deg);
    }
    
    /* Title */
    .feature-title {
        font-size: 1.8rem;
        font-weight: 700;
        margin-bottom: 0.8rem;
        color: #1a1a1a;
        letter-spacing: -0.5px;
    }
    
    .feature-card-static .feature-title {
        color: #1E88E5;
    }
    
    .feature-card-dynamic .feature-title {
        color: #00BCD4;
    }
    
    /* Description */
    .feature-desc {
        font-size: 0.95rem;
        color: #555;
        line-height: 1.6;
        margin-bottom: 1.5rem;
    }
    
    /* Link Arrow */
    .feature-link {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        font-weight: 600;
        color: #00BCD4;
        text-decoration: none;
        font-size: 0.95rem;
        transition: all 0.3s ease;
    }
    
    .feature-card-static .feature-link {
        color: #1E88E5;
    }
    
    .feature-link:hover {
        gap: 1rem;
    }
    
    /* Hide Streamlit elements */
    [data-testid="stElementToolbar"] {
        display: none;
    }
    
    header[data-testid="stHeader"] {
        background: transparent !important;
        backdrop-filter: none !important;
        border-bottom: none !important;
        box-shadow: none !important;
    }
    
    footer {
        display: none;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
        .app-title {
            font-size: 2rem;
        }
        
        .feature-card {
            width: 100%;
        }
        
        .card-wrapper {
            gap: 1.5rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="header-section">
    <div class="app-title">🔐 Security Validation Dashboard</div>
    <div class="app-subtitle">Nền tảng đối soát log và kiểm chứng Gateway</div>
</div>
""", unsafe_allow_html=True)

# Feature Cards Container
st.markdown('<div class="card-wrapper">', unsafe_allow_html=True)

col1, col2 = st.columns(2, gap="large")

with col1:
    st.markdown("""
    <div class="card-center">
        <div class="feature-card feature-card-static">
            <div class="feature-icon">📊</div>
            <div class="feature-title">Static Analysis</div>
            <div class="feature-desc">
                Đối soát danh sách log lọt với blacklist, phân loại nguyên nhân rò rỉ một cách chính xác.
            </div>
            <a href="/Static_Analysis" target="_self" class="feature-link">
                Start →
            </a>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="card-center">
        <div class="feature-card feature-card-dynamic">
            <div class="feature-icon">🌐</div>
            <div class="feature-title">Dynamic Live Testing</div>
            <div class="feature-desc">
                Kiểm thử trực tiếp về mạng, phân loại trạng thái Block/Leak theo thời gian thực.
            </div>
            <a href="/Dynamic_Live_Testing" target="_self" class="feature-link">
                Start →
            </a>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)
