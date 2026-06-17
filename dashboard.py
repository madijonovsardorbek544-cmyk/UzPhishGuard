import os
import logging
import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import DictCursor
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

# 1. PROFESSIONAL LOGGING & ENV CONFIGURATION
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("UzPhishGuardDashboard")

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# 2. APPLICATION INTERFACE INITIALIZATION (PAGE CONFIG)
st.set_page_config(
    page_title="UzPhishGuard Advanced SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 3. HIGH-END CYBER SECURITY DARK THEME (CUSTOM CSS)
st.markdown("""
    <style>
    /* Umumiy fon va matn ranglari */
    .stApp { background-color: #060913; color: #f1f5f9; }
    
    /* Yon panel (Sidebar) dizayni */
    [data-testid="stSidebar"] { background-color: #0b1120; border-right: 1px solid #1e293b; }
    
    /* Kiber metrik kartalar */
    .metric-card {
        background: linear-gradient(135deg, #0f172a 0%, #111827 100%);
        border: 1px solid #1e40af;
        border-left: 5px solid #3b82f6;
        padding: 24px;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
        margin-bottom: 20px;
    }
    .metric-card.critical {
        border: 1px solid #991b1b;
        border-left: 5px solid #ef4444;
    }
    .metric-card.warning {
        border: 1px solid #854d0e;
        border-left: 5px solid #eab308;
    }
    .metric-title { font-size: 12px; font-weight: 700; color: #94a3b8; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 8px; }
    .metric-value { font-size: 36px; font-weight: 800; color: #38bdf8; font-family: 'Courier New', monospace; }
    .metric-value.crit { color: #f87171; text-shadow: 0 0 12px rgba(248, 113, 113, 0.3); }
    .metric-value.warn { color: #fbbf24; }
    </style>
""", unsafe_allow_html=True)


# 4. SECURE DATA RETRIEVAL LAYER (HIGH-PERFORMANCE CACHING)
@st.cache_data(ttl=15, show_spinner="SIEM markazidan jonli ma'lumotlar tortilmoqda...")
def fetch_siem_logs(db_url: str) -> pd.DataFrame:
    """Supabase'dan ma'lumotlarni xavfsiz oqimda tortib olish va xatoliklarni filtrlash"""
    if not db_url:
        logger.error("Database URL topilmadi!")
        return pd.DataFrame()
    
    conn = None
    try:
        conn = psycopg2.connect(db_url)
        query = """
            SELECT id, chat_title, sender_username, threat_type, risk_score, details, detected_at 
            FROM threats 
            ORDER BY detected_at DESC;
        """
        # Pandas xotira optimizatsiyasi bilan o'qiydi
        df = pd.read_sql(query, conn)
        return df
    except Exception as e:
        logger.error(f"SIEM ma'lumotlarini yuklashda uzilish: {e}")
        return pd.DataFrame()
    finally:
        if conn:
            conn.close() # Connection Pool'ni bo'shatish (Memory leak'ni oldini oladi)


# 5. DATA INGESTION & PIPELINE
df_raw = fetch_siem_logs(DATABASE_URL)


# 6. SIDEBAR CONTROL PANEL
with st.sidebar:
    st.markdown("### 🖥️ SOC Boshqaruv Paneli")
    st.markdown("`Tizim: UzPhishGuard Core v6.0`")
    st.markdown("`Status: Monitoring Faol`")
    st.markdown("---")
    
    st.markdown("### 🔍 Global Filtrlar")
    if not df_raw.empty:
        # Tahdid turlari bo'yicha multiselect filtr
        all_threats = df_raw['threat_type'].unique().tolist()
        selected_types = st.multiselect("Tahdid turlarini filtrlash:", all_threats, default=all_threats)
        
        # Risk darajasi bo'yicha slider filtr
        min_risk, max_risk = int(df_raw['risk_score'].min()), int(df_raw['risk_score'].max())
        if min_risk == max_risk:
            min_risk = 0
        risk_range = st.slider("Minimal Risk Darajasi (%):", min_risk, max_risk, (min_risk, max_risk))
        
        # Ma'lumotlarni filtrlash qasri
        df_filtered = df_raw[(df_raw['threat_type'].isin(selected_types)) & 
                             (df_raw['risk_score'].between(risk_range[0], risk_range[1]))]
    else:
        df_filtered = df_raw
        st.write("Filtrlash uchun ma'lumot mavjud emas.")
    
    st.markdown("---")
    if st.button("🔄 Canllarni Yangilash (Flush Cache)", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# 7. MAIN EXECUTIVE DASHBOARD LAYOUT
st.title("🛡️ UzPhishGuard — MIT-Tier Cyber Security SIEM Center")
st.markdown("##### Markaziy kiber-tahdidlarni tahlil qilish va intellektual monitoring stansiyasi")
st.markdown("---")

if df_filtered.empty:
    st.info("💡 Hozircha kiber-tahdidlar jurnali bo'sh yoki filtrga mos ma'lumot topilmadi. Tizim guruhlarni himoya qilish rejimida barqaror ishlamoqda.")
else:
    # Vaqt formatini to'g'irlash
    df_filtered['detected_at'] = pd.to_datetime(df_filtered['detected_at'])
    
    # Metrik hisob-kitoblar
    total_incidents = len(df_filtered)
    critical_incidents = len(df_filtered[df_filtered['risk_score'] >= 80])
    avg_risk_score = int(df_filtered['risk_score'].mean())
    
    # 8. METRIC CARDS WALL
    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">🚨 Jami Aniqlangan Tahdidlar</div>
                <div class="metric-value">{total_incidents} ta</div>
            </div>
        """, unsafe_allow_html=True)
    with col_m2:
        st.markdown(f"""
            <div class="metric-card critical">
                <div class="metric-title">🔴 Kritik Hujumlar (Risk >= 80%)</div>
                <div class="metric-value crit">{critical_incidents} ta</div>
            </div>
        """, unsafe_allow_html=True)
    with col_m3:
        st.markdown(f"""
            <div class="metric-card warning">
                <div class="metric-title">📊 O'rtacha Xavf Ko'rsatkichi</div>
                <div class="metric-value warn">{avg_risk_score}%</div>
            </div>
        """, unsafe_allow_html=True)
        
    st.markdown("---")
    
    # 9. ADVANCED GRAPHICS & CYBER MATRIX LAYER
    col_g1, col_g2 = st.columns([1.4, 1.0])
    
    with col_g1:
        st.markdown("### 🌐 3D Hujumlar Matritsasi (Scatter 3D)")
        
        # Plotly 3D uchun vaqt o'qini sekundga o'giramiz
        df_filtered['Time_Seconds'] = df_filtered['detected_at'].dt.hour * 3600 + df_filtered['detected_at'].dt.minute * 60 + df_filtered['detected_at'].dt.second
        
        fig_3d = px.scatter_3d(
            df_filtered,
            x='threat_type',
            y='risk_score',
            z='Time_Seconds',
            color='risk_score',
            size='risk_score',
            hover_data=['sender_username', 'chat_title'],
            color_continuous_scale=px.colors.sequential.Solar,
            labels={'threat_type': 'Tahdid Turi', 'risk_score': 'Risk %', 'Time_Seconds': 'Vaqt (Sekundda)'}
        )
        
        # XATO TO'G'IRLANDI: backgroundcolor olib tashlanib, to'g'ri dizayn berildi
        fig_3d.update_layout(
            margin=dict(l=0, r=0, b=0, t=0),
            paper_bgcolor='rgba(0,0,0,0)',
            font_color="#94a3b8",
            scene=dict(
                xaxis=dict(backgroundcolor="rgba(15, 23, 42, 0.5)", gridcolor="#1e293b", showbackground=True),
                yaxis=dict(backgroundcolor="rgba(15, 23, 42, 0.5)", gridcolor="#1e293b", showbackground=True),
                zaxis=dict(backgroundcolor="rgba(15, 23, 42, 0.5)", gridcolor="#1e293b", showbackground=True)
            )
        )
        st.plotly_chart(fig_3d, use_container_width=True)
        
    with col_g2:
        st.markdown("### 🎯 Tahdid Vektorlari Taqsimoti")
        
        vector_counts = df_filtered['threat_type'].value_counts().reset_index()
        vector_counts.columns = ['Vector', 'Count']
        
        fig_donut = go.Figure(data=[go.Pie(
            labels=vector_counts['Vector'],
            values=vector_counts['Count'],
            hole=.55,
            marker=dict(colors=px.colors.qualitative.Pastel)
        )])
        
        fig_donut.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color="#94a3b8",
            legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_donut, use_container_width=True)
        
    st.markdown("---")
    
    # 10. ENTERPRISE LIVE LOG AUDIT FEED
    st.markdown("### 📋 SIEM Jonli Voqealar Log Jurnali (Live Audit Feed)")
    
    # Jadval interfeysini foydalanuvchiga qulay va scannable holatga keltiramiz
    display_df = df_filtered[['detected_at', 'chat_title', 'sender_username', 'threat_type', 'risk_score', 'details']].copy()
    display_df.columns = ['Hujum Vaqti', 'Guruh/Chat Nomi', 'Hujumchi (Username)', 'Tahdid Turi', 'Risk %', 'Kiber Detallar / Xesh']
    
    st.dataframe(
        display_df.style.background_gradient(cmap='Reds', subset=['Risk %']),
        use_container_width=True,
        hide_index=True
    )
