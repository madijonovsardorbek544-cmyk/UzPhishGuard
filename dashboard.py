import os
import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

load_dotenv()

# 1. Sahifa Konfiguratsiyasi (Cyberpunk & Dark Mode formatda)
st.set_page_config(
    page_title="UzPhishGuard SOC Dashboard v5.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Maxsus Premium CSS Interfeys (Glitch va Neon Chiroqlar)
st.markdown("""
    <style>
    .main { background-color: #060913; color: #e2e8f0; }
    [data-testid="stSidebar"] { background-color: #0b1120; border-right: 2px solid #1e293b; }
    
    /* Neon kiber-kartalar */
    .metric-card {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid #3730a3;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.15);
        padding: 24px;
        border-radius: 12px;
        text-align: center;
        transition: transform 0.3s ease;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        border-color: #6366f1;
        box-shadow: 0 6px 25px rgba(99, 102, 241, 0.3);
    }
    .metric-title { font-size: 14px; text-transform: uppercase; letter-spacing: 2px; color: #94a3b8; margin-bottom: 8px; }
    .metric-value { font-size: 36px; font-weight: 800; color: #38bdf8; font-family: 'Courier New', monospace; }
    .metric-value.critical { color: #f43f5e; text-shadow: 0 0 10px rgba(244, 63, 94, 0.5); }
    </style>
""", unsafe_allowed_html=True)

DATABASE_URL = os.getenv("DATABASE_URL")

# 3. Ma'lumotlarni xavfsiz yuklash (Kesh bilan)
@st.cache_data(ttl=10) # Har 10 soniyada ma'lumot yangilanadi
def fetch_threats_from_supabase():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        query = """
            SELECT id, chat_title, sender_username, threat_type, risk_score, details, detected_at 
            FROM threats 
            ORDER BY detected_at DESC;
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"❌ Supabase SQL ulanishida uzilish: {e}")
        return pd.DataFrame()

df_raw = fetch_threats_from_supabase()

# --- SIDEBAR CONTROL PANEL ---
st.sidebar.markdown("## ⚙️ SOC boshqaruv paneli")
st.sidebar.markdown("---")
st.sidebar.info("🤖 **Tizim:** UzPhishGuard Core v4.5\n\n🎯 **Status:** Real-time monitoring faol.")

if df_raw.empty:
    st.title("🛡️ UzPhishGuard SIEM Command Center")
    st.warning("⚠️ Supabase bazasida hozircha kiber-hujumlar jurnali bo'sh. Bot birinchi fishing xabarini ushlashi bilan bu yerda interaktiv 3D grafiklar paydo bo'ladi!")
else:
    # Ma'lumotlarni tayyorlash
    df = df_raw.copy()
    df['detected_at'] = pd.to_datetime(df['detected_at'])
    
    # Yon paneldagi filtrlar
    threat_filter = st.sidebar.multiselect(
        "🔮 Tahdid turlarini filtrlash:",
        options=df['threat_type'].unique(),
        default=df['threat_type'].unique()
    )
    df = df[df['threat_type'].isin(threat_filter)]

    # --- MAIN DASHBOARD INTERFACE ---
    st.markdown("# 🛡️ UzPhishGuard — MIT-Tier Cyber Security SIEM Center")
    st.markdown("### 🏢 Markaziy kiber-tahdidlarni tahlil qilish va intellektual monitoring stansiyasi")
    st.markdown("---")

    # 4. KIBER METRIKALAR (KPI)
    total_incidents = len(df)
    critical_incidents = len(df[df['risk_score'] >= 80])
    avg_danger_rate = int(df['risk_score'].mean()) if total_incidents > 0 else 0

    m_col1, m_col2, m_col3 = st.columns(3)
    with m_col1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">🚨 JAMI INTEGRATSIYA QILINGAN TAHIDLAR</div>
                <div class="metric-value">{total_incidents} ta</div>
            </div>
        """, unsafe_allowed_html=True)
    with m_col2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">🔴 CRITICAL ATTACKS (💥 RISK >= 80%)</div>
                <div class="metric-value critical">{critical_incidents} ta</div>
            </div>
        """, unsafe_allowed_html=True)
    with m_col3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">📊 O'RTACHA XAVF KO'RSATKICHI</div>
                <div class="metric-value" style="color: #a855f7;">{avg_danger_rate}%</div>
            </div>
        """, unsafe_allowed_html=True)

    st.markdown("---")

    # 5. ADVANCED 3D VIZUALIZATSIYA VA GRAFIKLAR
    g_col1, g_col2 = st.columns([1.1, 0.9])

    with g_col1:
        st.subheader("🌐 3D Hujumlar Matritsasi (Scatter 3D)")
        # Vaqtni soniyaga o'tkazish (Z o'qi uchun vizual chiroyli ko'rinish beradi)
        df['Time_Seconds'] = df['detected_at'].dt.hour * 3600 + df['detected_at'].dt.minute * 60 + df['detected_at'].dt.second
        
        fig_3d = px.scatter_3d(
            df,
            x='threat_type',
            y='risk_score',
            z='Time_Seconds',
            color='risk_score',
            size='risk_score',
            hover_name='sender_username',
            hover_data=['chat_title', 'details'],
            color_continuous_scale=px.colors.sequential.Sunsetdark,
            labels={'threat_type': 'Tahdid turi', 'risk_score': 'Xavf darajasi %', 'Time_Seconds': 'Vaqt (Soniya)'}
        )
        fig_3d.update_layout(
            scene=dict(
                backgroundcolor="#090d16",
                xaxis=dict(backgroundcolor="#0f172a", gridcolor="#334155"),
                yaxis=dict(backgroundcolor="#0f172a", gridcolor="#334155"),
                zaxis=dict(backgroundcolor="#0f172a", gridcolor="#334155"),
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=0, r=0, b=0, t=0)
        )
        st.plotly_chart(fig_3d, use_container_width=True)

    with g_col2:
        st.subheader("🎯 Kiber Taktika Klasteri (Donut Chart)")
        type_matrix = df['threat_type'].value_counts().reset_index()
        type_matrix.columns = ['Type', 'Count']
        
        fig_donut = go.Figure(data=[go.Pie(
            labels=type_matrix['Type'], 
            values=type_matrix['Count'], 
            hole=.5,
            marker=dict(colors=['#f43f5e', '#38bdf8', '#a855f7', '#10b981'])
        )])
        fig_donut.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color="#94a3b8",
            legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    st.markdown("---")

    # 6. INCIDENT TIMELINE CHART
    st.subheader("📈 Vaqt Davomidagi Kiber Hujumlar Intensivligi")
    df_timeline = df.set_index('detected_at').resample('min').size().reset_index()
    df_timeline.columns = ['Timeline', 'Hujumlar Soni']
    
    fig_line = px.area(
        df_timeline, 
        x='Timeline', 
        y='Hujumlar Soni', 
        title="Dinamik Vaqt Shkalasi",
        color_discrete_sequence=['#3b82f6']
    )
    fig_line.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(gridcolor="#1e293b", title_font=dict(color="#94a3b8")),
        yaxis=dict(gridcolor="#1e293b", title_font=dict(color="#94a3b8")),
        font_color="#e2e8f0"
    )
    st.plotly_chart(fig_line, use_container_width=True)

    st.markdown("---")

    # 7. JONLI INTEGRATSIYALASHGAN LOG JADVALI
    st.subheader("📋 Jonli Tahdidlar Voqeligining Jurnali (Incident Feed)")
    search_bar = st.text_input("🔍 Guruh nomi, buzuvchi username yoki aniq kiber-detallar bo'yicha tezkor qidiruv:")
    
    if search_bar:
        df = df[
            df['chat_title'].str.contains(search_bar, case=False, na=False) | 
            df['sender_username'].str.contains(search_bar, case=False, na=False) |
            df['details'].str.contains(search_bar, case=False, na=False)
        ]

    # Jadvalni chiroyli formatda chiqarish
    st.dataframe(
        df[['detected_at', 'chat_title', 'sender_username', 'threat_type', 'risk_score', 'details']],
        use_container_width=True,
        column_config={
            "detected_at": "Vaqt (UTC)",
            "chat_title": "Guruh / Manba",
            "sender_username": "Hujumchi",
            "threat_type": "Tahdid Turi",
            "risk_score": st.column_config.ProgressColumn("Xavf Ko'rsatkichi", min_value=0, max_value=100, format="%d%%"),
            "details": "AI Diagnostika Tafsilotlari"
        }
    )
