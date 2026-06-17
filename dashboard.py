import os
import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

st.set_page_config(page_title="UzPhishGuard SOC Panel", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #060913; color: #e2e8f0; }
    .metric-box {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid #3730a3; padding: 20px; border-radius: 12px;
        text-align: center; margin-bottom: 20px;
    }
    .metric-lbl { font-size: 13px; font-weight: 600; color: #94a3b8; letter-spacing: 1px; }
    .metric-val { font-size: 36px; font-weight: 800; color: #38bdf8; font-family: monospace; }
    .metric-crit { font-size: 36px; font-weight: 800; color: #f43f5e; font-family: monospace; }
    </style>
""", unsafe_allow_html=True)

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")
if DB_URL and DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

@st.cache_data(ttl=10) # Baza qiynalmasligi uchun ma'lumotni 10 soniyaga kesh qilamiz
def fetch_data(url):
    if not url:
        return pd.DataFrame()
    conn = None
    try:
        conn = psycopg2.connect(url)
        df = pd.read_sql("SELECT * FROM threats ORDER BY detected_at DESC;", conn)
        return df
    except Exception as e:
        st.error(f"Ma'lumot tortishda xatolik: {e}")
        return pd.DataFrame()
    finally:
        if conn:
            conn.close()

df = fetch_data(DB_URL)

st.title("🛡️ Enterprise SOC Command Center")
st.markdown("---")

if df.empty:
    st.info("💡 Baza ayni vaqtda toza. Real-time monitoring faol.")
else:
    df['detected_at'] = pd.to_datetime(df['detected_at'])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f'<div class="metric-box"><div class="metric-lbl">JAMI INCIDENTLAR</div><div class="metric-val">{len(df)}</div></div>', unsafe_allow_html=True)
    with col2:
        crits = len(df[df['risk_score'] >= 80])
        st.markdown(f'<div class="metric-box"><div class="metric-lbl">KRITIK HUJUMLAR</div><div class="metric-crit">{crits}</div></div>', unsafe_allow_html=True)
    with col3:
        avg = int(df['risk_score'].mean())
        st.markdown(f'<div class="metric-box"><div class="metric-lbl">O\'RTACHA XAVF</div><div class="metric-val" style="color:#a855f7;">{avg}%</div></div>', unsafe_allow_html=True)

    g1, g2 = st.columns([1.5, 1])
    with g1:
        st.subheader("🌐 Vaqt va Xavf Matritsasi")
        fig_scatter = px.scatter(
            df, x="detected_at", y="risk_score", color="threat_type", 
            size="risk_score", hover_data=["sender_username", "chat_title"],
            color_discrete_sequence=px.colors.qualitative.Set1
        )
        fig_scatter.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="#94a3b8")
        st.plotly_chart(fig_scatter, use_container_width=True)

    with g2:
        st.subheader("🎯 Tahdid Vektorlari")
        pie_data = df['threat_type'].value_counts().reset_index()
        pie_data.columns = ['Type', 'Count']
        fig_pie = go.Figure(data=[go.Pie(labels=pie_data['Type'], values=pie_data['Count'], hole=0.5)])
        fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="#94a3b8")
        st.plotly_chart(fig_pie, use_container_width=True)

    st.subheader("📋 Kiber-Jurnal (Logs)")
    st.dataframe(df[['detected_at', 'chat_title', 'sender_username', 'threat_type', 'risk_score', 'details']], use_container_width=True)

    if st.button("🔄 Yangilash"):
        fetch_data.clear() # Keshni tozalab majburiy yangilash
        st.rerun()
