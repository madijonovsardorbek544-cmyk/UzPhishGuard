import os
import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Sahifa interfeysi sozlamalari
st.set_page_config(
    page_title="UzPhishGuard Enterprise SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Professional To'q Kiber-Dizayn UI elementlari (CSS)
st.markdown("""
    <style>
    .main { background-color: #060913; color: #e2e8f0; }
    .metric-box {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid #3730a3;
        padding: 22px;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 15px;
    }
    .metric-lbl { font-size: 12px; text-transform: uppercase; letter-spacing: 2px; color: #94a3b8; margin-bottom: 5px; }
    .metric-val { font-size: 34px; font-weight: 800; color: #38bdf8; font-family: 'Courier New', monospace; }
    .metric-val-crit { font-size: 34px; font-weight: 800; color: #f43f5e; font-family: 'Courier New', monospace; text-shadow: 0 0 10px rgba(244, 63, 94, 0.4); }
    </style>
""", unsafe_allow_html=True)

def load_threat_data():
    """Supabase bazasidan ma'lumotlarni xavfsiz tortib olish"""
    if not DATABASE_URL:
        return pd.DataFrame()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        query = "SELECT id, chat_title, sender_username, threat_type, risk_score, details, detected_at FROM threats ORDER BY detected_at DESC;"
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"❌ Supabase SQL ulanishida texnik uzilish yuz berdi: {e}")
        return pd.DataFrame()

df = load_threat_data()

st.title("🛡️ UzPhishGuard — MIT-Tier Security Command Center")
st.markdown("---")

if df.empty:
    st.info("💡 SIEM monitoring tizimi muvaffaqiyatli ulandi. Hozircha bazada kiber-tahdidlar jurnali bo'sh. Guruhda botni faollashtirib, test tariqasida xavfli xabar yoki .apk fayl yuborib ko'ring.")
else:
    df['detected_at'] = pd.to_datetime(df['detected_at'])
    
    # Asosiy kiber metrikalar hisobi
    total_threats = len(df)
    critical_threats = len(df[df['risk_score'] >= 80])
    average_risk = int(df['risk_score'].mean())
    
    # Metrikalarni ekranga chiqarish
    col_m1, col_m2, col_m3 = st.columns(3)
    with col_m1:
        st.markdown(f'<div class="metric-box"><div class="metric-lbl">🚨 JAMI ANIQLANGAN TAHDIDLAR</div><div class="metric-val">{total_threats} ta</div></div>', unsafe_allow_html=True)
    with col_m2:
        st.markdown(f'<div class="metric-box"><div class="metric-lbl">🔴 KRITIK (CRITICAL) ATTACKS</div><div class="metric-val-crit">{critical_threats} ta</div></div>', unsafe_allow_html=True)
    with col_m3:
        st.markdown(f'<div class="metric-box"><div class="metric-lbl">📊 O\'RTACHA TIZIM XAVFI</div><div class="metric-val" style="color:#a855f7;">{average_risk}%</div></div>', unsafe_allow_html=True)

    st.markdown("---")

    # Grafiklarni chiqarish paneli
    col_g1, col_g2 = st.columns([1.2, 0.8])
    with col_g1:
        st.subheader("🌐 Real-time 3D Cyber Threat Matrix")
        df['Time_Seconds'] = df['detected_at'].dt.hour * 3600 + df['detected_at'].dt.minute * 60
        fig_3d = px.scatter_3d(
            df, 
            x='threat_type', 
            y='risk_score', 
            z='Time_Seconds', 
            color='risk_score', 
            size='risk_score', 
            hover_name='sender_username', 
            color_continuous_scale=px.colors.sequential.Sunsetdark
        )
        fig_3d.update_layout(scene=dict(bgcolor="#090d16"), paper_bgcolor='rgba(0,0,0,0)', font_color="#94a3b8")
        st.plotly_chart(fig_3d, use_container_width=True)
        
    with col_g2:
        st.subheader("🎯 Threat Vector Distribution")
        threat_counts = df['threat_type'].value_counts().reset_index()
        threat_counts.columns = ['Attack Type', 'Incidents Count']
        fig_pie = go.Figure(data=[go.Pie(labels=threat_counts['Attack Type'], values=threat_counts['Incidents Count'], hole=.45)])
        fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color="#94a3b8")
        st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown("---")
    st.subheader("📋 SIEM Jonli Voqealar Log Jurnali (Live Attack Feeds)")
    
    # Ma'lumotlar jadvalini chiroyli formatda ko'rsatish
    st.dataframe(df[['detected_at', 'chat_title', 'sender_username', 'threat_type', 'risk_score', 'details']], use_container_width=True)
    
    if st.button("🔄 Dashboard ma'lumotlarini yangilash"):
        st.rerun()
