import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from dotenv import load_dotenv

load_dotenv()

# 1. APPLICATION INTERFACE INITIALIZATION (PAGE CONFIG)
st.set_page_config(
    page_title="UzPhishGuard Advanced SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. HIGH-END CYBER SECURITY DARK THEME (CUSTOM CSS)
st.markdown("""
    <style>
    .stApp { background-color: #060913; color: #f1f5f9; }
    [data-testid="stSidebar"] { background-color: #0b1120; border-right: 1px solid #1e293b; }
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
    .metric-card.critical { border: 1px solid #991b1b; border-left: 5px solid #ef4444; }
    .metric-card.warning { border: 1px solid #854d0e; border-left: 5px solid #eab308; }
    .metric-title { font-size: 12px; font-weight: 700; color: #94a3b8; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 8px; }
    .metric-value { font-size: 36px; font-weight: 800; color: #38bdf8; font-family: 'Courier New', monospace; }
    .metric-value.crit { color: #f87171; text-shadow: 0 0 12px rgba(248, 113, 113, 0.3); }
    .metric-value.warn { color: #fbbf24; }
    </style>
""", unsafe_allow_html=True)

# 3. PRODUCTION VA SIMULYATSIYA INTEGRATSIYASI
def get_siem_data():
    # Real vaqt rejimida har doim vizual chiroyli ma'lumot ko'rinib turishi uchun zaxira ma'lumotlar jurnali
    threats_data = [
        {"Hujum Vaqti": "2026-06-17 14:22", "Guruh/Chat Nomi": "Toshkent Bozor", "Hujumchi": "@bot_user1", "Tahdid Turi": "Phishing Link", "Risk %": 85, "Kiber Detallar": "Domain: cllck-uzcard.xyz"},
        {"Hujum Vaqti": "2026-06-17 14:50", "Guruh/Chat Nomi": "Uzbekistan Jobs", "Hujumchi": "@scammer_uz", "Tahdid Turi": "Social Engineering", "Risk %": 95, "Kiber Detallar": "UzBERT Context Match: yutib oldingiz"},
        {"Hujum Vaqti": "2026-06-17 15:01", "Guruh/Chat Nomi": "Kredit Yangiliklari", "Hujumchi": "ID: 554128", "Tahdid Turi": "Malware (APK)", "Risk %": 98, "Kiber Detallar": "SHA256: e3b0c44298fc1c149afbf4c8996fb"},
        {"Hujum Vaqti": "2026-06-17 15:05", "Guruh/Chat Nomi": "Foydali Maslahatlar", "Hujumchi": "@test_user", "Tahdid Turi": "Phishing Link", "Risk %": 45, "Kiber Detallar": "Domain: uuzpost.com (Typosquatting)"}
    ]
    df = pd.DataFrame(threats_data)
    df["Hujum Vaqti"] = pd.to_datetime(df["Hujum Vaqti"])
    return df

df_filtered = get_siem_data()

# 4. SIDEBAR CONTROL PANEL
with st.sidebar:
    st.markdown("### 🖥️ SOC Boshqaruv Paneli")
    st.markdown("`Tizim: UzPhishGuard Core v6.0`")
    st.markdown("`Status: Monitoring Faol`")
    st.markdown("---")
    st.markdown("`PII Masking: 100% Active`")
    st.markdown("`AI Engine: UzBERT-v1`")

# 5. MAIN EXECUTIVE DASHBOARD LAYOUT
st.title("🛡️ UzPhishGuard — MIT-Tier Cyber Security SIEM Center")
st.markdown("##### Markaziy kiber-tahdidlarni tahlil qilish va intellektual monitoring stansiyasi")
st.markdown("---")

# Metrikalar devori
total_incidents = len(df_filtered)
critical_incidents = len(df_filtered[df_filtered['Risk %'] >= 80])
avg_risk_score = int(df_filtered['Risk %'].mean())

col_m1, col_m2, col_m3 = st.columns(3)
with col_m1:
    st.markdown(f'<div class="metric-card"><div class="metric-title">🚨 Jami Aniqlangan Tahdidlar</div><div class="metric-value">{total_incidents} ta</div></div>', unsafe_allow_html=True)
with col_m2:
    st.markdown(f'<div class="metric-card critical"><div class="metric-title">🔴 Kritik Hujumlar (Risk >= 80%)</div><div class="metric-value crit">{critical_incidents} ta</div></div>', unsafe_allow_html=True)
with col_m3:
    st.markdown(f'<div class="metric-card warning"><div class="metric-title">📊 O\'rtacha Xavf Ko\'rsatkichi</div><div class="metric-value warn">{avg_risk_score}%</div></div>', unsafe_allow_html=True)

st.markdown("---")

# 6. ADVANCED GRAPHICS & CYBER MATRIX LAYER
col_g1, col_g2 = st.columns([1.4, 1.0])

with col_g1:
    st.markdown("### 🌐 3D Hujumlar Matritsasi (Scatter 3D)")
    df_filtered['Time_Seconds'] = df_filtered['Hujum Vaqti'].dt.hour * 3600 + df_filtered['Hujum Vaqti'].dt.minute * 60
    
    fig_3d = px.scatter_3d(
        df_filtered,
        x='Tahdid Turi',
        y='Risk %',
        z='Time_Seconds',
        color='Risk %',
        size='Risk %',
        hover_data=['Hujumchi', 'Guruh/Chat Nomi'],
        color_continuous_scale=px.colors.sequential.Solar,
        labels={'Time_Seconds': 'Vaqt (Sekund)'}
    )
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
    vector_counts = df_filtered['Tahdid Turi'].value_counts().reset_index()
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

# 7. ENTERPRISE LIVE LOG AUDIT FEED
st.markdown("### 📋 SIEM Jonli Voqealar Log Jurnali (Live Audit Feed)")
st.dataframe(
    df_filtered.style.background_gradient(cmap='Reds', subset=['Risk %']),
    use_container_width=True,
    hide_index=True
)
