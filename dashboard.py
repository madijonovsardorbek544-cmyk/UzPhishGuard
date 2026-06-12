import os
import sqlite3
import time
import pandas as pd
import streamlit as st
import plotly.express as px

# ==========================================
# ⚙️ STRATEGIK SAHIFA SOZLAMALARI
# ==========================================
st.set_page_config(
    page_title="UzPhishGuard SOC v2 — Threat Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

DB_NAME = "phish_guard.db"

# 🎨 KIBER-SOC TO'Q RANG DIZAYNI (CUSTOM CSS)
st.markdown("""
    <style>
    .main { background-color: #0f111a; color: #ffffff; }
    h1, h2, h3 { color: #00f0ff !important; font-weight: bold; }
    div[data-testid="stMetric"] {
        background-color: #161925 !important;
        border-left: 5px solid #00f0ff !important;
        border-radius: 10px !important;
        padding: 15px !important;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    div[data-testid="stMetric"] label { color: #8a91ad !important; font-size: 14px !important; }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] { color: #00ff66 !important; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

# Sarlavha paneli
st.title("🛡️ UzPhishGuard SOC v2 Dashboard")
st.caption("Next-Gen Llama-3 AI & Global Threat Intel Live Monitoring — Enterprise Edition")
st.markdown("---")

# ==========================================
# 📊 MA'LUMOTLAR BAZASI BILAN ISHLASH
# ==========================================
if not os.path.exists(DB_NAME):
    st.info("🔄 Hozircha ma'lumotlar bazasi topilmadi. Bot guruhda birinchi xabarni ushlashi bilan baza avtomatik yaratiladi.")
else:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM scanned_links ORDER BY id DESC", conn)
    conn.close()

    if df.empty:
        st.warning("⚠️ Baza mavjud, lekin hozircha hech qanday kiber-hujum yoki fishing xabari qayd etilmadi.")
    else:
        # 3-BOSQICH: MULTI-TENANT FILTER (Guruhlar bo'yicha saralash)
        unique_groups = ["Barcha Guruhlar (Global)"] + list(df["chat_title"].dropna().unique())
        
        st.markdown("### 🌐 Monitoring Filteri")
        selected_group = st.selectbox("Saralash uchun guruhni tanlang:", unique_groups)
        
        # Tanlangan guruhga qarab ma'lumotni ajratish
        if selected_group != "Barcha Guruhlar (Global)":
            filtered_df = df[df["chat_title"] == selected_group]
        else:
            filtered_df = df

        # ==========================================
        # 📈 KIBER METRIKALAR (COUNTERS)
        # ==========================================
        total_scans = len(filtered_df)
        blocked_count = len(filtered_df[filtered_df["status"].str.contains("BLOCKED", na=False)])
        avg_risk = int(filtered_df['risk_score'].mean()) if total_scans > 0 else 0

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="JAMI TEKSHIRILDI XABARLAR", value=str(total_scans))
        with col2:
            st.metric(label="BLOKLANDI (FISHING / XAVF)", value=str(blocked_count))
        with col3:
            st.metric(label="O'RTACHA XAVF DARAJASI", value=f"{avg_risk}%")

        st.markdown("<br>", unsafe_allow_html=True)

        # ==========================================
        # 🗺️ JONLI INTERAKTIV KIBER XARITA
        # ==========================================
        st.subheader("🗺️ Live Cyber Threat Map (Hujumlar Koordinatalari)")
        
        # Faqat koordinatalari 0.0 bo'lmagan real serverlarni xaritaga chiqaramiz
        map_df = filtered_df[(filtered_df["latitude"] != 0.0) & (filtered_df["longitude"] != 0.0)]

        if map_df.empty:
            # Standart O'zbekiston markazi koordinatasi
            fig = px.scatter_mapbox(lat=[41.311081], lon=[69.240562], zoom=3)
        else:
            fig = px.scatter_mapbox(
                map_df,
                lat="latitude",
                lon="longitude",
                hover_name="url",
                hover_data={"chat_title": True, "username": True, "ip_address": True, "country": True, "risk_score": True, "latitude": False, "longitude": False},
                color="risk_score",
                color_continuous_scale=["#00ff66", "#ffaa00", "#ff0055"],
                size=[14] * len(map_df),
                zoom=1.5
            )
        
        fig.update_layout(
            mapbox_style="carto-darkmatter", # Haqiqiy kiber-SOC qora xaritasi
            margin={"r": 0, "t": 0, "l": 0, "b": 0},
            paper_bgcolor="#161925",
            plot_bgcolor="#161925",
            font_color="#ffffff",
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

        # ==========================================
        # 🚨 INCIDENT RESPONSE LOGS (JADVAL)
        # ==========================================
        st.subheader("🚨 Real-Time Incident Response Logs")
        
        display_df = filtered_df[["scan_date", "chat_title", "username", "url", "status", "ip_address", "country"]].copy()
        display_df.columns = ["Sana", "Guruh Nomi", "Foydalanuvchi", "Havola (URL)", "Tizim Qarori", "Server IP", "Davlat"]
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # ⚡ 2-BOSQICH: AUTO-REFRESH (Har 10 soniyada sahifani jonli yangilash)
        time.sleep(10)
        st.rerun()
