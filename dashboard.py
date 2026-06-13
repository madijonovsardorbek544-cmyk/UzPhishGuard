import os
import pandas as pd
import streamlit as st
import plotly.express as px
import pydeck as pdk  # 3D Xarita uchun WebGL kutubxonasi
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# .env yuklash
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# ==========================================
# 1. ENTERPRISE SAHIFA SOZLAMALARI
# ==========================================
st.set_page_config(
    page_title="UzPhishGuard 3D SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# 2. NEON CYBER-PUNK SOC CSS
# ==========================================
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; }
    div[data-testid="metric-container"] {
        background-color: #161b22;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #30363d;
        border-left: 6px solid #00f2fe;
        box-shadow: 0 5px 15px rgba(0,0,0,0.5);
    }
    div[data-testid="metric-container"]:nth-child(2) { border-left-color: #ff4b4b; }
    div[data-testid="metric-container"]:nth-child(3) { border-left-color: #00cc96; }
    div[data-testid="metric-container"]:nth-child(4) { border-left-color: #fecb52; }
    h1, h2, h3, h4 { color: #ffffff !important; font-family: 'Courier New', Courier, monospace; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 3. KESHLASH VA OPTIMIZATSIYA
# ==========================================
@st.cache_data(ttl=3, show_spinner=False) 
def load_data():
    if not DATABASE_URL:
        return pd.DataFrame()
    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            query = "SELECT * FROM scanned_links ORDER BY id DESC;"
            df = pd.read_sql(query, conn)
            
            if not df.empty:
                df.columns = [col.lower() for col in df.columns]
                
                # Soxta test satrlarini (chat_title, username yozuvlarini) bazadan o'chirish
                if 'chat_title' in df.columns:
                    df = df[~df['chat_title'].astype(str).str.contains('chat_title|username|url', case=False, na=False)]
                
                if 'created_at' in df.columns:
                    df['created_at'] = pd.to_datetime(df['created_at'], errors='coerce', utc=True)
                if 'risk_score' in df.columns:
                    df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce').fillna(0).astype(int)
            return df
    except Exception as e:
        st.error(f"Baza xatoligi: {e}")
        return pd.DataFrame()

def main():
    # Kiber Sarlavha
    st.markdown("<h1 style='text-align: center; color: #00F2FE; text-shadow: 0 0 20px rgba(0,242,254,0.6); font-family: monospace;'>🛡️ UZPHISHGUARD SOC v3 — 3D CYBER SIEM</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #8b949e; font-size: 14px;'>Real-time WebGL 3D Kiber-tahdidlar Interaktiv Monitoring Markazi</p>", unsafe_allow_html=True)
    st.write("")

    df = load_data()

    if df.empty:
        st.warning("⚠️ Ma'lumotlar bazasi hozircha bo'sh yoki faqat test satrlari mavjud edi (ular tozalandi). Telegrambotga yangi havola tashlang!")
        return

    # ==========================================
    # 4. SIDEBAR
    # ==========================================
    with st.sidebar:
        st.markdown("<h3 style='color: #00F2FE;'>⚙️ 3D SOC Controller</h3>", unsafe_allow_html=True)
        if st.button("🔄 Zudlik bilan yangilash", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
        
        st.write("---")
        if 'chat_title' in df.columns:
            all_groups = ["Barcha Guruhlar"] + list(df['chat_title'].dropna().unique())
            selected_group = st.selectbox("🎯 Guruh Filtri:", all_groups)
            if selected_group != "Barcha Guruhlar":
                df = df[df['chat_title'] == selected_group]

    status_col = 'status' if 'status' in df.columns else df.columns[4]
    df[status_col] = df[status_col].astype(str).str.upper()

    # ==========================================
    # 5. LIVE METRIKALAR PANEL
    # ==========================================
    total_scanned = len(df)
    total_blocked = len(df[df[status_col] == 'BLOCKED'])
    total_safe = len(df[df[status_col] == 'SAFE'])
    phishing_rate = round((total_blocked / total_scanned) * 100, 1) if total_scanned > 0 else 0.0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🌐 Jami Trafik (Links)", total_scanned)
    m2.metric("🚫 Bloklangan Hujumlar", total_blocked, delta=f"{total_blocked} Tahdid" if total_blocked > 0 else None, delta_color="inverse")
    m3.metric("✅ Toza Havolalar", total_safe)
    m4.metric("📊 Fishing Nisbati (Rate)", f"{phishing_rate}%")

    st.write("---")

    # ==========================================
    # 6. 3D INTERAKTIV GEOLOKATSIYA XARITASI (PyDeck)
    # ==========================================
    st.markdown("### 🗺️ Jonli 3D Kiber-Hujumlar Globus Simulyatsiyasi (WebGL)")
    
    if 'latitude' in df.columns and 'longitude' in df.columns:
        # Faqat koordinatali va bloklangan xavflarni olamiz
        map_data = df[(df[status_col] == 'BLOCKED') & (df['latitude'].notna()) & (df['latitude'] != 0.0)].copy()
        
        # Ustun balandligi uchun xavf darajasini ko'paytiramiz (3D vizual effekt uchun)
        if not map_data.empty:
            map_data['elevation'] = map_data['risk_score'] * 500
            
            # PyDeck 3D Qatlami (Har bir hujum - kiber-ustun ko'rinishida)
            layer = pdk.Layer(
                "ColumnLayer",
                data=map_data,
                get_position="[longitude, latitude]",
                get_elevation="elevation",
                elevation_scale=10,
                radius=40000,
                get_fill_color="[255, 75, 75, 200]", # Neon Qizil ustunlar
                pickable=True,
                auto_highlight=True,
            )
            
            # Xarita ko'rinish kamerasi (Kiber-dizayn burchagi)
            view_state = pdk.ViewState(
                latitude=map_data['latitude'].mean(),
                longitude=map_data['longitude'].mean(),
                zoom=1.5,
                pitch=45, # 3D qiyalik burchagi
                bearing=30
            )
            
            # 3D render qilish
            r = pdk.Deck(
                layers=[layer],
                initial_view_state=view_state,
                map_style="mapbox://styles/mapbox/dark-v10", # To'q qora xarita
                tooltip={"text": "Tahdid: {url}\nXavf: {risk_score}%\nIP: {ip_address}\nDavlat: {country}"}
            )
            st.pydeck_chart(r)
        else:
            st.info("ℹ️ 3D Xaritada ko'rsatish uchun koordinatali JONLI bloklangan tahdidlar hozircha yo'q. Botga fishing link tashlashingiz bilan bu yerda 3D ustunlar paydo bo'ladi!")
    else:
        st.info("ℹ️ Geolokatsiya ma'lumotlari mavjud emas.")

    # ==========================================
    # 7. INTERAKTIV JADVAL (Toza Real Loglar)
    # ==========================================
    st.write("---")
    st.markdown("### 📋 SIEM Interaktiv Loglar (Deep Dive)")

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=380,
        column_config={
            "created_at": st.column_config.DatetimeColumn("Vaqt (UTC)", format="YYYY-MM-DD HH:mm"),
            "url": st.column_config.LinkColumn("Tekshirilgan Havola", max_chars=60),
            "risk_score": st.column_config.ProgressColumn("Xavf Darajasi", format="%d%%", min_value=0, max_value=100),
            "status": "Holati",
            "chat_title": "Guruh nomi",
            "username": "User",
            "ip_address": "IP Manzil",
            "country": "Davlat"
        }
    )

    st.markdown("<p style='text-align: center; color: #30363d; margin-top: 50px; font-family: monospace;'>UzPhishGuard SOC Tizimi v3.0 | 3D Enterprise Edition © 2026</p>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
