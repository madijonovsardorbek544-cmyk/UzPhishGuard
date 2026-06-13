import os
import pandas as pd
import streamlit as st
import plotly.express as px
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
    page_title="UzPhishGuard SOC v2",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# 2. NEON CYBER-PUNK SOC CSS
# ==========================================
st.markdown("""
    <style>
    /* Umumiy fon va neon effektlar */
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
    h1, h2, h3 { color: #ffffff !important; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 3. KESHLASH VA OPTIMIZATSIYA (Xatosiz vaqt)
# ==========================================
@st.cache_data(ttl=3, show_spinner=False) 
def load_data():
    if not DATABASE_URL:
        return pd.DataFrame()
    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            # Ustunlar mavjudligini kafolatlash uchun to'g'ridan-to'g'ri chaqiramiz
            query = "SELECT * FROM scanned_links ORDER BY id DESC;"
            df = pd.read_sql(query, conn)
            
            if not df.empty:
                # Ustun nomlarini kichik harfga o'tkazish (Xavfsizlik uchun)
                df.columns = [col.lower() for col in df.columns]
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
    st.markdown("<h1 style='text-align: center; color: #00F2FE; text-shadow: 0 0 20px rgba(0,242,254,0.6); font-family: monospace;'>🛡️ UZPHISHGUARD SOC v2 — ULTRA SIEM</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #8b949e; font-size: 14px;'>Real-time Kiber-tahdidlar Monitoringi va Avtomatik Incident Response Markazi</p>", unsafe_allow_html=True)
    st.write("")

    df = load_data()

    if df.empty:
        st.warning("⚠️ Ma'lumotlar bazasi bo'sh yoki ulanish o'rnatilmadi.")
        return

    # ==========================================
    # 4. SIDEBAR (Filtrlar)
    # ==========================================
    with st.sidebar:
        st.markdown("<h3 style='color: #00F2FE;'>⚙️ SOC Controller</h3>", unsafe_allow_html=True)
        if st.button("🔄 Majburiy Sinxronizatsiya", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
        
        st.write("---")
        if 'chat_title' in df.columns:
            all_groups = ["Barcha Guruhlar"] + list(df['chat_title'].dropna().unique())
            selected_group = st.selectbox("🎯 Guruh Filtri:", all_groups)
            if selected_group != "Barcha Guruhlar":
                df = df[df['chat_title'] == selected_group]

    # Statuslarni tekshirish (Katta/kichik harf muammosiz)
    status_col = 'status' if 'status' in df.columns else df.columns[4] # fail-safe
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
    # 6. GEOLOKATSIYA VA PIE CHART
    # ==========================================
    g1, g2 = st.columns([2, 1])

    with g1:
        st.markdown("#### 🗺️ Jonli Kiber-Hujumlar Geolokatsiyasi")
        # Xarita koordinatalarini xavfsiz tekshirish
        if 'latitude' in df.columns and 'longitude' in df.columns:
            map_data = df[(df[status_col] == 'BLOCKED') & (df['latitude'].notna()) & (df['latitude'] != 0.0)]
            if not map_data.empty:
                fig_map = px.scatter_mapbox(
                    map_data, lat="latitude", lon="longitude", hover_name="url" if "url" in map_data.columns else None,
                    color="risk_score" if "risk_score" in map_data.columns else None, 
                    color_continuous_scale="Reds", size_max=15, zoom=1, height=400
                )
                fig_map.update_layout(mapbox_style="carto-darkmatter", margin={"r":0,"t":0,"l":0,"b":0}, paper_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig_map, use_container_width=True)
            else:
                st.info("ℹ️ Xaritada ko'rsatish uchun koordinatali bloklangan tahdidlar hozircha yo'q.")
        else:
            st.info("ℹ️ Geolokatsiya ustunlari bazada topilmadi.")

    with g2:
        st.markdown("#### 🎯 Tahdid Geografiyasi")
        country_col = 'country' if 'country' in df.columns else None
        if country_col and not df[df[status_col] == 'BLOCKED'].empty:
            c_data = df[df[status_col] == 'BLOCKED'][country_col].value_counts().reset_index()
            c_data.columns = ['Davlat', 'Hujumlar']
            fig_pie = px.pie(c_data, names='Davlat', values='Hujumlar', hole=0.5, color_discrete_sequence=px.colors.sequential.Reds_r)
            fig_pie.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, paper_bgcolor="rgba(0,0,0,0)", showlegend=False)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.caption("Bloklangan davlatlar tahlili mavjud emas.")

    # ==========================================
    # 7. INTERAKTIV JADVAL (Dinamik Ustunlar!)
    # ==========================================
    st.write("---")
    st.markdown("### 📋 SIEM Interaktiv Loglar (Deep Dive)")

    # Haqiqiy ma'lumot chiqishi uchun ustunlarni to'g'ridan-to'g'ri o'qiymiz
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

    st.markdown("<p style='text-align: center; color: #30363d; margin-top: 50px; font-family: monospace;'>UzPhishGuard SOC Tizimi v2.5 | Enterprise Edition</p>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
