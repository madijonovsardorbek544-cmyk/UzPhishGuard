import streamlit as st
import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd
import plotly.express as px
import os

st.set_page_config(
    page_title="UzPhishGuard SOC v2 — SIEM Threat Map",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
    .main { background-color: #0E1117; color: #FFFFFF; }
    h1, h2, h3 { color: #00F0FF !important; text-shadow: 0 0 10px rgba(0,240,255,0.5); }
    div[data-testid="stMetricValue"] { color: #FF0055 !important; font-size: 2.5rem !important; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

DATABASE_URL = os.getenv("DATABASE_URL")

def load_data():
    """Supabase PostgreSQL-dan ma'lumotlarni real vaqtda yuklash"""
    if not DATABASE_URL:
        st.error("DATABASE_URL topilmadi. Render paneli sozlamalarini tekshiring.")
        return pd.DataFrame()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        query = "SELECT * FROM scanned_links"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"PostgreSQL-dan ma'lumot yuklashda xato: {e}")
        return pd.DataFrame()

df = load_data()

st.title("🛡️ UzPhishGuard SOC v2 — Jonli SIEM Dashboard")
st.write("Supabase Cloud DB orqali real vaqt rejimida ishlovchi professional kiber-tahlil markazi.")

if df.empty:
    st.info("🔄 Tizimda hozircha hech qanday hodisalar aniqlanmadi. Monitoring rejimi faol!")
else:
    df['chat_title'] = df['chat_title'].fillna('Shaxsiy Chat')
    
    st.sidebar.header("🎯 Multi-Tenant Markazi")
    available_groups = ["Barcha Guruhlar"] + list(df['chat_title'].unique())
    selected_group = st.sidebar.selectbox("Filtrni tanlang:", available_groups)
    
    df_filtered = df if selected_group == "Barcha Guruhlar" else df[df['chat_title'] == selected_group]

    # Haqiqiy formula bo'yicha samaradorlikni hisoblash (Claude so'ragan talab)
    total_scans = len(df_filtered)
    blocked_count = len(df_filtered[df_filtered['status'].str.contains('BLOCKED', na=False)])
    clean_count = total_scans - blocked_count
    efficiency = round((blocked_count / total_scans * 100), 1) if total_scans > 0 else 100.0

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="🌐 Jami Tahlillar", value=total_scans)
    with col2:
        st.metric(label="🛑 Zararsizlantirildi", value=blocked_count)
    with col3:
        st.metric(label="🟢 Xavfsiz Havolalar", value=clean_count)
    with col4:
        st.metric(label="🎯 Haqiqiy Himoya", value=f"{efficiency}%")

    st.markdown("---")

    col_left, col_right = st.columns([2, 1])
    with col_left:
        st.subheader("🗺️ Global Kiber-Hujumlar Real-Time Geolokatsiya Xaritasi")
        df_map = df_filtered[(df_filtered['latitude'].notnull()) & (df_filtered['longitude'].notnull()) & (df_filtered['status'].str.contains('BLOCKED', na=False))]
        if not df_map.empty:
            fig_map = px.scatter_mapbox(
                df_map, lat="latitude", lon="longitude", hover_name="url",
                hover_data=["country", "ip_address", "risk_score"],
                color="risk_score", size="risk_score",
                color_continuous_scale=px.colors.sequential.YlOrRd, zoom=1, height=450
            )
            fig_map.update_layout(mapbox_style="carto-darkmatter", margin={"r":0,"t":0,"l":0,"b":0})
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("Xaritada vizualizatsiya qilish uchun fishing hodisasi hozircha yo'q.")

    with col_right:
        st.subheader("📊 Tahdid Manbalari")
        if not df_filtered.empty and df_filtered['country'].notnull().any():
            fig_country = px.pie(df_filtered, names='country', title='Davlatlar kesimida', hole=0.3)
            fig_country.update_layout(template="plotly_dark")
            st.plotly_chart(fig_country, use_container_width=True)
        else:
            st.write("Ma'lumot kam.")

    st.markdown("---")
    st.subheader("📋 SIEM Incident Jurnali (Jonli Loglar)")
    cols = ['scan_date', 'chat_title', 'username', 'url', 'status', 'risk_score', 'ip_address', 'country']
    st.dataframe(df_filtered[[c for c in cols if c in df_filtered.columns]].sort_index(ascending=False), use_container_width=True)
