import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px

# ==========================================
# 🎨 SAHIFANING ASOSIY SOZLAMALARI (UI/UX)
# ==========================================
st.set_page_config(
    page_title="UzPhishGuard SOC v2 — SIEM Threat Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Kiber-xavfsizlik markazlariga xos bo'lgan Dark Mode CSS dizayni
st.markdown("""
    <style>
    .main { background-color: #0E1117; color: #FFFFFF; }
    h1, h2, h3 { color: #00F0FF !important; text-shadow: 0 0 10px rgba(0,240,255,0.5); }
    .stSelectbox label { color: #00F0FF !important; }
    div[data-testid="stMetricValue"] { color: #FF0055 !important; font-size: 2.5rem !important; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

DB_NAME = "phish_guard.db"

def load_data():
    """Ma'lumotlar bazasidan jonli kiber-hodisalarni yuklash"""
    try:
        conn = sqlite3.connect(DB_NAME)
        query = "SELECT * FROM scanned_links"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Ma'lumotlar bazasiga ulanishda xato: {e}")
        return pd.DataFrame()

# Ma'lumotlarni bazadan o'qish
df = load_data()

# ==========================================
# 📊 STRATEGIK REJA: MULTI-TENANT FILTER
# ==========================================
st.title("🛡️ UzPhishGuard SOC v2 — Jonli SIEM Dashboard")
st.write("Real vaqt rejimida guruhlardagi kiber-hujumlar monitoringi va tahlil markazi.")

if df.empty:
    st.info("🔄 Tizimda hozircha hech qanday kiber-hodisalar qayd etilmadi. Bot guruhlarda faollashishi bilan ma'lumotlar shu yerda chiqadi.")
else:
    # Bo'sh guruh nomlari bo'lsa tozalash
    df['chat_title'] = df['chat_title'].fillna('Shaxsiy Chat / Noma'lum')
    
    # Guruh adminlari o'z guruhini tanlashi uchun mukammal filtr (Multi-Tenant)
    st.sidebar.header("🎯 SOC Filtr Markazi")
    available_groups = ["Barcha Guruhlar"] + list(df['chat_title'].unique())
    selected_group = st.sidebar.selectbox("Guruhni tanlang:", available_groups)
    
    # Tanlangan guruhga qarab ma'lumotlarni saralash
    if selected_group != "Barcha Guruhlar":
        df_filtered = df[df['chat_title'] == selected_group]
    else:
        df_filtered = df

    # ==========================================
    # 📈 KIBER-METRIKALAR (LIVE STATS)
    # ==========================================
    total_scans = len(df_filtered)
    blocked_count = len(df_filtered[df_filtered['status'].str.contains('BLOCKED', na=False)])
    clean_count = total_scans - blocked_count
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="🌐 Jami Tahlillar", value=total_scans)
    with col2:
        st.metric(label="🛑 Zararsizlantirildi (Fishing)", value=blocked_count)
    with col3:
        st.metric(label="🟢 Xavfsiz Havolalar", value=clean_count)

    st.markdown("---")

    # ==========================================
    # 🗺️ GEO-THREAT MAP & PIE CHART
    # ==========================================
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.subheader("🗺️ Global Kiber-Hujumlar Geolokatsiya Xaritasi")
        # Faqat koordinatalari bor va bloklangan fishing xavflarini xaritada ko'rsatish
        df_map = df_filtered[(df_filtered['latitude'].notnull()) & (df_filtered['longitude'].notnull()) & (df_filtered['status'].str.contains('BLOCKED', na=False))]
        
        if not df_map.empty:
            fig_map = px.scatter_mapbox(
                df_map, 
                lat="latitude", 
                lon="longitude", 
                hover_name="url", 
                hover_data=["country", "ip_address", "risk_score"],
                color="risk_score",
                size="risk_score",
                color_continuous_scale=px.colors.sequential.Colorbrewer,
                size_max=15, 
                zoom=1, 
                height=450
            )
            fig_map.update_layout(mapbox_style="carto-darkmatter", margin={"r":0,"t":0,"l":0,"b":0})
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("ℹ️ Tanlangan guruh bo'yicha xaritaga yuklash uchun geolokatsiyali bloklangan xavflar hozircha mavjud emas.")

    with col_right:
        st.subheader("📊 Davlatlar Tahlili")
        if not df_filtered.empty and df_filtered['country'].notnull().any():
            fig_country = px.pie(df_filtered, names='country', title='Xavflar kelib chiqishi', hole=0.4)
            fig_country.update_layout(template="plotly_dark")
            st.plotly_chart(fig_country, use_container_width=True)
        else:
            st.write("Ma'lumot mavjud emas")

    st.markdown("---")

    # ==========================================
    # 📋 SIEM INCIDENT LOGS (JURNAL)
    # ==========================================
    st.subheader("📋 Oxirgi Kiber-Hodisalar Jurnali (Logs)")
    
    # Kerakli ustunlarni tartiblash va eng oxirgisini tepada ko'rsatish
    columns_to_show = ['scan_date', 'chat_title', 'username', 'url', 'status', 'risk_score', 'ip_address', 'country']
    # Mavjud ustunlarni tekshirib olish (xatolik bermasligi uchun)
    existing_cols = [c for c in columns_to_show if c in df_filtered.columns]
    
    display_df = df_filtered[existing_cols].sort_index(ascending=False)
    st.dataframe(display_df, use_container_width=True)
