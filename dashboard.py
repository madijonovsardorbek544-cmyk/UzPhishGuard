import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px

# ==========================================
# 1. SAHIFA KONFIGURATSIYASI (Professional UI)
# ==========================================
st.set_page_config(page_title="UzPhishGuard 3D SOC", page_icon="🛡️", layout="wide")

# STRATEGIK MA'LUMOTLAR BAZASI
DATABASE_URL = "postgresql://postgres.quvyyouwtytywtotkdyw:Harvard2030$^^@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres"

# ==========================================
# 2. XATOGA CHIDAMLI BAZA (FAIL-SAFE DB CONNECTION)
# ==========================================
@st.cache_data(ttl=3) # Ma'lumotlarni har 3 soniyada xavfsiz yangilaydi
def fetch_cyber_data():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        # Barcha ma'lumotlarni xom holatda olamiz (SQL chalkashliklarsiz)
        query = "SELECT * FROM scanned_links ORDER BY id DESC LIMIT 1000;"
        df = pd.read_sql(query, conn)
        conn.close()
        
        # 👑 DUBILIKAT XATOLIKNI 100% YO'QOTISH (Narwhals xatosi yechimi):
        # Agar bazada tasodifan bir xil nomli ustunlar bo'lsa, ularni avtomatik tozalaymiz
        df = df.loc[:, ~df.columns.duplicated()].copy()
        
        # Ustunlarni standartizatsiya qilish (Dinamik moslashuv)
        if 'group_id' in df.columns and 'chat_title' not in df.columns:
            df.rename(columns={'group_id': 'chat_title'}, inplace=True)
        if 'user' in df.columns and 'username' not in df.columns:
            df.rename(columns={'user': 'username'}, inplace=True)
            
        # Vaqt formatini xatosiz to'g'rilash
        if 'created_at' in df.columns:
            df['created_at'] = pd.to_datetime(df['created_at'], errors='coerce')
            
        return df
    except Exception as e:
        st.error(f"❌ Kiber-xarita bazasiga ulanishda xatolik: {e}")
        return pd.DataFrame()

# Ma'lumotlarni chaqiramiz
df = fetch_cyber_data()

# ==========================================
# 3. ASOSIY DASHBOARD INTERFEYSI
# ==========================================
st.markdown("<h1 style='text-align: center; color: #00E5FF; text-shadow: 0px 0px 10px #00E5FF; font-family: monospace;'>🛡️ UZPHISHGUARD SOC v3 — ENTERPRISE SIEM</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #A0A0A0; font-style: italic; margin-bottom: 30px;'>Real-time WebGL 3D Kiber-tahdidlar Interaktiv Monitoring Markazi</p>", unsafe_allow_html=True)

if not df.empty:
    
    # Zarur ustunlar bor-yo'qligini xavfsiz tekshiramiz
    required_cols = ['status', 'latitude', 'longitude', 'risk_score']
    for col in required_cols:
        if col not in df.columns:
            df[col] = "SAFE" if col == 'status' else 0

    # ==========================================
    # 4. KPI METRIKALAR (JONLI STATISTIKA)
    # ==========================================
    total_events = len(df)
    blocked_events = len(df[df['status'] == 'BLOCKED'])
    safe_events = len(df[df['status'] == 'SAFE'])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="🌐 UMUMIY TRAFIK TAHLILI", value=total_events)
    with col2:
        st.metric(label="🚨 BLOKLANGAN FISHING HUJUMLAR", value=blocked_events, delta=f"+{blocked_events} kritik tahdid", delta_color="inverse")
    with col3:
        st.metric(label="✅ XAVFSIZ HAVOLALAR", value=safe_events)
        
    st.markdown("<hr style='border: 1px solid #333;'>", unsafe_allow_html=True)

    # ==========================================
    # 5. 3D GLOBAL INCIDENT MAP (NEON XARITA)
    # ==========================================
    st.subheader("🌍 Kiber-Hujumlar Geografiyasi (3D SOC Map)")
    
    # Xarita ma'lumotlarini tozalash va qat'iy tipga (float) o'girish (Crashni oldini oladi)
    map_df = df.dropna(subset=['latitude', 'longitude']).copy()
    map_df['latitude'] = pd.to_numeric(map_df['latitude'], errors='coerce').fillna(41.2995)
    map_df['longitude'] = pd.to_numeric(map_df['longitude'], errors='coerce').fillna(69.2401)
    map_df['risk_score'] = pd.to_numeric(map_df['risk_score'], errors='coerce').fillna(10)
    
    fig_map = px.scatter_mapbox(
        map_df,
        lat="latitude",
        lon="longitude",
        hover_name="url" if 'url' in map_df.columns else None,
        hover_data=["username", "country", "ip_address", "status"] if 'country' in map_df.columns else None,
        color="status",
        color_discrete_map={"BLOCKED": "#FF0044", "SAFE": "#00FF66"},
        size="risk_score",
        zoom=1.8,
        height=600
    )
    fig_map.update_layout(
        mapbox_style="carto-darkmatter", # Haqiqiy xakerlik dark mode xaritasi
        margin={"r":0,"t":0,"l":0,"b":0},
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )
    st.plotly_chart(fig_map, use_container_width=True)

    # ==========================================
    # 6. ANALITIK GRAFIKLAR
    # ==========================================
    st.markdown("<hr style='border: 1px solid #333;'>", unsafe_allow_html=True)
    g1, g2 = st.columns(2)
    
    with g1:
        st.subheader("📈 Hujumlar Dinamikasi (Vaqt bo'yicha)")
        if 'created_at' in df.columns:
            time_df = df.copy()
            time_df['vaqt'] = time_df['created_at'].dt.strftime('%H:%M')
            timeline = time_df.groupby('vaqt').size().reset_index(name='Tahdidlar soni')
            fig_line = px.line(timeline, x='vaqt', y='Tahdidlar soni', template="plotly_dark", markers=True)
            fig_line.update_traces(line_color='#00E5FF', line_width=3, marker=dict(size=8, color='#FF0044'))
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("Vaqt ma'lumotlari shakllanmoqda...")
            
    with g2:
        st.subheader("🎯 Nishonga olingan Guruhlar")
        if 'chat_title' in df.columns:
            group_counts = df['chat_title'].fillna("Noma'lum").value_counts().reset_index()
            group_counts.columns = ['Guruh', 'Hujumlar Soni']
            fig_bar = px.bar(group_counts, x='Guruh', y='Hujumlar Soni', color='Hujumlar Soni', 
                             color_continuous_scale='Reds', template="plotly_dark")
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("Guruh ma'lumotlari shakllanmoqda...")

    # ==========================================
    # 7. XAVFSIZLIK LOGLARI (TERMINAL JADVAL)
    # ==========================================
    st.markdown("<hr style='border: 1px solid #333;'>", unsafe_allow_html=True)
    st.subheader("📜 SOC Security Logs (Jonli tranzaksiyalar)")
    
    # Ekranda faqat mavjud va muhim ustunlarni ko'rsatamiz
    display_cols = [c for c in ['created_at', 'chat_title', 'username', 'url', 'status', 'risk_score', 'ip_address', 'country'] if c in df.columns]
    
    st.dataframe(
        df[display_cols].style.applymap(
            lambda x: 'color: #FF0044; font-weight: bold;' if x == 'BLOCKED' else ('color: #00FF66;' if x == 'SAFE' else ''),
            subset=['status'] if 'status' in df.columns else []
        ),
        use_container_width=True,
        height=300
    )

else:
    st.warning("⚠️ Baza hozircha bo'sh. Telegram bot orqali guruhga havolalar yuboring va xarita avtomatik jonlanadi!")

# ==========================================
# 8. JONLI YANGILASH TIZIMI
# ==========================================
if st.button("🔄 Zudlik bilan yangilash", use_container_width=True):
    st.cache_data.clear()
    st.rerun()
