import os
import pandas as pd
import streamlit as st
import plotly.express as px
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# .env faylini yuklash
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# ==========================================
# 1. SAHIFA KONFIGURATSIYASI (Enterprise SOC)
# ==========================================
st.set_page_config(
    page_title="UzPhishGuard SOC | Enterprise SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# 2. CUSTOM CSS (Neon SOC ko'rinishi)
# ==========================================
st.markdown("""
    <style>
    div[data-testid="metric-container"] {
        background-color: #1a1c23;
        padding: 15px;
        border-radius: 12px;
        border-left: 5px solid #ff4b4b;
        box-shadow: 0 4px 10px rgba(0,0,0,0.4);
    }
    div[data-testid="metric-container"]:nth-child(1) { border-left-color: #00f2fe; }
    div[data-testid="metric-container"]:nth-child(3) { border-left-color: #00cc96; }
    div[data-testid="metric-container"]:nth-child(4) { border-left-color: #fecb52; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 3. KESHLASH VA OPTIMIZATSIYA (Xatosiz vaqt formati)
# ==========================================
@st.cache_data(ttl=5, show_spinner=False) 
def load_data():
    if not DATABASE_URL:
        return pd.DataFrame()
    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            query = "SELECT * FROM scanned_links ORDER BY created_at DESC;"
            df = pd.read_sql(query, conn)
            if not df.empty:
                # Muammo to'liq tuzatildi: errors='coerce' va utc=True qo'shildi
                df['created_at'] = pd.to_datetime(df['created_at'], errors='coerce', utc=True)
            return df
    except Exception as e:
        st.error(f"Ma'lumotlar bazasiga ulanishda xatolik: {e}")
        return pd.DataFrame()

def main():
    # Sarlavha
    st.markdown("<h1 style='text-align: center; color: #00F2FE; text-shadow: 0 0 15px rgba(0,242,254,0.5);'>🛡️ UzPhishGuard SOC v2 — Enterprise SIEM</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #A0AEC0; margin-bottom: 30px;'>Global kiber-tahdidlarni real vaqt rejimida kuzatish, IP boyitish va AI orqali tahlil qilish markazi</p>", unsafe_allow_html=True)

    df = load_data()

    if df.empty:
        st.warning("⚠️ Ma'lumotlar bazasida hozircha hech qanday hodisa yo'q yoki ulanish o'rnatilmadi. Tizim kutish rejimida...")
        return

    # ==========================================
    # 4. SIDEBAR (Boshqaruv va Filtrlar)
    # ==========================================
    with st.sidebar:
        st.header("⚙️ SOC Boshqaruv Paneli")
        
        if st.button("🔄 Zudlik bilan yangilash", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
            
        st.write("---")
        st.header("🎯 Multi-Tenant Filtr")
        all_groups = ["Barcha Guruhlar"] + list(df['chat_title'].dropna().unique())
        selected_group = st.selectbox("Guruhni tanlang:", all_groups)

    # Filtrni qo'llash
    if selected_group != "Barcha Guruhlar":
        filtered_df = df[df['chat_title'] == selected_group]
    else:
        filtered_df = df

    # ==========================================
    # 5. ASOSIY METRIKALAR
    # ==========================================
    total_scanned = len(filtered_df)
    total_blocked = len(filtered_df[filtered_df['status'] == 'BLOCKED'])
    total_safe = len(filtered_df[filtered_df['status'] == 'SAFE'])
    phishing_rate = round((total_blocked / total_scanned) * 100, 1) if total_scanned > 0 else 0.0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🌐 Jami Tekshirildi", total_scanned)
    col2.metric("🚫 Bloklangan Tahdidlar", total_blocked, delta=f"{total_blocked} ta xavf", delta_color="inverse")
    col3.metric("✅ Xavfsiz Havolalar", total_safe)
    col4.metric("📊 Tahdid Indeksi (Rate)", f"{phishing_rate}%")

    st.write("---")

    # ==========================================
    # 6. VIZUAL GRAFIKLAR (Xarita va Davlatlar)
    # ==========================================
    r1_col1, r1_col2 = st.columns([2, 1])

    with r1_col1:
        st.subheader("🗺️ Global Kiber-Hujumlar Xaritasi (Live)")
        map_data = filtered_df[(filtered_df['status'] == 'BLOCKED') & (filtered_df['latitude'] != 0.0) & (filtered_df['latitude'].notna())]
        
        if not map_data.empty:
            # Muammo to'liq tuzatildi: Palitra "Reds" qilib sozlandi
            fig_map = px.scatter_mapbox(
                map_data, lat="latitude", lon="longitude", hover_name="url",
                hover_data={"latitude": False, "longitude": False, "username": True, "country": True, "ip_address": True, "risk_score": True},
                color="risk_score", color_continuous_scale="Reds", size="risk_score",
                zoom=1.2, height=450
            )
            fig_map.update_layout(
                mapbox_style="carto-darkmatter", margin={"r":0,"t":0,"l":0,"b":0},
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)"
            )
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("ℹ️ Hozircha geo-lokatsiyaga ega jonli fishing tahdidlari mavjud emas.")

    with r1_col2:
        st.subheader("🎯 Hujum Manbalari")
        blocked_df = filtered_df[filtered_df['status'] == 'BLOCKED']
        if not blocked_df.empty:
            country_counts = blocked_df['country'].value_counts().reset_index()
            country_counts.columns = ['Davlat', 'Soni']
            fig_pie = px.pie(
                country_counts, names='Davlat', values='Soni', hole=0.6,
                color_discrete_sequence=px.colors.sequential.Reds_r
            )
            fig_pie.update_layout(
                margin={"r":10,"t":10,"l":10,"b":10},
                paper_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            fig_pie.add_annotation(text="IP Geo", x=0.5, y=0.5, font_size=14, showarrow=False)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.write("Manbalar mavjud emas.")

    st.write("---")

    # ==========================================
    # 7. TAHDIDLAR DINAMIKASI (Timeline)
    # ==========================================
    st.subheader("📈 Tahdidlar Dinamikasi (Vaqt bo'yicha)")
    time_df = filtered_df.copy()
    
    # Faqat vaqt formati muvaffaqiyatli o'qilgan qatorlarni chiqaramiz
    time_df = time_df[time_df['created_at'].notna()]
    
    if not time_df.empty:
        time_df['Soat'] = time_df['created_at'].dt.floor('H')
        time_grouped = time_df.groupby(['Soat', 'status']).size().reset_index(name='Soni')
        
        fig_bar = px.bar(
            time_grouped, x='Soat', y='Soni', color='status',
            color_discrete_map={'BLOCKED': '#ff4b4b', 'SAFE': '#00cc96'},
            barmode='group', height=300
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin={"r":10,"t":10,"l":10,"b":10},
            xaxis_title="Vaqt", yaxis_title="Xabarlar soni"
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("Vaqt tahlili uchun ma'lumot yetarli emas.")

    # ==========================================
    # 8. INTERAKTIV JADVAL (Smart Progress Bar)
    # ==========================================
    st.write("---")
    st.subheader("📋 SIEM Interaktiv Loglar (Deep Dive)")
    
    display_df = filtered_df[['created_at', 'chat_title', 'username', 'url', 'status', 'risk_score', 'ip_address', 'country']].copy()
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=400,
        column_config={
            "created_at": st.column_config.DatetimeColumn("Vaqt (UTC)", format="YYYY-MM-DD HH:mm"),
            "chat_title": "Guruh",
            "username": "Foydalanuvchi",
            "url": st.column_config.LinkColumn("Tekshirilgan Havola", max_chars=50),
            "status": "Holati",
            "risk_score": st.column_config.ProgressColumn(
                "Xavf (% Progress)", 
                help="AI tahlili bo'yicha xavflilik darajasi", 
                format="%d", 
                min_value=0, 
                max_value=100
            ),
            "ip_address": "IP Manzil",
            "country": "Davlat"
        }
    )

    st.markdown("<p style='text-align: center; color: #555; margin-top: 60px;'>UzPhishGuard SOC v2 Enterprise © 2026 | Barcha huquqlar himoyalangan</p>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
