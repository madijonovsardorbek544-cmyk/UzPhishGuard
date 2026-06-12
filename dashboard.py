import os
import streamlit as tf
import psycopg2
import pandas as pd
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv

# .env yuklash
load_dotenv()

# Sahifa konfiguratsiyasi (Enterprise SIEM uslubida)
tf.set_page_config(
    page_title="UzPhishGuard SOC v2 — SIEM Center",
    page_icon="🛡️",
    layout="wide"
)

# PostgreSQL (Supabase) ulanish funksiyasi
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        tf.error("Kritik xatolik: DATABASE_URL muhit o'zgaruvchisi topilmadi!")
        return None
    try:
        conn = psycopg2.connect(db_url)
        return conn
    except Exception as e:
        tf.error(f"Ma'lumotlar bazasiga ulanishda xatolik: {e}")
        return None

# Ma'lumotlarni bazadan tortib olish
def load_data():
    conn = get_db_connection()
    if conn is None:
        return pd.DataFrame()
    
    query = """
        SELECT id, group_id, chat_title, user_id, username, url, status, 
               risk_score, ip_address, country, latitude, longitude, created_at 
        FROM scanned_links 
        ORDER BY created_at DESC;
    """
    try:
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        tf.error(f"Ma'lumotlarni o'qishda xatolik (Schema mos emas): {e}")
        if conn:
            conn.close()
        return pd.DataFrame()

# Ma'lumotlarni yuklash
df = load_data()

# Sarlavha qismi
tf.markdown("<h1 style='text-align: center; color: #00F2FE;'>🛡️ UzPhishGuard SOC v2 — Jonli SIEM Dashboard</h1>", unsafe_allow_html=True)
tf.markdown("<p style='text-align: center; color: #888;'>Supabase Cloud DB va IP Enrichment orqali real vaqt rejimida ishlovchi professional kiber-tahlil markazi.</p>", unsafe_allow_html=True)
tf.markdown("---")

if df.empty:
    tf.info("ℹ️ Tizimda hozircha hech qanday hodisalar aniqlanmadi. Monitoring rejimi faol!")
else:
    # Sidebar — Filtrlash tizimi (Multi-Tenant Markazi)
    tf.sidebar.header("🎯 Multi-Tenant Markazi")
    chats = ["Barcha Guruhlar"] + list(df['chat_title'].dropna().unique())
    selected_chat = tf.sidebar.selectbox("Filtrni tanlang:", chats)
    
    # Ma'lumotlarni filtrga asosan kesish
    if selected_chat != "Barcha Guruhlar":
        df_filtered = df[df['chat_title'] == selected_chat]
    else:
        df_filtered = df

    # Asosiy Metrikalar (KPI Cards)
    total_scanned = len(df_filtered)
    blocked_count = len(df_filtered[df_filtered['status'] == 'BLOCKED'])
    safe_count = len(df_filtered[df_filtered['status'] == 'SAFE'])
    
    # Fishing foizi hisobi
    phish_rate = (blocked_count / total_scanned * 100) if total_scanned > 0 else 0.0

    m1, m2, m3, m4 = tf.columns(4)
    with m1:
        tf.metric(label="📈 Jami Tekshirilgan Havolalar", value=total_scanned)
    with m2:
        tf.metric(label="❌ Bloklangan Fishing Hujumlar", value=blocked_count, delta=f"+{blocked_count} ta tahdid", delta_color="inverse")
    with m3:
        tf.metric(label="✅ Xavfsiz Deb Topilganlar", value=safe_count)
    with m4:
        tf.metric(label="📊 Fishing Nisbati (Rate)", value=f"{phish_rate:.1f}%")

    tf.markdown("---")

    # Grafika bo'limi (Ikki ustunli vizualizatsiya)
    g1, g2 = tf.columns([2, 1])

    with g1:
        tf.subheader("🗺️ Global Kiber-Hujumlar Real-Time Geolokatsiya Xaritasi")
        
        # Faqat koordinatalari aniq bo'lgan va bloklangan fishinglarni xaritada ko'rsatamiz
        map_df = df_filtered[(df_filtered['status'] == 'BLOCKED') & (df_filtered['latitude'] != 0.0)]
        
        if map_df.empty:
            tf.warning("⚠️ Hozircha bloklangan fishing serverlarining geolokatsiya ma'lumotlari mavjud emas (yoki barcha havolalar xavfsiz).")
        else:
            fig_map = px.scatter_mapbox(
                map_df,
                lat="latitude",
                lon="longitude",
                hover_name="url",
                hover_data=["ip_address", "country", "username", "chat_title"],
                color="risk_score",
                size="risk_score",
                color_continuous_scale=px.colors.sequential.Colorbrewer,
                size_max=15,
                zoom=1,
                mapbox_style="carto-darkmatter"
            )
            fig_map.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            tf.plotly_chart(fig_map, use_container_width=True)

    with g2:
        tf.subheader("📊 Hujum Manbalari (Davlatlar)")
        blocked_df = df_filtered[df_filtered['status'] == 'BLOCKED']
        if blocked_df.empty:
            tf.write("Tahdidlar aniqlanmadi.")
        else:
            country_counts = blocked_df['country'].value_counts().reset_index()
            country_counts.columns = ['Davlat', 'Soni']
            fig_pie = px.pie(
                country_counts, 
                values='Soni', 
                names='Davlat', 
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_pie.update_layout(showlegend=True, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            tf.plotly_chart(fig_pie, use_container_width=True)

    tf.markdown("---")

    # Jonli Loglar va Tafsilotlar Jadvali
    tf.subheader("📋 SIEM Markazi Oqayotgan Jonli Hodisalar Logi (Incident Logs)")
    
    # Jadvalni foydalanuvchiga chiroyli ko'rsatish uchun ustunlarni saralash
    display_df = df_filtered[[
        'created_at', 'chat_title', 'username', 'url', 'status', 'risk_score', 'ip_address', 'country'
    ]].copy()
    
    display_df.columns = [
        'Vaqt', 'Guruh Nomi', 'Foydalanuvchi', 'Tekshirilgan URL', 'Holat', 'Xavf Balli', 'IP Manzil', 'Server Davlati'
    ]
    
    tf.dataframe(display_df, use_container_width=True, hide_index=True)
