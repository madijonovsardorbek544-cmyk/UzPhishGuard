import sqlite3
import streamlit as pd_stream
import pandas as pd
import plotly.express as px
from datetime import datetime

# Sahifa sozlamalari
pd_stream.set_page_config(
    page_title="UzPhishGuard | Kiber-Tahlil Paneli",
    page_icon="🛡️",
    layout="wide"
)

DB_NAME = "phish_guard.db"

def get_dashboard_data():
    """Ma'lumotlar bazasidan barcha skanerlash statistikasini oladi."""
    try:
        conn = sqlite3.connect(DB_NAME)
        query = "SELECT scan_date, chat_title, username, url, status FROM scanned_links"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        # Agar baza hali bo'sh bo'lsa yoki topilmasa test ma'lumot ko'rsatadi
        return pd.DataFrame(columns=["scan_date", "chat_title", "username", "url", "status"])

# Sarlavha qismi
pd_stream.markdown("<h1 style='text-align: center; color: #1E3A8A;'>🛡️ UzPhishGuard Real-Time Cyber Security Dashboard</h1>", unsafe_allow_html=True)
pd_stream.markdown("<p style='text-align: center; color: #6B7280;'>Guruhlarni fishing va kiber-hujumlardan himoya qilish tizimi statistikasi</p>", unsafe_allow_html=True)
pd_stream.write("---")

df = get_dashboard_data()

if df.empty:
    pd_stream.info("📊 Hozircha ma'lumotlar bazasi bo'sh. Bot guruhlarda ishlashni boshlagach, statistika shu yerda yangilanadi.")
else:
    # 1. METRIKALAR (Asosiy raqamlar)
    total_scans = len(df)
    blocked_count = df[df['status'].str.contains("BLOCKED", na=False)].shape[0]
    clean_count = df[df['status'] == "CLEAN (Passed)"].shape[0]
    
    col1, col2, col3 = pd_stream.columns(3)
    with col1:
        pd_stream.metric(label="🔎 Jami skaner qilingan havolalar", value=total_scans)
    with col2:
        pd_stream.metric(label="🛑 Bloklangan fishing hujumlar", value=blocked_count, delta=f"{blocked_count} ta xavf", delta_color="inverse")
    with col3:
        pd_stream.metric(label="✅ Xavfsiz deb topilganlar", value=clean_count)
        
    pd_stream.write("---")
    
    # 2. GRAFIKLAR BO'LIMI
    left_col, right_col = pd_stream.columns(2)
    
    with left_col:
        pd_stream.subheader("📊 Havolalar holati nisbati")
        # Statuslarni chiroyli guruhlash
        df['Analiz Natijasi'] = df['status'].apply(lambda x: "Fishing (Bloklandi)" if "BLOCKED" in str(x) else "Xavfsiz (O'tkazildi)")
        fig_pie = px.pie(df, names='Analiz Natijasi', color='Analiz Natijasi',
                         color_discrete_map={"Fishing (Bloklandi)": "#EF4444", "Xavfsiz (O'tkazildi)": "#10B981"},
                         hole=0.4)
        pd_stream.plotly_chart(fig_pie, use_container_width=True)
        
    with right_col:
        pd_stream.subheader("🛑 Aniqlangan fishing turlari (Metodlar)")
        # Faqat bloklanganlarni filterlash
        blocked_df = df[df['status'].str.contains("BLOCKED", na=False)].copy()
        if not blocked_df.empty:
            def extract_reason(status_str):
                if "(" in status_str and ")" in status_str:
                    return status_str.split("(")[1].split(")")[0]
                return "Boshqa"
            
            blocked_df['Metod'] = blocked_df['status'].apply(extract_reason)
            reason_counts = blocked_df['Metod'].value_counts().reset_index()
            reason_counts.columns = ['Kiber-Metod', 'Soni']
            
            fig_bar = px.bar(reason_counts, x='Kiber-Metod', y='Soni', color='Kiber-Metod',
                             title="Qaysi himoya qatlami ko'p xavfni ushladi?",
                             color_discrete_sequence=px.colors.sequential.Reds_r)
            pd_stream.plotly_chart(fig_bar, use_container_width=True)
        else:
            pd_stream.info("Hozircha guruhlarda birorta ham fishing xavfi aniqlanmadi.")

    pd_stream.write("---")
    
    # 3. JONLI JURNAL (LATEST LOGS)
    pd_stream.subheader("📋 Oxirgi skanerlash harakatlarining jonli jurnali")
    
    # Jadvalni chiroyli ko'rinishga keltirish
    display_df = df.sort_index(ascending=False).rename(columns={
        "scan_date": "Skaner vaqti",
        "chat_title": "Guruh nomi",
        "username": "Foydalanuvchi",
        "url": "Tekshirilgan Havola",
        "status": "Tizim Qarori"
    })
    
    pd_stream.dataframe(display_df, use_container_width=True)
