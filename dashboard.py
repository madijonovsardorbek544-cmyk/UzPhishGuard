import sqlite3
import streamlit as pd_stream
import pandas as pd
import plotly.express as px

pd_stream.set_page_config(
    page_title="UzPhishGuard SOC v2 | SIEM Control Center",
    page_icon="⚡",
    layout="wide"
)

DB_NAME = "phish_guard.db"

def get_v2_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        query = "SELECT scan_date, chat_title, username, url, status, screenshot_path, risk_score FROM scanned_links"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame(columns=["scan_date", "chat_title", "username", "url", "status", "screenshot_path", "risk_score"])

pd_stream.markdown("<h1 style='text-align: center; color: #0F172A;'>🛡️ UzPhishGuard Next-Gen SIEM & Threat Intelligence Dashboard</h1>", unsafe_allow_html=True)
pd_stream.write("---")

df = get_v2_data()

if df.empty:
    pd_stream.info("📡 Tizim tinch holatda. Hujumlar aniqlanishi bilanoq kiber-tahlillar shu yerda aks etadi.")
else:
    total_events = len(df)
    malicious = df[df['status'].str.contains("BLOCKED", na=False)]
    total_phish = len(malicious)
    safety_index = 100 if total_events == 0 else int(((total_events - total_phish) / total_events) * 100)
    
    c1, c2, c3, c4 = pd_stream.columns(4)
    with c1:
        pd_stream.metric(label="📊 Jami Scanned Trafik", value=total_events)
    with c2:
        pd_stream.metric(label="🛑 Tutilgan Kiber Hujumlar", value=total_phish)
    with c3:
        status_color = "normal" if safety_index > 80 else "inverse"
        pd_stream.metric(label="🛡️ Tizim Xavfsizlik Indeksi", value=f"{safety_index}%", delta="Barqaror" if safety_index > 80 else "XAVFLI", delta_color=status_color)
    with c4:
        max_risk = df['risk_score'].max() if not df['risk_score'].empty else 0
        pd_stream.metric(label="🔥 Eng Yuqori Hujum Kuchi", value=f"{max_risk}%")
        
    pd_stream.write("---")
    
    col_left, col_right = pd_stream.columns(2)
    with col_left:
        pd_stream.subheader("📈 Kiber-Hujumlar Vaqt Kesimida Grafigi")
        df['scan_date'] = pd.to_datetime(df['scan_date'])
        df_timeline = df.set_index('scan_date').resample('min').count().reset_index()
        fig_line = px.line(df_timeline, x='scan_date', y='url', title="Hujumlar Oqimi (Real-Time Timeline)", labels={'url': 'Hujumlar Soni'}, color_discrete_sequence=["#EF4444"])
        pd_stream.plotly_chart(fig_line, use_container_width=True)
        
    with col_right:
        pd_stream.subheader("👤 User Risk Score Card")
        user_counts = df['username'].value_counts().reset_index()
        user_counts.columns = ['Foydalanuvchi', 'Yuborilgan Havolalar Soni']
        fig_user = px.bar(user_counts, x='Yuborilgan Havolalar Soni', y='Foydalanuvchi', orientation='h', title="Top Traffic Creators", color='Yuborilgan Havolalar Soni', color_continuous_scale=px.colors.sequential.Blugrn)
        pd_stream.plotly_chart(fig_user, use_container_width=True)

    pd_stream.write("---")
    
    # KIBER-SANDBOX VIEWER
    pd_stream.subheader("🌐 Enterprise Zero-Day Sandbox Screenshot Viewer")
    sandbox_df = df[df['screenshot_path'].notna() & (df['screenshot_path'] != "")]
    
    if not sandbox_df.empty:
        selected_url = pd_stream.selectbox("AI va Urlscan tomonidan skrinshot qilingan fishing saytini tanlang:", sandbox_df['url'].unique())
        img_row = sandbox_df[sandbox_df['url'] == selected_url].iloc[0]
        
        c_img, c_det = pd_stream.columns([2, 1])
        with c_img:
            pd_stream.image(img_row['screenshot_path'], caption=f"Professional Sandbox Skrinshoti: {selected_url}", use_column_width=True)
        with c_det:
            pd_stream.info(f"📋 **Intel Detallari:**\n\n* **Skaner vaqti:** {img_row['scan_date']}\n* **Guruh:** {img_row['chat_title']}\n* **Tarqatuvchi:** @{img_row['username']}\n* **Xavf darajasi:** {img_row['risk_score']}%")
    else:
        pd_stream.info("Sandbox hozircha bo'sh. Fishing havolalar tutilganda kiber-markaz skrinshotlari shu yerda chiqadi.")

    pd_stream.write("---")
    pd_stream.subheader("📋 SIEM Jonli Hodisalar Jurnali")
    log_df = df.sort_index(ascending=False).rename(columns={
        "scan_date": "Skaner Vaqti", "chat_title": "Guruh Nomi", "username": "Foydalanuvchi Akkaunti", "url": "Tekshirilgan URL", "status": "Tizim Qarori", "risk_score": "Xavf Darajasi"
    })
    pd_stream.dataframe(log_df, use_container_width=True)
