import sqlite3
import streamlit as pd_stream
import pandas as pd
import plotly.express as px

pd_stream.set_page_config(
    page_title="UzPhishGuard SOC v2 | Threat Map Center",
    page_icon="⚡",
    layout="wide"
)

DB_NAME = "phish_guard.db"

def get_v2_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        query = "SELECT * FROM scanned_links"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

pd_stream.markdown("<h1 style='text-align: center; color: #1E293B;'>🛡️ UzPhishGuard Next-Gen SIEM & Live Cyber Threat Map</h1>", unsafe_allow_html=True)
pd_stream.write("---")

df = get_v2_data()

if df.empty or len(df) == 0:
    pd_stream.info("📡 Tizim tinch holatda. Hujumlar aniqlanishi bilanoq kiber-xarita va tahlillar shu yerda aks etadi.")
else:
    # Narigi ustunlar mavjudligini tekshirish (yangi baza uchun)
    if 'latitude' not in df.columns:
        df['latitude'] = 0.0
        df['longitude'] = 0.0
        df['country'] = "Unknown"
        df['ip_address'] = "0.0.0.0"

    total_events = len(df)
    malicious = df[df['status'].str.contains("BLOCKED", na=False)]
    total_phish = len(malicious)
    safety_index = int(((total_events - total_phish) / total_events) * 100)
    
    c1, c2, c3, c4 = pd_stream.columns(4)
    with c1:
        pd_stream.metric(label="📊 Jami Scanned Trafik", value=total_events)
    with c2:
        pd_stream.metric(label="🛑 Tutilgan Kiber Hujumlar", value=total_phish)
    with c3:
        pd_stream.metric(label="🛡️ Tizim Xavfsizlik Indeksi", value=f"{safety_index}%")
    with c4:
        max_risk = df['risk_score'].max() if not df['risk_score'].empty else 0
        pd_stream.metric(label="🔥 Eng Yuqori Hujum Kuchi", value=f"{max_risk}%")
        
    pd_stream.write("---")
    
    # 🌍 1-QADAM: LIVE CYBER THREAT MAP
    pd_stream.subheader("🌐 Real-Time Global Cyber Threat Map")
    
    # Faqat bloklangan va koordinatasi aniq bo'lgan nuqtalarni xaritaga chizamiz
    map_df = df[(df['latitude'] != 0.0) & (df['status'].str.contains("BLOCKED", na=False))]
    
    if not map_df.empty:
        fig_map = px.scatter_mapbox(
            map_df,
            lat="latitude",
            lon="longitude",
            hover_name="url",
            hover_data=["country", "ip_address", "username", "risk_score"],
            color="risk_score",
            size=[15] * len(map_df),
            color_continuous_scale=px.colors.sequential.Reds,
            zoom=1,
            height=500
        )
        fig_map.update_layout(mapbox_style="open-street-map")
        fig_map.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
        pd_stream.plotly_chart(fig_map, use_container_width=True)
    else:
        pd_stream.info("🌍 Xarita tayyor. Bloklangan xavfli serverlar koordinatalari aniqlanishi bilan kiber-nuqtalar shu yerda ko'rinadi.")

    pd_stream.write("---")
    
    col_left, col_right = pd_stream.columns(2)
    with col_left:
        pd_stream.subheader("📈 Hujumlar Oqimi (Timeline)")
        df['scan_date'] = pd.to_datetime(df['scan_date'])
        df_timeline = df.set_index('scan_date').resample('min').count().reset_index()
        fig_line = px.line(df_timeline, x='scan_date', y='url', labels={'url': 'Hujumlar Soni'}, color_discrete_sequence=["#EF4444"])
        pd_stream.plotly_chart(fig_line, use_container_width=True)
        
    with col_right:
        pd_stream.subheader("👤 Top Risk Creators (User Card)")
        user_counts = df['username'].value_counts().reset_index()
        user_counts.columns = ['Foydalanuvchi', 'Yuborilgan Havolalar']
        fig_user = px.bar(user_counts, x='Yuborilgan Havolalar', y='Foydalanuvchi', orientation='h', color_continuous_scale=px.colors.sequential.Blugrn)
        pd_stream.plotly_chart(fig_user, use_container_width=True)

    pd_stream.write("---")
    
    # KIBER-SANDBOX VIEWER
    pd_stream.subheader("🌐 Enterprise Zero-Day Sandbox Screenshot Viewer")
    sandbox_df = df[df['screenshot_path'].notna() & (df['screenshot_path'] != "")]
    
    if not sandbox_df.empty:
        selected_url = pd_stream.selectbox("Skaner qilingan saytni tanlang:", sandbox_df['url'].unique())
        img_row = sandbox_df[sandbox_df['url'] == selected_url].iloc[0]
        
        c_img, c_det = pd_stream.columns([2, 1])
        with c_img:
            pd_stream.image(img_row['screenshot_path'], use_column_width=True)
        with c_det:
            pd_stream.info(f"📋 **Intel Detallari:**\n\n* **Skaner vaqti:** {img_row['scan_date']}\n* **Server IP:** `{img_row.get('ip_address', '0.0.0.0')}`\n* **Davlat:** {img_row.get('country', 'Unknown')}\n* **Guruh:** {img_row['chat_title']}\n* **Tarqatuvchi:** @{img_row['username']}\n* **Xavf:** {img_row['risk_score']}%")

    pd_stream.write("---")
    pd_stream.subheader("📋 SIEM Jonli Hodisalar Jurnali")
    pd_stream.dataframe(df.sort_index(ascending=False), use_container_width=True)
