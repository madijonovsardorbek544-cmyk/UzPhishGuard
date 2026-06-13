import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go

# Sahifa sozlamalari (Full-width mode)
st.set_page_config(page_title="UzPhishGuard 3D SOC", layout="wide", initial_sidebar_state="collapsed")

# STRATEGIK MA'LUMOTLAR
DATABASE_URL = "postgresql://postgres.quvyyouwtytywtotkdyw:Harvard2030$^^@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres"

def load_data_from_supabase():
    try:
        # Baza bilan ulanish
        conn = psycopg2.connect(DATABASE_URL)
        
        # Avval jadvaldagi haqiqiy ustunlarni aniqlab olamiz
        columns_query = "SELECT column_name FROM information_schema.columns WHERE table_name = 'scanned_links';"
        df_cols = pd.read_sql(columns_query, conn)
        existing_cols = set(df_cols['column_name'].tolist())
        
        # Agar jadval mutlaqo bo'sh bo'lsa yoki topilmasa
        if not existing_cols:
            conn.close()
            return pd.DataFrame()
            
        # Dinamik ravishda bor ustunlarnigina tanlab olamiz
        query_cols = []
        mapping = {
            'chat_title': 'chat_title', 'group_id': 'chat_title',
            'username': 'username', 'user': 'username',
            'url': 'url', 'status': 'status', 'risk_score': 'risk_score',
            'ip_address': 'ip_address', 'country': 'country',
            'latitude': 'latitude', 'longitude': 'longitude',
            'created_at': 'created_at'
        }
        
        for db_col, target_name in mapping.items():
            if db_col in existing_cols:
                query_cols.append(f"{db_col} AS {target_name}")
                # Bir marta mapping qilingach, muqobil variantni tekshirmaslik uchun
                if target_name in ['chat_title', 'username'] and db_col != target_name:
                    continue
                    
        # Dublikatlarni tozalab, SQL so'rovini quramiz
        unique_query_cols = list(set(query_cols))
        
        if 'created_at AS created_at' not in unique_query_cols and 'created_at' in existing_cols:
            unique_query_cols.append('created_at')

        select_clause = ", ".join(unique_query_cols)
        query = f"SELECT {select_clause} FROM scanned_links ORDER BY id DESC LIMIT 500;"
        
        df = pd.read_sql(query, conn)
        conn.close()
        
        # Vaqt formatini xavfsiz o'girish
        if 'created_at' in df.columns:
            df['created_at'] = pd.to_datetime(df['created_at'], errors='coerce')
        else:
            df['created_at'] = pd.Timestamp.now()
            
        return df
    except Exception as e:
        st.error(f"Bazadan ma'lumot olishda xatolik: {e}")
        return pd.DataFrame()

# Ma'lumotlarni yuklash
df = load_data_from_supabase()

# Dizayn sarlavhasi
st.markdown("<h1 style='text-align: center; color: #00F3FF; font-family: monospace;'>🛡️ UZPHISHGUARD SOC v3 — 3D CYBER SIEM</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #888; font-style: italic;'>Real-time WebGL 3D Kiber-tahdidlar Interaktiv Monitoring Markazi</p>", unsafe_allow_html=True)

# Agar ma'lumotlar bo'lsa dashboardni chizamiz
if not df.empty and len(df) > 0:
    
    # 1. METRIKALAR (KPIs)
    total_scanned = len(df)
    blocked_links = len(df[df['status'] == 'BLOCKED'])
    safe_links = len(df[df['status'] == 'SAFE'])
    
    m1, m2, m3 = st.columns(3)
    m1.metric("📊 UMUMIY TRAFIK", total_scanned)
    m2.metric("❌ BLOKLANGAN FISHING", blocked_links, delta=f"+{blocked_links} tahdid", delta_color="inverse")
    m3.metric("✅ XAVFSIZ HAVOLALAR", safe_links)
    
    st.write("---")
    
    # 2. 3D KIBER XARITA (INTERACTIVE NEON GLOBE)
    st.subheader("🌐 Global Incident Map (3D Kiber-Xarita)")
    
    # Koordinata ustunlari borligini tekshirish
    if 'latitude' in df.columns and 'longitude' in df.columns:
        # Bo'sh koordinatalarni tozalash
        map_df = df.dropna(subset=['latitude', 'longitude'])
        
        fig_map = px.scatter_mapbox(
            map_df,
            lat="latitude",
            lon="longitude",
            hover_name="url",
            hover_data=["username", "country", "ip_address", "status"],
            color="status",
            color_discrete_map={"BLOCKED": "#FF0055", "SAFE": "#00FF66"},
            size="risk_score",
            zoom=1.5,
            height=500
        )
        fig_map.update_layout(
            mapbox_style="carto-darkmatter",
            margin={"r":0,"t":0,"l":0,"b":0},
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("Geolokatsiya ma'lumotlari shakllanmoqda...")

    # 3. GRAFIKLAR PANEL
    st.write("---")
    g1, g2 = st.columns(2)
    
    with g1:
        st.subheader("📈 Vaqt bo'yicha hujumlar dinamikasi")
        df_counts = df.set_index('created_at').resample('H').count().reset_index() if 'created_at' in df.columns else df
        fig_line = px.line(df_counts, x='created_at', y='url', title="Hujumlar intensivligi", template="plotly_dark")
        fig_line.update_traces(line_color='#00F3FF')
        st.plotly_chart(fig_line, use_container_width=True)
        
    with g2:
        st.subheader("🎯 Eng ko'p nishonga olingan guruhlar")
        if 'chat_title' in df.columns:
            group_counts = df['chat_title'].value_counts().reset_index()
            group_counts.columns = ['Guruh', 'Soni']
            fig_bar = px.bar(group_counts, x='Guruh', y='Soni', color='Soni', color_continuous_scale='Reds', template="plotly_dark")
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("Guruhlar tahlili yuklanmoqda...")

    # 4. REAL-TIME LOG TABLE
    st.write("---")
    st.subheader("📜 Canli SOC Log Terminali")
    st.dataframe(df, use_container_width=True)

else:
    st.warning("⚠️ Ma'lumotlar bazasi hozircha bo'sh yoki format mos kelmadi. Telegram guruhga fishing havola tashlang va sahifani yangilang!")

# Avtomatik yangilash tugmasi
if st.button("🔄 Zudlik bilan yangilash"):
    st.rerun()
