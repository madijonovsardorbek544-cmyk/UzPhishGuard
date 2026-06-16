import os
import streamlit as st
import pandas as pd
import psycopg2
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

# .env fayldan yoki server muhitidan (Render) o'zgaruvchilarni yuklash
load_dotenv()

# 1. Sahifa Konfiguratsiyasi (Faqat bir marta va eng tepada bo'lishi shart)
st.set_page_config(
    page_title="UzPhishGuard SOC Dashboard v5.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. To'g'ri va Xavfsiz Kiber-Dizayn Stillari (Xatoliksiz variant)
st.markdown("""
    <style>
    /* Asosiy fon va matn ranglari */
    .main { background-color: #060913; color: #e2e8f0; }
    [data-testid="stSidebar"] { background-color: #0b1120; border-right: 2px solid #1e293b; }
    
    /* Neon kiber-kartalar uchun klasslar */
    .metric-box {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        border: 1px solid #3730a3;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.15);
        padding: 20px;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 15px;
    }
    .metric-lbl { 
        font-size: 13px; 
        text-transform: uppercase; 
        letter-spacing: 2px; 
        color: #94a3b8; 
        margin-bottom: 5px; 
    }
    .metric-val { 
        font-size: 32px; 
        font-weight: 800; 
        color: #38bdf8; 
        font-family: 'Courier New', monospace; 
    }
    .metric-val-crit { 
        font-size: 32px; 
        font-weight: 800; 
        color: #f43f5e; 
        font-family: 'Courier New', monospace; 
        text-shadow: 0 0 10px rgba(244, 63, 94, 0.5); 
    }
    </style>
""", unsafe_allow_html=True)

# Supabase ulanish havolasi
DATABASE_URL = os.getenv("DATABASE_URL")

# 3. Ma'lumotlarni Supabase'dan tortish funksiyasi
def fetch_threats_from_supabase():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        query = """
            SELECT id, chat_title, sender_username, threat_type, risk_score, details, detected_at 
            FROM threats 
            ORDER BY detected_at DESC;
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"❌ Supabase SQL ulanishida uzilish: {e}")
        return pd.DataFrame()

# Ma'lumotlar bazasidan jurnallarni o'qish
df_raw = fetch_threats_from_supabase()

# --- SIDEBAR CONTROL PANEL (Yon Panel) ---
st.sidebar.markdown("## ⚙️ SOC boshqaruv paneli")
st.sidebar.markdown("---")
st.sidebar.info("🤖 **Tizim:** UzPhishGuard Core v4.5\n\n🎯 **Status:** Real-time monitoring faol.")

# Baza bo'sh bo'lgan holatni tekshirish
if df_raw.empty:
    st.title("🛡️ UzPhishGuard SIEM Command Center")
    st.markdown("---")
    st.warning("⚠️ Supabase bazasida hozircha kiber-hujumlar jurnali topilmadi. Bot birinchi fishing xabarini ushlashi bilan bu yerda interaktiv 3D grafiklar paydo bo'ladi!")
else:
    df = df_raw.copy()
    df['detected_at'] = pd.to_datetime(df['detected_at'])
    
    # Yon paneldagi tahdid turi bo'yicha filtr
    threat_filter = st.sidebar.multiselect(
        "🔮 Tahdid turlarini filtrlash:",
        options=df['threat_type'].unique(),
        default=df['threat_type'].unique()
    )
    df = df[df['threat_type'].isin(threat_filter)]

    # --- MAIN DASHBOARD INTERFACE (Asosiy Oyna) ---
    st.markdown("# 🛡️ UzPhishGuard — MIT-Tier Cyber Security SIEM Center")
    st.markdown("### 🏢 Markaziy kiber-tahdidlarni tahlil qilish va intellektual monitoring stansiyasi")
    st.markdown("---")

    # 4. KIBER METRIKALAR PANELINI GENERATSIYA QILISH
    total_incidents = len(df)
    critical_incidents = len(df[df['risk_score'] >= 80])
    avg_danger_rate = int(df['risk_score'].mean()) if total_incidents > 0 else 0

    m_col1, m_col2, m_col3 = st.columns(3)
    with m_col1:
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-lbl">🚨 JAMI ANIQLANGAN TAHDIDLAR</div>
                <div class="metric-val">{total_incidents} ta</div>
            </div>
        """, unsafe_allow_html=True)
    with m_col2:
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-lbl">🔴 CRITICAL ATTACKS (💥 RISK >= 80%)</div>
                <div class="metric-val-crit">{critical_incidents} ta</div>
            </div>
        """, unsafe_allow_html=True)
    with m_col3:
        st.markdown(f"""
            <div class="metric-box">
                <div class="metric-lbl">📊 O'RTACHA XAVF KO'RSATKICHI</div>
                <div class="metric-val" style="color: #a855f7;">{avg_danger_rate}%</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # 5. INTERAKTIV 3D VA DYNAMIC GRAFIKLAR
    g_col1, g_col2 = st.columns([1.2, 0.8])

    with g_col1:
        st.subheader("🌐 3D Hujumlar Matritsasi (Scatter 3D)")
        # Vaqtni soniyalarga o'tkazish (Z o'qi uchun)
        df['Time_Seconds'] = df['detected_at'].dt.hour * 3600 + df['detected_at'].dt.minute * 60 + df['detected_at'].dt.second
        
        fig_3d = px.scatter_3d(
            df,
            x='threat_type',
            y='risk_score',
            z='Time_Seconds',
            color='risk_score',
            size='risk_score',
            hover_name='sender_username',
            color_continuous_scale=px.colors.sequential.Sunsetdark,
            labels={'threat_type': 'Tahdid turi', 'risk_score': 'Xavf %', 'Time_Seconds': 'Vaqt (Soniya)'}
        )
        fig_3d.update_layout(
            scene=dict(
                backgroundcolor="#090d16",
                xaxis=dict(backgroundcolor="#0f172a", gridcolor="#334155"),
                yaxis=dict(backgroundcolor="#0f172a", gridcolor="#334155"),
                zaxis=dict(backgroundcolor="#0f172a", gridcolor="#334155"),
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=0, r=0, b=0, t=0)
        )
        st.plotly_chart(fig_3d, use_container_width=True)

    with g_col2:
        st.subheader("🎯 Kiber Taktika Klasteri")
        type_matrix = df['threat_type'].value_counts().reset_index()
        type_matrix.columns = ['Type', 'Count']
        
        fig_donut = go.Figure(data=[go.Pie(
            labels=type_matrix['Type'], 
            values=type_matrix['Count'], 
            hole=.5,
            marker=dict(colors=['#f43f5e', '#38bdf8', '#a855f7', '#10b981'])
        )])
        fig_donut.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color="#94a3b8",
            margin=dict(l=0, r=0, b=0, t=0),
            legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    st.markdown("---")

    # 6. JONLI LOG JADVALI (Incident Feed)
    st.subheader("📋 Jonli Tahdidlar Voqeligining Jurnali")
    search_bar = st.text_input("🔍 Guruh nomi yoki foydalanuvchi username bo'yicha tezkor qidiruv:")
    
    if search_bar:
        df = df[
            df['chat_title'].str.contains(search_bar, case=False, na=False) | 
            df['sender_username'].str.contains(search_bar, case=False, na=False)
        ]

    st.dataframe(
        df[['detected_at', 'chat_title', 'sender_username', 'threat_type', 'risk_score', 'details']],
        use_container_width=True,
        column_config={
            "detected_at": "Vaqt",
            "chat_title": "Guruh nomi",
            "sender_username": "Hujumchi",
            "threat_type": "Tahdid turi",
            "risk_score": st.column_config.ProgressColumn("Xavf ko'rsatkichi", min_value=0, max_value=100, format="%d%%"),
            "details": "AI Diagnostika"
        }
    )
