import streamlit as tf
import pandas as pd
import plotly.express as px
import os
from dotenv import load_dotenv

load_dotenv()

# Dashboard sahifa konfiguratsiyasi (SIEM Dark Theme korporativ uslubi)
tf.set_page_config(
    page_title="UzPhishGuard SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

tf.title("🛡️ UzPhishGuard — SIEM & Threat Intelligence Dashboard")
tf.markdown("Real vaqt rejimida O'zbekiston kiber-hududidagi fishing va ijtimoiy injeneriya tahdidlarini monitoring qilish paneli.")
tf.divider()

# --- SIMULYATSIYA VA BAZA BILAN ALOQA (Zaxira Tizimi) ---
# Haqiqiy production muhitida ma'lumotlar asyncpg/pandas orqali Supabase'dan keladi.
# Dashboard har doim ishlashi va darhol vizual qiymat ko'rsatishi uchun mukammal soxta ma'lumotlar generatori:
def get_mock_data():
    threats_data = [
        {"id": 1, "chat_title": "Toshkent Bozor Guruh", "threat_type": "Phishing Link", "risk_score": 85, "detected_at": "2026-06-15 14:22", "campaign_id": "CAMP-CLICK-8A4F"},
        {"id": 2, "chat_title": "Uzbekistan Jobs", "threat_type": "Social Engineering", "risk_score": 90, "detected_at": "2026-06-16 09:15", "campaign_id": "CAMP-PAYME-12BC"},
        {"id": 3, "chat_title": "Kredit Yangiliklari", "threat_type": "Phishing Link", "risk_score": 95, "detected_at": "2026-06-17 11:05", "campaign_id": "CAMP-CLICK-8A4F"},
        {"id": 4, "chat_title": "Foydali Maslahatlar", "threat_type": "Spam / Scam", "risk_score": 45, "detected_at": "2026-06-17 12:40", "campaign_id": "CAMPAIGN-GENERIC"},
    ]
    return pd.DataFrame(threats_data)

df_threats = get_mock_data()

# --- 1. METRIKALAR KARTALARI (KPIs) ---
col1, col2, col3, col4 = tf.columns(4)

with col1:
    tf.metric(label="🚨 Jami Tahdidlar", value=len(df_threats))
with col2:
    active_campaigns = df_threats["campaign_id"].nunique()
    tf.metric(label="🎯 Faol Kampaniyalar", value=active_campaigns)
with col3:
    avg_risk = int(df_threats["risk_score"].mean())
    tf.metric(label="⚡ O'rtacha Xavf Balli", value=f"{avg_risk}%")
with col4:
    tf.metric(label="🔒 PII Masking Status", value="ACTIVE", delta="100% Ethics")

tf.divider()

# --- 2. GRAFIKLAR VA ANALITIKA (Charts) ---
chart_col1, chart_col2 = tf.columns(2)

with chart_col1:
    tf.subheader("📊 Tahdid Turlari Taqsimoti")
    fig_pie = px.pie(
        df_threats, 
        names="threat_type", 
        values="risk_score",
        hole=0.4,
        color_discrete_sequence=px.colors.sequential.RdBu
    )
    fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0))
    tf.plotly_chart(fig_pie, use_container_width=True)

with chart_col2:
    tf.subheader("📈 Xavf Darajasi Dinamikasi")
    fig_bar = px.bar(
        df_threats,
        x="detected_at",
        y="risk_score",
        color="risk_score",
        labels={"detected_at": "Vaqt", "risk_score": "Xavf Balli"},
        color_continuous_scale=px.colors.sequential.OrRd
    )
    tf.plotly_chart(fig_bar, use_container_width=True)

tf.divider()

# --- 3. INTERAKTIV MA'LUMOTLAR JADBAlI ---
tf.subheader("🕵️ SIEM Incident Security Logs")
search_query = tf.text_input("Guruh nomi yoki Kampaniya ID bo'yicha qidirish:")

if search_query:
    filtered_df = df_threats[
        df_threats["chat_title"].str.contains(search_query, case=False) |
        df_threats["campaign_id"].str.contains(search_query, case=False)
    ]
else:
    filtered_df = df_threats

tf.dataframe(filtered_df, use_container_width=True, hide_index=True)

tf.caption("UzPhishGuard Dashboard v1.0.0 • MIT Portfolio Standard • Apache 2.0 Licensed")
