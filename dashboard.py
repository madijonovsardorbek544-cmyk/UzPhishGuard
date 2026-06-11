import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime, timedelta

# Professional SecOps Dashboard Configuration
st.set_page_config(
    page_title="UzPhishGuard | Cyber Threat Intelligence Center",
    page_icon="🛡️",
    layout="wide"
)

DB_NAME = "phish_guard.db"

def fetch_security_logs():
    """Fetches real logs from the production database"""
    try:
        conn = sqlite3.connect(DB_NAME)
        query = "SELECT * FROM scanned_links"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def generate_simulation_data():
    """Generates enterprise-level simulation data if production database is empty"""
    now = datetime.now()
    simulated_data = [
        {"scan_date": (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 5011, "username": "alpha_user", "chat_title": "FinTech_Uz_Community", "url": "https://payme-security-update.com/login", "status": "BLOCKED (Typosquatting)"},
        {"scan_date": (now - timedelta(minutes=14)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 9022, "username": "guest_99", "chat_title": "Global_Crypto_Chat", "url": "https://binance-airdrop-free.net", "status": "BLOCKED (Global VirusTotal)"},
        {"scan_date": (now - timedelta(minutes=32)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 3341, "username": "sardor_dev", "chat_title": "DevOps_Uzbekistan", "url": "https://github.com/aiogram/aiogram", "status": "CLEAN (Passed)"},
        {"scan_date": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 1102, "username": "anon_uz", "chat_title": "Tashkent_Marketplace", "url": "http://olx-uz-safe-transaction.ru/item/2938", "status": "BLOCKED (Mahalliy qora ro'yxat (Blacklist))"},
        {"scan_date": (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 5541, "username": "bek_uz", "chat_title": "FinTech_Uz_Community", "url": "https://click.uz/uz", "status": "CLEAN (Passed)"},
        {"scan_date": (now - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 8831, "username": "victim_zero", "chat_title": "Tashkent_Marketplace", "url": "https://telegram-premium-free.com/gift", "status": "BLOCKED (Shubhali fishing matni (Heuristic))"},
        {"scan_date": (now - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S"), "user_id": 4412, "username": "cyber_scout", "chat_title": "Global_Crypto_Chat", "url": "https://wikipedia.org", "status": "CLEAN (Passed)"}
    ]
    return pd.DataFrame(simulated_data)

# Header Section
st.title("🛡️ UzPhishGuard | Threat Intelligence & Analytics")
st.caption("Enterprise-grade Phishing Detection and Real-time Threat Mitigation Platform")
st.markdown("---")

# Data Engine Router
raw_df = fetch_security_logs()
if raw_df.empty or len(raw_df) == 0:
    st.sidebar.warning("⚠️ Running in Simulation Mode (Database Empty)")
    df = generate_simulation_data()
else:
    st.sidebar.success("🚀 Running on Live Production Data")
    df = raw_df

# Operational Metrics (KPIs)
total_events = len(df)
blocked_threats = len(df[df['status'].str.contains("BLOCKED", na=False)])
clean_traffic = total_events - blocked_threats
mitigation_rate = (blocked_threats / total_events * 100) if total_events > 0 else 0.0

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric(label="Total Network Traffic (Links)", value=total_events)
with col2:
    st.metric(label="Mitigated Threats (Blocked)", value=blocked_threats, delta=f"-{blocked_threats} Threats", delta_color="inverse")
with col3:
    st.metric(label="Verified Safe Traffic", value=clean_traffic)
with col4:
    st.metric(label="Threat Mitigation Rate", value=f"{mitigation_rate:.1f}%")

st.markdown("---")

# Advanced Analytics Visualizations
left_pane, right_pane = st.columns(2)

with left_pane:
    st.markdown("### 📊 Traffic Composition Triage")
    status_summary = df['status'].apply(lambda x: 'Malicious (Threat Blocked)' if 'BLOCKED' in str(x) else 'Benign (Safe Allowed)').value_counts().reset_index()
    status_summary.columns = ['Verdict', 'Event Count']
    
    fig_pie = px.pie(
        status_summary, 
        values='Event Count', 
        names='Verdict', 
        color='Verdict',
        color_discrete_map={'Malicious (Threat Blocked)': '#D32F2F', 'Benign (Safe Allowed)': '#388E3C'},
        hole=0.4
    )
    fig_pie.update_layout(margin=dict(l=20, r=20, t=20, b=20))
    st.plotly_chart(fig_pie, use_container_width=True)

with right_pane:
    st.markdown("### 🚨 Threat Vector Attribution")
    blocked_events = df[df['status'].str.contains("BLOCKED", na=False)].copy()
    
    if not blocked_events.empty:
        blocked_events['Vector'] = blocked_events['status'].apply(lambda x: x.split(" (")[1].replace(")", "") if " (" in str(x) else "Unknown Vector")
        vector_analysis = blocked_events['Vector'].value_counts().reset_index()
        vector_analysis.columns = ['Detection Engine', 'Incidents Intercepted']
        
        fig_bar = px.bar(
            vector_analysis, 
            x='Incidents Intercepted', 
            y='Detection Engine', 
            orientation='h',
            color='Detection Engine',
            color_discrete_sequence=px.colors.sequential.Reds_r
        )
        fig_bar.update_layout(margin=dict(l=20, r=20, t=20, b=20), showlegend=False)
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No malicious vectors vectors detected in the current cycle.")

st.markdown("---")

# Security Audit Trail (SIEM Logs)
st.markdown("### 📋 Security Information and Event Management (SIEM) Logs")
formatted_df = df.copy()
# Re-ordering for professional look
columns_order = ['scan_date', 'chat_title', 'username', 'url', 'status']
if all(col in formatted_df.columns for col in columns_order):
    formatted_df = formatted_df[columns_order]

st.dataframe(
    formatted_df.sort_index(ascending=False), 
    use_container_width=True,
    hide_index=True
)
