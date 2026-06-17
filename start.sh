#!/bin/bash

# 1. Streamlit dashboardni Render taqdim etgan portda fonda ishga tushiramiz
# Bu Render port skanerini darhol qoniqtiradi va "Timed Out" xatosini yo'qotadi
echo "📊 SOC Dashboard Render portida ishga tushmoqda..."
streamlit run app/dashboard/dashboard.py --server.port ${PORT:-8501} --server.address 0.0.0.0 &

# Dashboard ishga tushishi uchun 3 soniya kutamiz
sleep 3

# 2. Telegram botni asosiy jarayon (Foreground) sifatida ishga tushiramiz
echo "🤖 Asinxron UzPhishGuard Bot ishga tushmoqda..."
python app/bot/main.py
