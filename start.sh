#!/bin/bash

# 1. Telegram botni orqa fonda xavfsiz ishga tushiramiz (Yangi yo'nalish)
echo "🤖 Asinxron UzPhishGuard Bot fonda ishga tushmoqda..."
python app/bot/main.py &

# 2. Streamlit'ni Render portiga moslab ishga tushiramiz.
# PORT muhit o'zgaruvchisi Render tomonidan avtomat beriladi ($PORT)
echo "📊 SOC Dashboard Render portida ishga tushmoqda..."
streamlit run app/dashboard/dashboard.py --server.port ${PORT:-8501} --server.address 0.0.0.0
