#!/bin/bash

# 1. Telegram botni orqa fonda xavfsiz ishga tushiramiz
echo "🤖 Asinxron UzPhishGuard Bot fonda ishga tushmoqda..."
python main.py &

# 2. Streamlit'ni Render portiga moslab oldingi plonga chiqaramiz.
# Bu Render'dagi "Port Timeout" xatosini 100% yo'q qiladi.
echo "📊 SOC Dashboard Render asosiy portida ishga tushmoqda..."
streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0
