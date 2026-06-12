#!/bin/bash

# 1. Streamlit dashboardini orqa fonda (background) port 8501 da ishga tushirish
echo "📊 SOC Dashboard ishga tushmoqda..."
streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0 &

# 2. Asosiy asinxron bot jarayonini oldingi plonda (foreground) ishga tushirish
# Bu orqali Docker/Render bot o'chib qolsa, konteynerni qayta start qilishi mumkin
echo "🤖 Asinxron UzPhishGuard Bot ishga tushmoqda..."
python main.py
