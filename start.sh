#!/bin/bash

# 1. Fondagi Telegram botni ishga tushiramiz va loglarini saqlaymiz
echo "Telegram bot ishga tushirilmoqda..."
python main.py > bot.log 2>&1 &

# 2. Asosiy jarayon sifatida Streamlit dashboardni portda yoqamiz
echo "Streamlit dashboard ishga tushirilmoqda..."
streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0
