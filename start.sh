#!/bin/bash

# 1. Streamlit dashboardni Render porti orqali fonda (&) ishga tushirish
# Bu Render skanerini aldash va "No open ports detected" xatosini yo'qotish uchun kerak
streamlit run dashboard.py --server.port $PORT --server.address 0.0.0.0 &

# 2. Telegram botni asosiy jarayon sifatida ishga tushirish
python app/bot/main.py
