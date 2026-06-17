#!/bin/bash

# dashboard.py faylining haqiqiy joylashgan yo'lini ko'rsatamiz
streamlit run app/dashboard/dashboard.py --server.port $PORT --server.address 0.0.0.0 &

# Telegram botni ishga tushirish
python app/bot/main.py
