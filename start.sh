#!/bin/bash

# 1. Telegram botni orqa fonda (background) ishga tushiramiz
python main.py &

# 2. Streamlit Dashboardni asosiy jarayon sifatida oldingi planda ishga tushiramiz
streamlit run dashboard.py --server.port=8501 --server.address=0.0.0.0
