#!/bin/bash

# 1. Ma'lumotlar bazasini noldan tekshirish va yaratish uchun bir marta asosiy kodni yurgizamiz
python -c "import main; main.init_db()"

# 2. Telegram botni mustaqil fonda ishga tushirish
python main.py &

# 3. Streamlit dashboardni asosiy jarayon sifatida portda yoqish
streamlit run dashboard.py --server.port=8501 --server.address=0.0.0.0
