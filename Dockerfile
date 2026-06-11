# 1. Eng barqaror va engil Python muhitini tanlaymiz
FROM python:3.10-slim

# 2. Konteyner ichida ishchi papka yaratamiz
WORKDIR /app

# 3. Tizim paketlarini yangilaymiz va kerakli Linux instrumentlarini o'rnatamiz
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    git \
    && rm -rf /var/lib/apt/lists/*

# 4. Bog'liqliklar ro'yxatini konteynerga nusxalaymiz
COPY requirements.txt .

# 5. Barcha Python kutubxonalarini keshsiz, tezkor o'rnatamiz
RUN pip install --no-cache-dir -r requirements.txt

# 6. Loyihaning barcha kodlari va fayllarini konteyner ichiga ko'chiramiz
COPY . .

# 7. Veb-sayt (Streamlit dashboard) ishlaydigan portni ochib qo'yamiz
EXPOSE 8501

# 8. start.sh skript fayliga ishga tushish huquqini beramiz
RUN chmod +x start.sh

# 9. Konteyner yonganda start.sh skriptini ishga tushiramiz
CMD ["./start.sh"]
