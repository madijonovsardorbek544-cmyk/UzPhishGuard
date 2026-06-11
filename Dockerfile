# Base image sifatida eng barqaror Python versiyasini tanlaymiz
FROM python:3.10-slim

# Server ichida loyiha papkasini ochamiz
WORKDIR /app

# Tizim uchun kerakli paketlarni yangilaymiz
RUN apt-get update && apt-get install -y \
    build-essential \
    software-properties-common \
    git \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt faylini serverga nusxalaymiz
COPY requirements.txt .

# Barcha kerakli Python kutubxonalarni o'rnatamiz
RUN pip install --no-cache-dir -r requirements.txt

# Loyihaning qolgan barcha kodlarini server ichiga nusxalaymiz
COPY . .

# Serverda dashboard ochilishi uchun portni ochiq qilamiz
EXPOSE 8501

# Maxsus ishga tushirish skriptiga ruxsat beramiz
RUN chmod +x start.sh

# Loyihani ishga tushirish buyrug'i
CMD ["./start.sh"]
