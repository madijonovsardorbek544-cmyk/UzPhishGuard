# Barqaror Python versiyasi
FROM python:3.10-slim

# Ishchi papka
WORKDIR /app

# Server paketlarini minimal ko'rinishda yangilaymiz (Muammo tug'dirgan paket olib tashlandi)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Kutubxonalarni yuklash va o'rnatish
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Loyihaning barcha fayllarini nusxalash
COPY . .

# Dashboard uchun port
EXPOSE 8501

# Skriptga ruxsat berish
RUN chmod +x start.sh

# Ishga tushirish
CMD ["./start.sh"]
