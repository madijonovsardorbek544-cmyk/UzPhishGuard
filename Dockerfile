# 1. Rasmiy yengil Python tasvirini yuklash
FROM python:3.10-slim

# 2. Tizim ichidagi ishchi papkani belgilash
WORKDIR /app

# 3. Kerakli tizim paketlarini o'rnatish (Androguard va kompilyatsiya uchun)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 4. Kutubxonalar ro'yxatini nusxalash va o'rnatish
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Butun loyiha kodlarini konteyner ichiga ko'chirish
COPY . .

# 6. Python loyiha yo'lini tizimga tanitish (Import xatoliklarini oldini oladi)
ENV PYTHONPATH=/app

# 7. Default komanda (start.sh skriptiga ruxsat berib, uni ishga tushiramiz)
RUN chmod +x start.sh
CMD ["./start.sh"]
