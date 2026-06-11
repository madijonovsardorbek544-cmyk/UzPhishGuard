# 1. Eng barqaror va barcha paketlar ichida tayyor bo'lgan rasmiy Python imiji
FROM python:3.10

# 2. Konteyner ichida ishchi papka yaratamiz
WORKDIR /app

# 3. Bog'liqliklar ro'yxatini va loyiha fayllarini konteynerga nusxalaymiz
COPY requirements.txt .

# 4. Python kutubxonalarini tezkor o'rnatamiz
RUN pip install --no-cache-dir -r requirements.txt

# 5. Qolgan barcha kodlarni nusxalash
COPY . .

# 6. Veb-sayt portini ochamiz
EXPOSE 8501

# 7. start.sh skriptiga ruxsat berish
RUN chmod +x start.sh

# 8. Konteyner yonganda start.sh skriptini ishga tushiramiz
CMD ["./start.sh"]
