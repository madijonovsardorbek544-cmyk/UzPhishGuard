FROM python:3.10-slim

# Tizim paketlarini yangilash va Playwright uchun kerakli kutubxonalarni o'rnatish
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    curl \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixees3 \
    librandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright brauzerlarini o'rnatish
RUN playwright install chromium
RUN playwright install-deps

COPY . .

RUN chmod +x start.sh

CMD ["./start.sh"]
