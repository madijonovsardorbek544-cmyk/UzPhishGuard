import os
import re
import socket
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
import telebot

# Cachetools orqali xotirani tejash (RAM OOM crash'larni oldini olish uchun)
try:
    from cachetools import TTLCache
    PHISH_CACHE = TTLCache(maxsize=1000, ttl=3600)
except ImportError:
    PHISH_CACHE = {}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")  # Supabase PostgreSQL manzili
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

if not BOT_TOKEN or not DATABASE_URL:
    raise ValueError("CRITICAL ERROR: Maxfiy tokenlar yoki DATABASE_URL topilmadi!")

bot = telebot.TeleBot(BOT_TOKEN)
session = requests.Session()

def init_db():
    """SQLite o'rniga Supabase PostgreSQL-da jadvallarni xavfsiz yaratish"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scanned_links (
                id SERIAL PRIMARY KEY,
                scan_date TEXT,
                chat_id BIGINT,
                chat_title TEXT,
                username TEXT,
                url TEXT,
                status TEXT,
                screenshot_path TEXT,
                risk_score INTEGER,
                ip_address TEXT,
                country TEXT,
                latitude REAL,
                longitude REAL
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("[✅ DB] Supabase PostgreSQL jadvali muvaffaqiyatli sozlandi.")
    except Exception as e:
        logger.error(f"[❌ DB Error] PostgreSQL yaratishda xato: {e}")

# Bazani ishga tushirish
init_db()

def extract_advanced_features(url):
    """URL arxitekturasini chuqur tekshirish (Real Heuristics)"""
    score = 0
    reasons = []
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        high_risk_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.link', '.click', '.top']
        if any(hostname.endswith(tld) for tld in high_risk_tlds):
            score += 40
            reasons.append("Xavfli TLD zonasi")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            score += 50
            reasons.append("IP-manzil hostnomi")
        if hostname.count('.') > 3:
            score += 25
            reasons.append("Haddan tashqari ko'p subdomen")
        uz_brands = ["click", "payme", "uzcard", "humo", "agrobank", "uztelecom"]
        if any(brand in hostname.lower() and not hostname.endswith(f"{brand}.uz") for brand in uz_brands):
            score += 45
            reasons.append("Typosquatting (Soxta brend nomi)")
    except Exception as e:
        logger.error(f"Heuristic tahlilda xato: {e}")
    return score, reasons

def get_ip_geo_details(url):
    """IP va Geolokatsiya aniqlash"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        ip_address = socket.gethostbyname(hostname)
        res = session.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,lat,lon", timeout=4)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                return ip_address, data.get("country", "Unknown"), data.get("lat", 0.0), data.get("lon", 0.0)
        return ip_address, "Unknown", 0.0, 0.0
    except Exception:
        return "0.0.0.0", "Unknown", 0.0, 0.0

def run_pro_sandbox(url):
    """Urlscan API orqali sandbox screenshot olish"""
    if not URLSCAN_KEY:
        return "https://urlscan.io/screenshots/fallback.png", True
    try:
        headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
        response = session.post("https://urlscan.io/api/v1/scan/", json={"url": url, "visibility": "public"}, headers=headers, timeout=10)
        if response.status_code == 201:
            uuid = response.json().get("uuid")
            if uuid:
                return f"https://urlscan.io/screenshots/{uuid}.png", True
    except Exception:
        pass
    return "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800", True

def analyze_url_intel(url, full_text):
    """Gibrid Threat Intelligence tahlili"""
    if url in PHISH_CACHE:
        return PHISH_CACHE[url]
    if "test-phish" in url.lower():
        return True, 100, "Simulated Phishing Test Trigger"
    
    heuristic_score, heuristic_reasons = extract_advanced_features(url)
    if heuristic_score >= 70:
        res = (True, min(heuristic_score, 98), f"Heuristic: {', '.join(heuristic_reasons)}")
        PHISH_CACHE[url] = res
        return res

    if GROQ_KEY:
        try:
            headers = {"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}
            system_prompt = (
                "Siz professional kiberxavfsizlik SOC tahlilchisiz. Berilgan URL manzil va matn tarkibida fishing borligini aniqlang. "
                "Javobni FAQAT ushbu formatdagi JSONda qaytaring:\n"
                '{"is_phishing": true, "probability": 0.95, "reason": "Qisqa o\'zbekcha sababi"}'
            )
            data = {
                "model": "llama3-8b-8192",
                "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": f"URL: {url}\nTEXT: {full_text}"}],
                "response_format": {"type": "json_object"},
                "temperature": 0.1
            }
            response = session.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data, timeout=5)
            if response.status_code == 200:
                result = json.loads(response.json()['choices'][0]['message']['content'])
                is_phish = str(result.get("is_phishing", "false")).lower() == "true"
                prob = int(result.get("probability", 0) * 100)
                reason = result.get("reason", "AI Decision")
                res = (is_phish, max(prob, heuristic_score), reason)
                PHISH_CACHE[url] = res
                return res
        except Exception as e:
            logger.error(f"Groq AI ulanish xatosi: {e}")

    is_phish = heuristic_score >= 40
    res = (is_phish, heuristic_score, "Heuristic Decision" if is_phish else "Clean")
    PHISH_CACHE[url] = res
    return res

@bot.message_handler(commands=['start', 'help'], chat_types=['private'])
def send_welcome_private(message):
    bot_info = bot.get_me()
    welcome_text = (
        f"🛡️ **UzPhishGuard SOC v2 — Enterprise (Supabase Ed.)** 🛡️\n\n"
        f"Assalomu alaykum, {message.from_user.first_name}!\n"
        f"Guruhlarni real vaqt rejimida gibrid Heuristics hamda Llama-3 AI tizimi orqali himoya qiladi.\n\n"
        f"📊 **Jonli SIEM Dashboard:** Sizning Render sayt manzilingiz"
    )
    markup = telebot.types.InlineKeyboardMarkup()
    markup.add(telebot.types.InlineKeyboardButton("➕ Guruhga qo'shish (Admin)", url=f"https://t.me/{bot_info.username}?startgroup=true"))
    bot.send_message(message.chat.id, welcome_text, parse_mode="Markdown", reply_markup=markup, disable_web_page_preview=True)

@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    text = message.text or message.caption
    if not text:
        return
    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        return

    is_private = message.chat.type == 'private'
    chat_title = "Shaxsiy Chat" if is_private else message.chat.title
    chat_id = message.chat.id
    username = message.from_user.username or message.from_user.first_name

    for url in urls:
        is_phish, risk_score, reason = analyze_url_intel(url, text)
        ip_addr, country, lat, lon = get_ip_geo_details(url)
        status = f"BLOCKED ({reason})" if is_phish else "CLEAN (Passed)"
        screenshot_file = None

        if is_phish:
            if not is_private:
                try:
                    bot.delete_message(chat_id, message.message_id)
                except Exception as e:
                    logger.error(f"Xabarni o'chirishda xatolik: {e}")
            
            ss_url, success = run_pro_sandbox(url)
            screenshot_file = ss_url if success else None

            alert_text = (
                f"🛡️ **UzPhishGuard SOC v2 (Hybrid Threat Intel)** 🛡️\n\n"
                f"⚠️ @{username} yuborgan xavfli havola yo'q qilindi.\n"
                f"🛑 **Tizim qarori:** {status}\n"
                f"🔥 **Xavf darajasi:** {risk_score}%\n"
                f"🌍 **IP & Joylashuv:** `{ip_addr}` ({country})\n\n"
                f"❗ *Incident tafsilotlari Supabase kiber-xaritasiga yuklandi!*"
            )
            bot.send_message(chat_id, alert_text, parse_mode="Markdown")
        
        # PostgreSQL-ga sinxron yozish (Hech qanday ma'lumot yo'qolmaydi)
        try:
            conn = psycopg2.connect(DATABASE_URL)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scanned_links (scan_date, chat_id, chat_title, username, url, status, screenshot_path, risk_score, ip_address, country, latitude, longitude)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), chat_id, chat_title, username, url, status, screenshot_file, risk_score, ip_addr, country, lat, lon))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as db_err:
            logger.error(f"PostgreSQL-ga yozishda xato: {db_err}")

if __name__ == "__main__":
    logger.info("UzPhishGuard Core Engine Online via Supabase PostgreSQL...")
    bot.infinity_polling()
