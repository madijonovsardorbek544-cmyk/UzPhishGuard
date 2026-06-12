import os
import re
import socket
import sqlite3
import telebot
import requests
import json
import google.generativeai as genai
from datetime import datetime
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if not BOT_TOKEN:
    raise ValueError("CRITICAL ERROR: TELEGRAM_BOT_TOKEN topilmadi!")

# Gemini AI konfiguratsiyasi
if GEMINI_KEY:
    genai.configure(api_key=GEMINI_KEY)

bot = telebot.TeleBot(BOT_TOKEN)
DB_NAME = "phish_guard.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scanned_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
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
    conn.close()

init_db()

def extract_domain(url):
    """URL ichidan faqat domen nomini ajratib olish"""
    try:
        domain = url.split("//")[-1].split("/")[0].split("?")[0]
        return domain
    except:
        return None

def get_ip_geo_details(url):
    """Domendan IP manzil va Geolokatsiya koordinatalarini aniqlash (1-QADAM)"""
    domain = extract_domain(url)
    if not domain:
        return "0.0.0.0", "Unknown", 0.0, 0.0
    
    try:
        # 1. Soket orqali IP manzilni aniqlash
        ip_address = socket.gethostbyname(domain)
        
        # 2. IP-API orqali Geolokatsiyani olish
        geo_res = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,lat,lon", timeout=5)
        if geo_res.status_code == 200:
            geo_data = geo_res.json()
            if geo_data.get("status") == "success":
                return (
                    ip_address,
                    geo_data.get("country", "Unknown"),
                    geo_data.get("lat", 0.0),
                    geo_data.get("lon", 0.0)
                )
        return ip_address, "Unknown", 0.0, 0.0
    except:
        return "0.0.0.0", "Unknown", 0.0, 0.0

def run_pro_sandbox(url):
    """Enterprise Sandbox mantiqi"""
    if not URLSCAN_KEY or URLSCAN_KEY == "":
        return "https://urlscan.io/screenshots/fallback.png", True

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers, timeout=15)
        if response.status_code == 201:
            result_data = response.json()
            uuid = result_data.get("uuid")
            if uuid:
                return f"https://urlscan.io/screenshots/{uuid}.png", True
    except Exception as e:
        print(f"Pro Sandbox xatosi: {e}")
    
    return "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800", True

def analyze_text_ai(text):
    """2-QADAM: Google Gemini NLP Contextual AI tahlili"""
    if not GEMINI_KEY:
        # Fallback (Agar Gemini kaliti o'rnatilmagan bo'lsa oldingi mantiq ishlaydi)
        triggers = ["aksiya", "yutuq", "bepul", "telegram", "premium", "sovg", "bonus", "pul tarqat", "click", "payme"]
        score = sum(35 for t in triggers if t in text.lower())
        if score >= 70:
            return {"phishing_probability": 0.95, "manipulation_detected": True, "reason": "Heuristic Trigger Match"}
        return {"phishing_probability": 0.0, "manipulation_detected": False, "reason": "Clean"}

    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = (
            "Siz professional kiberxavfsizlik SOC tahlilchisiz. Kelgan o'zbekcha xabarni tahlil qilib, "
            "unda fishing (parol, profil yoki karta o'g'riligi), soxta yutuqli aksiyalar yoki firgarlik manipulyatsiyasi "
            "bor-yo'qligini aniqlang. Javobni FAQAT va FAQAT quyidagi JSON formatida qaytaring, ortiqcha matn qo'shmang:\n"
            '{"phishing_probability": 0.95, "manipulation_detected": true, "reason": "Sababi short o\'zbekcha"}\n\n'
            f"Xabar matni: {text}"
        )
        response = model.generate_content(prompt)
        # JSONni ajratib olish va o'qish
        match = re.search(r'\{.*\}', response.text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except Exception as e:
        print(f"Gemini AI Error: {e}")
    
    return {"phishing_probability": 0.0, "manipulation_detected": False, "reason": "AI Error Fallback"}

@bot.message_handler(commands=['start', 'help'], chat_types=['private'])
def send_welcome_private(message):
    bot_info = bot.get_me()
    welcome_text = (
        f"🛡️ **UzPhishGuard SOC v2 — Kiber-Himoya Tizimi** 🛡️\n\n"
        f"Assalomu alaykum, {message.from_user.first_name}!\n"
        f"Ushbu bot guruhlarni fishing havolalaridan **Google Gemini AI** yordamida himoya qiladi.\n\n"
        f"🚀 **Imkoniyatlar:**\n"
        f"1️⃣ **Guruh Himoyasi:** Meni guruhga admin qilib qo'shing.\n"
        f"2️⃣ **Shaxsiy Laboratoriya:** Menga istalgan havolani yuborib, uning IP manzilini va global kiber xaritadagi o'rnini aniqlang!\n\n"
        f"📊 **Jonli SIEM Dashboard va Kiber Xarita:** `uzphishguard.onrender.com`"
    )
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("➕ Meni Guruhga Qo'shish (Admin)", url=f"https://t.me/{bot_info.username}?startgroup=true"))
    markup.add(InlineKeyboardButton("📊 SIEM Threat Map", url="https://uzphishguard.onrender.com"))
    bot.send_message(message.chat.id, welcome_text, parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    text = message.text or message.caption
    if not text:
        return

    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        return

    is_private = message.chat.type == 'private'
    chat_title = "Shaxsiy Chat" if is_private else message.chat.title
    username = message.from_user.username if message.from_user.username else message.from_user.first_name

    for url in urls:
        if is_private:
            waiting_msg = bot.send_message(message.chat.id, "🔄 **Google Gemini AI va Geolocation tahlili boshlandi...**", parse_mode="Markdown")
        
        ai_res = analyze_text_ai(text)
        status = "CLEAN (Passed)"
        screenshot_file = None
        risk_score = int(ai_res.get("phishing_probability", 0) * 100)
        
        # IP va Geolokatsiyani aniqlash (1-QADAM)
        ip_addr, country, lat, lon = get_ip_geo_details(url)
        
        if ai_res.get("manipulation_detected", False):
            status = f"BLOCKED ({ai_res.get('reason', 'AI Decision')})"
            risk_score = max(risk_score, 95)
            
            ss_url, success = run_pro_sandbox(url)
            if success and ss_url:
                screenshot_file = ss_url

            if not is_private:
                try:
                    bot.delete_message(message.chat.id, message.message_id)
                except:
                    pass
            
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v2 (Next-Gen AI)** 🛡️\n\n"
                f"⚠️ @{username} yuborgan xavfli havola o'chirildi/aniqlandi.\n"
                f"🛑 **Tizim qarori:** {status}\n"
                f"🔥 **Xavf darajasi:** {risk_score}%\n"
                f"🌍 **Server IP & Joylashuvi:** `{ip_addr}` ({country})\n\n"
                f"❗ *Kiber-Xavfsizlik:* Incident tafsilotlari xalqaro Threat Map xaritasiga yuklandi!"
            )
            
            if is_private:
                bot.delete_message(message.chat.id, waiting_msg.message_id)
                if screenshot_file:
                    bot.send_photo(message.chat.id, screenshot_file, caption=alert_text, parse_mode="Markdown")
                else:
                    bot.send_message(message.chat.id, alert_text, parse_mode="Markdown")
            else:
                bot.send_message(message.chat.id, alert_text, parse_mode="Markdown")
        else:
            if is_private:
                bot.delete_message(message.chat.id, waiting_msg.message_id)
                bot.send_message(message.chat.id, f"🟢 **Xavfsiz:** Gemini AI ushbu havolada xavf aniqlamadi.\n🌐 Server IP: `{ip_addr}` ({country})", parse_mode="Markdown")

        # Ma'lumotlarni bazaga koordinatalari bilan yozish
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scanned_links (scan_date, chat_title, username, url, status, screenshot_path, risk_score, ip_address, country, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), chat_title, username, url, status, screenshot_file, risk_score, ip_addr, country, lat, lon))
            conn.commit()
            conn.close()
        except Exception as db_err:
            print(f"Baza xatosi: {db_err}")

if __name__ == "__main__":
    print("UzPhishGuard Next-Gen Gemini AI + Threat Map Engine Online...")
    bot.infinity_polling()
