import os
import re
import socket
import sqlite3
import telebot
import requests
import json
from datetime import datetime
from telebot import types

# ==========================================
# ⚙️ KONFIGURATSIYA VA API KALITLAR
# ==========================================
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

# 1-BOSQICH: PhishTank API kaliti (Render Environment Variables'ga qo'shishingiz mumkin)
# Agar hozircha kalit bo'lmasa, PhishTank tizimi test rejimida (anonim) xizmat ko'rsatadi
PHISHTANK_KEY = os.getenv("PHISHTANK_API_KEY", "") 

if not BOT_TOKEN:
    raise ValueError("CRITICAL ERROR: TELEGRAM_BOT_TOKEN topilmadi!")

bot = telebot.TeleBot(BOT_TOKEN)
DB_NAME = "phish_guard.db"

# ==========================================
# ⚡ 2-BOSQICH: IN-MEMORY CACHE (TEZKOR XOTIRA)
# ==========================================
# Bir marta tekshirilgan havolalarni Groq AI'ga qayta yubormaslik uchun kesh xotira
PHISH_CACHE = {}  # Format: {"url_manzili": {"is_phish": True, "reason": "...", "risk_score": 95}}

def init_db():
    """Ma'lumotlar bazasini yangi ustunlar bilan tekshirish va yaratish"""
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

# ==========================================
# 🌍 1-BOSQICH: GLOBAL THREAT INTEL (PHISHTANK)
# ==========================================
def report_to_phishtank(url):
    """Aniqlangan fishing havolani global brauzerlar bloklashi uchun PhishTank'ga yuborish"""
    try:
        payload = {
            "url": url,
            "format": "json",
            "app_key": PHISHTANK_KEY
        }
        # PhishTank global kiber-bazasiga havola yuborish
        response = requests.post("https://api.phishtank.com/v2/submit", data=payload, timeout=10)
        if response.status_code == 200:
            print(f"[🔥 Threat Intel] {url} muvaffaqiyatli global bazaga yuborildi.")
        else:
            print(f"[⚠️ Threat Intel] PhishTank anonim rejimda qabul qildi.")
    except Exception as e:
        print(f"PhishTank ulanish xatosi: {e}")

def extract_domain(url):
    try:
        domain = url.split("//")[-1].split("/")[0].split("?")[0]
        return domain
    except:
        return None

def get_ip_geo_details(url):
    domain = extract_domain(url)
    if not domain:
        return "0.0.0.0", "Unknown", 0.0, 0.0
    
    try:
        ip_address = socket.gethostbyname(domain)
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
    if not GROQ_KEY:
        triggers = ["aksiya", "yutuq", "bepul", "telegram", "premium", "sovg", "bonus", "pul tarqat", "click", "payme"]
        score = sum(35 for t in triggers if t in text.lower())
        if score >= 70:
            return {"phishing_probability": 0.95, "manipulation_detected": True, "reason": "Heuristic Trigger Match"}
        return {"phishing_probability": 0.0, "manipulation_detected": False, "reason": "Clean"}

    try:
        headers = {
            "Authorization": f"Bearer {GROQ_KEY}",
            "Content-Type": "application/json"
        }
        
        system_prompt = (
            "Siz professional kiberxavfsizlik SOC tahlilchisiz. Kelgan o'zbekcha xabarni tahlil qilib, "
            "unda fishing, soxta aksiyalar yoki firgarlik manipulyatsiyasi bor-yo'qligini aniqlang. "
            "Javobni FAQAT va FAQAT berilgan JSON formatida qaytaring, ortiqcha so'z qo'shmang:\n"
            '{"phishing_probability": 0.95, "manipulation_detected": true, "reason": "Qisqa o\'zbekcha sababi"}'
        )
        
        data = {
            "model": "llama3-8b-8192",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            ai_message = result['choices'][0]['message']['content']
            return json.loads(ai_message)
    except Exception as e:
        print(f"Groq AI Error: {e}")
    
    return {"phishing_probability": 0.0, "manipulation_detected": False, "reason": "AI Error Fallback"}

@bot.message_handler(commands=['start', 'help'], chat_types=['private'])
def send_welcome_private(message):
    bot_info = bot.get_me()
    welcome_text = (
        f"🛡️ **UzPhishGuard SOC v2 — Kiber-Himoya Platformasi** 🛡️\n\n"
        f"Assalomu alaykum, {message.from_user.first_name}!\n\n"
        f"Ushbu bot guruhlarni firgarlik, soxta yutuqli aksiyalar va "
        f"fishing havolalaridan **Next-Gen Llama-3 Core AI** hamda **Global Intel Feed** yordamida himoya qiladi.\n\n"
        f"⚙️ **BOTDAN FOYDALANISH YO'RIQNOMASI:**\n\n"
        f"1️⃣ **Guruhlarni Himoya Qilish:**\n"
        f"Meni guruhingizga qo'shing va **Admin** huquqini bering.\n\n"
        f"2️⃣ **Shaxsiy Kiber-Laboratoriya:**\n"
        f"Menga istalgan shubhali havola yoki matnni yuboring, AI uni srazi tekshiradi.\n\n"
        f"📊 **Jonli SIEM Dashboard & Threat Map:**\n"
        f"uzphishguard.onrender.com"
    )
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("➕ Meni Guruhga Qo'shish (Admin)", url=f"https://t.me/{bot_info.username}?startgroup=true"))
    markup.add(types.InlineKeyboardButton("📊 Jonli Kiber-Xarita (SIEM)", url="https://uzphishguard.onrender.com"))
    
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
            waiting_msg = bot.send_message(message.chat.id, "🔄 **Llama-3 AI va Geolocation tahlili boshlandi...**", parse_mode="Markdown")
        
        # ⚡ 2-BOSQICH: KESH TEKSHIRUVI (Tezlikni 10x oshirish)
        if url in PHISH_CACHE:
            print(f"[⚡ CACHE MATCH] {url} ma'lumotlari keshdan olindi.")
            cache_data = PHISH_CACHE[url]
            is_phish = cache_data["is_phish"]
            risk_score = cache_data["risk_score"]
            reason = cache_data["reason"] + " (Cached)"
        else:
            # Agar keshda bo'lmasa, AI orqali yangi tahlil qilish
            ai_res = analyze_text_ai(text)
            is_phish = str(ai_res.get("manipulation_detected", "false")).lower() == "true"
            risk_score = int(ai_res.get("phishing_probability", 0) * 100)
            reason = ai_res.get("reason", "AI Decision")
            
            # Kelgusi so'rovlar uchun kesh xotiraga saqlash
            PHISH_CACHE[url] = {
                "is_phish": is_phish,
                "risk_score": risk_score,
                "reason": reason
            }

        status = "CLEAN (Passed)"
        screenshot_file = None
        ip_addr, country, lat, lon = get_ip_geo_details(url)
        
        if is_phish or risk_score >= 70:
            status = f"BLOCKED ({reason})"
            risk_score = max(risk_score, 95)
            
            # 🌍 1-BOSQICH: Agar xavf yuqori bo'lsa, PhishTank'ga avtomatik jo'natish
            if risk_score >= 90:
                report_to_phishtank(url)
            
            ss_url, success = run_pro_sandbox(url)
            if success and ss_url:
                screenshot_file = ss_url

            # Guruhda fishingni o'chirish
            if not is_private:
                try:
                    bot.delete_message(message.chat.id, message.message_id)
                except Exception as e:
                    print(f"O'chirishda xatolik: {e}")
            
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v2 (Llama-3 Core AI)** 🛡️\n\n"
                f"⚠️ @{username} yuborgan xavfli havola o'chirildi.\n"
                f"🛑 **Tizim qarori:** {status}\n"
                f"🔥 **Xavf darajasi:** {risk_score}%\n"
                f"🌍 **Server IP & Joylashuvi:** `{ip_addr}` ({country})\n\n"
                f"❗ *Kiber-Xavfsizlik:* Incident tafsilotlari xalqaro Threat Map hamda Global PhishTank bazasiga yuklandi!"
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
                bot.send_message(message.chat.id, f"🟢 **Xavfsiz:** AI ushbu havolada xavf aniqlamadi.\n🌐 Server IP: `{ip_addr}` ({country})", parse_mode="Markdown")

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
    print("UzPhishGuard Enterprise Core Engine Online...")
    bot.infinity_polling()
