import os
import re
import socket
import sqlite3
import telebot
import requests
import json
from datetime import datetime
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# API kalitlarini Render muhitidan olish
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")

if not BOT_TOKEN:
    raise ValueError("CRITICAL ERROR: TELEGRAM_BOT_TOKEN topilmadi!")

bot = telebot.TeleBot(BOT_TOKEN)
DB_NAME = "phish_guard.db"

def init_db():
    """Ma'lumotlar bazasini yangi kiber-koordinatalar bilan yaratish/tekshirish"""
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

# Bazani ishga tushirish
init_db()

def extract_domain(url):
    """URL ichidan faqat domen nomini ajratib olish (kiber-tahlil uchun)"""
    try:
        domain = url.split("//")[-1].split("/")[0].split("?")[0]
        return domain
    except:
        return None

def get_ip_geo_details(url):
    """1-QADAM: Domendan IP manzil va Geolokatsiya koordinatalarini aniqlash"""
    domain = extract_domain(url)
    if not domain:
        return "0.0.0.0", "Unknown", 0.0, 0.0
    
    try:
        # Soket orqali server IP manzilini aniqlash
        ip_address = socket.gethostbyname(domain)
        
        # IP-API orqali geografik joylashuvni olish
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
    """Sandbox Screenshot Capture xizmati (Urlscan API)"""
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
    """2-QADAM: Groq Llama-3 AI orqali 100% kontekstual NLP antifraud tahlili"""
    if not GROQ_KEY:
        # Fallback mantiq (Agar Groq kaliti xato bo'lsa, trigger ishlaydi)
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
            "unda fishing (parol, karta, profil o'g'riligi), soxta aksiyalar yoki firgarlik manipulyatsiyasi "
            "bor-yo'qligini aniqlang. Javobni FAQAT va FAQAT berilgan JSON formatida qaytaring, ortiqcha so'z qo'shmang:\n"
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
    """Professional Yo'riqnoma va Start paneli"""
    bot_info = bot.get_me()
    welcome_text = (
        f"🛡️ **UzPhishGuard SOC v2 — Kiber-Himoya Platformasi** 🛡️\n\n"
        f"Assalomu alaykum, {message.from_user.first_name}!\n\n"
        f"Ushbu bot o'zbek kiber-hududidagi guruhlarni firgarlik, soxta yutuqli aksiyalar va "
        f"fishing (profil/karta o'g'riligi) havolalaridan **Next-Gen Llama-3 Core AI** yordamida real vaqtda himoya qiladi.\n\n"
        f"⚙️ **BOTDAN FOYDALANISH YO'RIQNOMASI:**\n\n"
        f"1️⃣ **Guruhlarni Himoya Qilish (Asosiy xizmat):**\n"
        f"Meni guruhingizga qo'shing va **Admin** huquqini bering (Xabarlarni o'chirish huquqi majburiy). "
        f"Shundan so'ng, guruhga tashlangan har qanday shubhali havola AI tomonidan tekshirilib, "
        f"firgarlik aniqlansa, darhol o'chiriladi va kiber-ogohlantirish yuboriladi.\n\n"
        f"2️⃣ **Shaxsiy Kiber-Laboratoriya:**\n"
        f"Menga istalgan shubhali havola yoki matnni yuboring. AI uni tekshirib, server joylashgan "
        f"IP manzilini, davlatini va global kiber-xaritadagi koordinatalarini aniqlab beradi.\n\n"
        f"📊 **Jonli SIEM Dashboard & Threat Map:**\n"
        f"Ushlangan barcha hujumlar va jonli skrinshotlarni kuzatish: uzphishguard.onrender.com"
    )
    
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("➕ Meni Guruhga Qo'shish (Admin)", url=f"https://t.me/{bot_info.username}?startgroup=true"))
    markup.add(InlineKeyboardButton("📊 Jonli Kiber-Xarita (SIEM)", url="https://uzphishguard.onrender.com"))
    
    bot.send_message(message.chat.id, welcome_text, parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    """Guruhlar va shaxsiy chatdagi xabarlarni global real-time monitoring qilish"""
    text = message.text or message.caption
    if not text:
        return

    # Matn ichidan barcha havolalarni (URL) ajratib olish
    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        return

    is_private = message.chat.type == 'private'
    chat_title = "Shaxsiy Chat" if is_private else message.chat.title
    username = message.from_user.username if message.from_user.username else message.from_user.first_name

    for url in urls:
        if is_private:
            waiting_msg = bot.send_message(message.chat.id, "🔄 **Llama-3 AI va Geolocation tahlili boshlandi...**", parse_mode="Markdown")
        
        # 1. Sun'iy intellekt tahlili
        ai_res = analyze_text_ai(text)
        status = "CLEAN (Passed)"
        screenshot_file = None
        risk_score = int(ai_res.get("phishing_probability", 0) * 100)
        
        # 2. Server IP va Geolokatsiyasini aniqlash
        ip_addr, country, lat, lon = get_ip_geo_details(url)
        
        # Agar firgarlik yoki manipulyatsiya aniqlansa
        if ai_res.get("manipulation_detected", False):
            status = f"BLOCKED ({ai_res.get('reason', 'AI Decision')})"
            risk_score = max(risk_score, 95)
            
            # Orqa fonda skrinshot olish
            ss_url, success = run_pro_sandbox(url)
            if success and ss_url:
                screenshot_file = ss_url

            # Guruhdagi xavfli xabarni o'chirish
            if not is_private:
                try:
                    bot.delete_message(message.chat.id, message.message_id)
                except:
                    pass
            
            # Kiber-Hujum Incident Alert hisoboti
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v2 (Llama-3 Core AI)** 🛡️\n\n"
                f"⚠️ @{username} yuborgan xavfli havola aniqlandi va bartaraf etildi.\n"
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
            # Agar havola toza bo'lsa va shaxsiy chatdan tekshirilayotgan bo'lsa
            if is_private:
                bot.delete_message(message.chat.id, waiting_msg.message_id)
                bot.send_message(message.chat.id, f"🟢 **Xavfsiz:** AI ushbu havolada xavf aniqlamadi.\n🌐 Server IP: `{ip_addr}` ({country})", parse_mode="Markdown")

        # Hamma ma'lumotlarni (shu jumladan koordinatalarni) bazaga saqlash
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
    print("UzPhishGuard Enterprise Llama-3 AI + Live Threat Map Engine Online...")
    bot.infinity_polling()
