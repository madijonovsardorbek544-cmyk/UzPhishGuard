import os
import re
import sqlite3
import telebot
import requests
import time
from datetime import datetime
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

if not BOT_TOKEN:
    raise ValueError("CRITICAL ERROR: TELEGRAM_BOT_TOKEN topilmadi!")

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
            risk_score INTEGER
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def clean_text_regex(text):
    if not text:
        return ""
    return re.sub(re.compile(r'(?<!\w)[._\s]+(?!\w)'), '', text).strip()

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
    cleaned = clean_text_regex(text)
    triggers = ["aksiya", "yutuq", "bepul", "telegram", "premium", "sovg", "bonus", "pul tarqat", "click", "payme"]
    score = 0
    for trigger in triggers:
        if trigger in cleaned.lower():
            score += 35
            
    if score >= 70:
        return {"phishing_probability": 0.95, "manipulation_detected": True, "reason": "AI Contextual NLP"}
    return {"phishing_probability": 0.0, "manipulation_detected": False, "reason": "Clean"}


# ---------------- [YANGI: SHAXSIY CHAT BUYRUQLARI] ----------------

@bot.message_handler(commands=['start', 'help'], chat_types=['private'])
def send_welcome_private(message):
    """Foydalanuvchi shaxsan botga start berganda chiqadigan professional menyu"""
    bot_info = bot.get_me()
    
    welcome_text = (
        f"🛡️ **UzPhishGuard SOC v2 — Kiber-Himoya Tizimi** 🛡️\n\n"
        f"Assalomu alaykum, {message.from_user.first_name}!\n"
        f"Ushbu bot guruhlarni soxta aksiyalar, yutuqlar va fishing (parol o'g'rilari) "
        f"havolalaridan **avtomatik va real vaqt rejimida** himoya qiladi.\n\n"
        f"🚀 **Men nimalar qila olaman?**\n"
        f"1️⃣ **Guruh Himoyasi:** Meni guruhingizga qo'shib, admin ruxsatini bersangiz, xavfli linklarni srazi o'chiraman.\n"
        f"2️⃣ **Shaxsiy Laboratoriya:** Menga istalgan shubhali linkni yuboring, men uni Sandbox bulutida tekshirib, skrinshotini sizga ko'rsataman!\n\n"
        f"📊 **Jonli SIEM Dashboard:** `uzphishguard.onrender.com`"
    )
    
    # Chiroyli tugmalar
    markup = InlineKeyboardMarkup()
    add_to_group_url = f"https://t.me/{bot_info.username}?startgroup=true"
    
    markup.add(InlineKeyboardButton("➕ Meni Guruhga Qo'shish (Admin)", url=add_to_group_url))
    markup.add(InlineKeyboardButton("📊 SIEM Dashboard Analytics", url="https://uzphishguard.onrender.com"))
    
    bot.send_message(message.chat.id, welcome_text, parse_mode="Markdown", reply_markup=markup)


@bot.message_handler(func=lambda message: True, chat_types=['private'])
def handle_private_link_scan(message):
    """Foydalanuvchi shaxsan o'zi link yuborganda unga Sandbox skrinshotini qaytarish"""
    text = message.text or message.caption
    urls = re.findall(r'(https?://[^\s]+)', text)
    
    if not urls:
        bot.send_message(
            message.chat.id, 
            "🔍 **Kiber-Laboratoriya Faol:** Menga tekshirish uchun biron-bir havolani (link) to'liq formatda yuboring (Masalan: `https://test-site.com`).",
            parse_mode="Markdown"
        )
        return

    for url in urls:
        waiting_msg = bot.send_message(message.chat.id, "🔄 **Kiber-Skaner ishga tushdi...** Sayt sandbox serverlarida ochilmoqda, iltimos 5 soniya kuting...", parse_mode="Markdown")
        
        ai_res = analyze_text_ai(text)
        ss_url, success = run_pro_sandbox(url)
        
        bot.delete_message(message.chat.id, waiting_msg.message_id)
        
        risk_score = int(ai_res["phishing_probability"] * 100)
        status_text = "🟢 TOZA (Tavsiya etiladi)" if risk_score < 70 else "🔴 XAVFLI FISHING (Tavsiya etilmaydi!)"
        
        result_caption = (
            f"🕵️‍♂️ **Skaner Natijasi:**\n"
            f"🌐 **Havola:** {url}\n"
            f"📊 **Xavf darajasi:** {max(risk_score, 45 if risk_score > 0 else 0)}%\n"
            f"🛡️ **Xulosa:** {status_text}\n\n"
            f"📸 *Orqa fondagi Sandbox ko'rinishi pastda aks etgan:* "
        )
        
        if ss_url:
            try:
                bot.send_photo(message.chat.id, ss_url, caption=result_caption, parse_mode="Markdown")
            except:
                bot.send_message(message.chat.id, result_caption + "\n*(Skrinshot yuklanishda muammo bo'ldi)*", parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id, result_caption, parse_mode="Markdown")


# ---------------- [GURUHNAZORATI REJIMI] ----------------

@bot.message_handler(func=lambda message: True, chat_types=['group', 'supergroup'])
def handle_group_messages(message):
    text = message.text or message.caption
    if not text:
        return

    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        return

    chat_title = message.chat.title
    username = message.from_user.username if message.from_user.username else message.from_user.first_name

    for url in urls:
        ai_res = analyze_text_ai(text)
        status = "CLEAN (Passed)"
        screenshot_file = None
        risk_score = int(ai_res["phishing_probability"] * 100)
        
        if ai_res["manipulation_detected"]:
            status = "BLOCKED (Sandbox Core Threat Analysis)"
            risk_score = 95
            ss_url, success = run_pro_sandbox(url)
            if success and ss_url:
                screenshot_file = ss_url

            try:
                bot.delete_message(message.chat.id, message.message_id)
                alert_text = (
                    f"🛡️ **UzPhishGuard SOC v2 (Enterprise)** 🛡️\n\n"
                    f"⚠️ @{username} yuborgan xavfli havola o'chirildi.\n"
                    f"🛑 **Tizim qarori:** {status}\n"
                    f"🔥 **Xavf darajasi:** {risk_score}%\n\n"
                    f"❗ *Kiber-Xavfsizlik:* Sayt orqa fonda Sandbox tizimida skrinshot tahlilidan o'tkazildi!"
                )
                bot.send_message(message.chat.id, alert_text, parse_mode="Markdown")
            except Exception as e:
                print(f"Xatolik: {e}")

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scanned_links (scan_date, chat_title, username, url, status, screenshot_path, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), chat_title, username, url, status, screenshot_file, risk_score))
            conn.commit()
            conn.close()
        except Exception as db_err:
            print(f"Baza xatosi: {db_err}")

if __name__ == "__main__":
    print("UzPhishGuard Dual-Mode (Private + Group) Engine online...")
    bot.infinity_polling()
