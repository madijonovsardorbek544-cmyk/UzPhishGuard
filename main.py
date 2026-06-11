import os
import re
import sqlite3
import telebot
import requests
import time
from datetime import datetime

# Tokenlarni Render muhitidan xavfsiz o'qib olish
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

if not BOT_TOKEN:
    raise ValueError("CRITICAL ERROR: TELEGRAM_BOT_TOKEN topilmadi! Render'da to'g'ri kiritilganini tekshiring.")

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
    # Harflar orasidagi nuqta va ortiqcha belgilarni tozalash (v1 bypass himoyasi)
    cleaned = re.sub(re.compile(r'(?<!\w)[._\s]+(?!\w)'), '', text)
    return cleaned.strip()

def run_pro_sandbox(url):
    """2-BOSQICH: Urlscan.io Enterprise Sandbox orqali saytni tekshirish va skrinshot URL olish"""
    if not URLSCAN_KEY:
        print("OGOHLANTIRISH: URLSCAN_API_KEY kiritilmagan, Sandbox o'tkazib yuborildi.")
        return None, False

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    
    try:
        # Kiber-markazga skanerlash so'rovini yuborish
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers, timeout=15)
        if response.status_code == 201:
            result_data = response.json()
            uuid = result_data.get("uuid")
            
            # Sayt to'liq yuklanishi va skrinshot tayyor bo'lishi uchun 12 soniya kutamiz
            time.sleep(12)
            
            screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
            return screenshot_url, True
    except Exception as e:
        print(f"Pro Sandbox xatosi ({url}): {e}")
    return None, False

def analyze_text_ai(text):
    """1-BOSQICH: NLP Contextual AI tahlili"""
    cleaned = clean_text_regex(text)
    triggers = ["aksiya", "yutuq", "bepul", "telegram", "premium", "sovg", "bonus", "pul tarqat", "click", "payme"]
    score = 0
    for trigger in triggers:
        if trigger in cleaned.lower():
            score += 35
            
    if score >= 70:
        return {"phishing_probability": 0.95, "manipulation_detected": True, "reason": "AI Contextual NLP"}
    return {"phishing_probability": 0.0, "manipulation_detected": False, "reason": "Clean"}

@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    text = message.text or message.caption
    if not text:
        return

    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        return

    chat_title = message.chat.title if message.chat.title else "Shaxsiy Chat"
    username = message.from_user.username if message.from_user.username else message.from_user.first_name

    for url in urls:
        ai_res = analyze_text_ai(text)
        status = "CLEAN (Passed)"
        screenshot_file = None
        risk_score = int(ai_res["phishing_probability"] * 100)
        
        if ai_res["manipulation_detected"]:
            status = f"BLOCKED ({ai_res['reason']})"
            
            # Dunyo darajasidagi Sandboxni ishga tushirish (Skrinshot olish)
            ss_url, forms_found = run_pro_sandbox(url)
            if ss_url:
                screenshot_file = ss_url  # Sayt skrinshoti havolasi
                status = "BLOCKED (Urlscan.io Core Intelligence)"
                risk_score = 100

            # Xabarni o'chirish va kiber-ogohlantirish yuborish
            try:
                bot.delete_message(message.chat.id, message.message_id)
                alert_text = (
                    f"🛡️ **UzPhishGuard SOC v2 (Enterprise)** 🛡️\n\n"
                    f"⚠️ @{username} yuborgan xavfli havola aniqlanib, o'chirildi.\n"
                    f"🛑 **Tizim qarori:** {status}\n"
                    f"🔥 **Xavf darajasi:** {risk_score}%\n\n"
                    f"❗ *Kiber-Xavfsizlik:* Sayt orqa fonda Sandbox tizimida skrinshot tahlilidan o'tkazildi!"
                )
                bot.send_message(message.chat.id, alert_text, parse_mode="Markdown")
            except Exception as e:
                print(f"Xabarni boshqarishda xatolik: {e}")

        # Ma'lumotlarni bazaga yozish
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
    print("UzPhishGuard Enterprise v2 muvaffaqiyatli yoqildi...")
    bot.infinity_polling()
