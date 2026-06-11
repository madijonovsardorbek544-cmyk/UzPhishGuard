import os
import re
import sqlite3
import telebot
import requests
import json
import asyncio
from datetime import datetime
from playwright.async_api import async_playwright

# Token va API sozlamalari
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "7437706342:AAEL7G-I9C9xG6X7Yk3R8fO2u8m1D4D")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
bot = telebot.TeleBot(BOT_TOKEN)

DB_NAME = "phish_guard.db"
SCREENSHOT_DIR = "static/screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# Baza mantiqini kengaytirish (v2 talablari uchun)
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
    """1-BOSQICH: Matndagi nuqta va ortiqcha belgilarni tozalash (Obfuscation bypass)"""
    if not text:
        return ""
    # Harflar orasidagi nuqtalar, chiziqlar va bo'shliqlarni yo'qotish (P.r.e.m.i.u.m -> Premium)
    cleaned = re.sub(re.compile(r'(?<!\w)[._\s]+(?!\w)'), '', text)
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned.strip()

async def run_url_sandbox(url):
    """2-BOSQICH: Zero-Day Screenshot Sandbox (Dinamik tahlil)"""
    screenshot_filename = f"snap_{int(datetime.now().timestamp())}.png"
    screenshot_path = os.path.join(SCREENSHOT_DIR, screenshot_filename)
    detected_forms = False
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            # Saytni ochish (Timeout 15 soniya)
            await page.goto(url, timeout=15000)
            await page.wait_for_timeout(2000)
            
            # Skrinshot olish
            await page.screenshot(path=screenshot_path)
            
            # HTML formalarni tekshirish (Karta, parol, login so'rayaptimi?)
            html_content = await page.content()
            suspicious_keywords = ["karta", "card", "pari", "parol", "password", "login", "pul", "yutuq", "bonus"]
            if any(word in html_content.lower() for word in suspicious_keywords):
                detected_forms = True
                
            await browser.close()
            return screenshot_path, detected_forms
    except Exception as e:
        print(f"Sandbox Error for {url}: {e}")
        return None, False

def report_to_intel_feed(url, reason):
    """4-BOSQICH: Global Threat Intel Feed Integration (HoneyPot Export)"""
    # Real loyihalarda bu yerda PhishTank yoki OpenPhish API'siga POST so'rovi ketadi
    # Biz hozircha kiber-log ko'rinishida simulyatsiya qilamiz
    intel_log = f"[{datetime.now()}] INTEL_FEED_EXPORT: {url} | Reason: {reason}\n"
    with open("threat_intel_feed.log", "a") as f:
        f.write(intel_log)

def analyze_text_ai(text):
    """1-BOSQICH: AI Contextual NLP Enginedan JSON ko'rinishida tahlil olish"""
    cleaned = clean_text_regex(text)
    # Mahalliy evristik tahlil mantiqi
    triggers = ["aksiya", "yutuq", "bepul", "telegram", "premium", "sovg", "bonus", "pul tarqat", "click", "payme"]
    score = 0
    for trigger in triggers:
        if trigger in cleaned.lower():
            score += 35
            
    if score >= 70:
        return {"phishing_probability": score / 100, "manipulation_detected": True, "reason": "AI Contextual NLP"}
    return {"phishing_probability": score / 100, "manipulation_detected": False, "reason": "Clean"}

@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    text = message.text or message.caption
    if not text:
        return

    # Havolalarni ajratib olish
    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        return

    chat_title = message.chat.title if message.chat.title else "Shaxsiy Chat"
    username = message.from_user.username if message.from_user.username else message.from_user.first_name

    for url in urls:
        # Tozalangan matn asosida AI tahlili
        ai_res = analyze_text_ai(text)
        
        status = "CLEAN (Passed)"
        screenshot_file = None
        risk_score = int(ai_res["phishing_probability"] * 100)
        
        if ai_res["manipulation_detected"]:
            status = f"BLOCKED ({ai_res['reason']})"
            
            # 2-Bosqich: Agar fishing gumoni bo'lsa, dinamik Sandboxni ishga tushirish
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ss_path, forms_found = loop.run_until_complete(run_url_sandbox(url))
            if ss_path:
                screenshot_file = ss_path
            if forms_found:
                status = "BLOCKED (Sandbox Data-Grabber Form)"
                risk_score = 100
            
            # 4-Bosqich: Global Threat Intelga yuborish
            report_to_intel_feed(url, status)

            # Xabarni guruhdan o'chirish va ogohlantirish
            try:
                bot.delete_message(message.chat.id, message.message_id)
                alert_text = (
                    f"🛡️ **UzPhishGuard Kiber-Himoya v2** 🛡️\n\n"
                    f"⚠️ @{username} yuborgan havola xavfsizlik tizimi tomonidan o'chirildi.\n"
                    f"🛑 **Sabab:** {status}\n"
                    f"🔥 **Xavf darajasi:** {risk_score}%\n\n"
                    f"❗ *Tavsiya:* Shaxsiy ma'lumotlar va plastik karta kodlarini kiritmang!"
                )
                bot.send_message(message.chat.id, alert_text, parse_mode="Markdown")
            except Exception as e:
                print(f"Message control error: {e}")

        # Ma'lumotlar bazasiga yozish
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scanned_links (scan_date, chat_title, username, url, status, screenshot_path, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), chat_title, username, url, status, screenshot_file, risk_score))
        conn.commit()
        conn.close()

if __name__ == "__main__":
    print("UzPhishGuard v2 Engine muvaffaqiyatli ishga tushdi...")
    bot.infinity_polling()
