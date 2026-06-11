import os
import re
import sqlite3
import asyncio
import logging
import requests
from datetime import datetime
from difflib import SequenceMatcher
from aiogram import Bot, Dispatcher, types
from aiogram.enums import ParseMode

# LOYIHA STRATEGIK KALITLARI
BOT_TOKEN = "8654394563:AAGIYkmFLi-UMo3uxTMvZKrPn5hOXVm3bcE"
VT_API_KEY = "eef8443f4adae9fc938c5e775c84b57df98cd93633e5539db0a8ba601231f538"

logging.basicConfig(level=logging.INFO)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

DB_NAME = "phish_guard.db"

# ----------------- MA'LUMOTLAR BAZASI -----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scanned_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
            user_id INTEGER,
            username TEXT,
            chat_title TEXT,
            url TEXT,
            status TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklisted_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
    """)
    sample_phishing = ["payme-bonus.ru", "click-uzbekistan.club", "telegram-premium-free.com", "olx-uz-safe.ru"]
    for domain in sample_phishing:
        cursor.execute("INSERT OR IGNORE INTO blacklisted_domains (domain) VALUES (?)", (domain,))
    conn.commit()
    conn.close()

def log_link(user_id, username, chat_title, url, status):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO scanned_links (scan_date, user_id, username, chat_title, url, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (current_time, user_id, username, chat_title, url, status))
    conn.commit()
    conn.close()

def is_local_blacklisted(url):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM blacklisted_domains")
    blacklist = [row[0] for row in cursor.fetchall()]
    conn.close()
    for domain in blacklist:
        if domain in url.lower():
            return True
    return False

# ----------------- INTELLEKTUAL KIBER-ALGORITMLAR -----------------

def check_virustotal(url: str) -> bool:
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-key": VT_API_KEY}
    try:
        response = requests.post(api_url, data={"url": url}, headers=headers, timeout=10)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report = requests.get(analysis_url, headers=headers, timeout=10)
            if report.status_code == 200:
                stats = report.json()["data"]["attributes"]["stats"]
                malicious_count = stats.get("malicious", 0) + stats.get("phishing", 0)
                if malicious_count >= 2:
                    return True
    except Exception as e:
        logging.error(f"VirusTotal Error: {e}")
    return False

def check_typosquatting(url: str) -> bool:
    official_domains = ["payme.uz", "click.uz", "uzcard.uz", "kun.uz", "id.egov.uz", "olx.uz"]
    clean_url = url.lower().replace("https://", "").replace("http://", "").split("/")[0]
    for official in official_domains:
        if clean_url == official:
            return False
        similarity = SequenceMatcher(None, clean_url, official).ratio()
        if similarity >= 0.70 and official in clean_url or (similarity >= 0.75):
            return True
    return False

def contains_phishing_keywords(text: str) -> bool:
    keywords = ["yutuq", "mukofot", "aksiya", "tekin", "premium", "jamg'arma", "fondi", "tarqating", "omadli"]
    text_lower = text.lower()
    match_count = sum(1 for word in keywords if word in text_lower)
    return match_count >= 2

def extract_links(text: str) -> list:
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

@dp.message()
async def check_message_for_links(message: types.Message):
    # Bot shaxsiy chatda /start buyrug'iga javob berishi uchun diagnostic block
    if message.text and message.text.startswith('/start'):
        await message.answer("🛡️ **UzPhishGuard Cyber Security Bot Active!**\nAdd me to groups as an Admin to secure links.")
        return

    if message.text:
        text_content = message.text
        detected_links = extract_links(text_content)
        
        if detected_links:
            chat_title = message.chat.title or "Private Chat"
            user_id = message.from_user.id
            user_name = message.from_user.username or "Unknown"
            
            for link in detected_links:
                is_phishing = False
                reason = ""
                
                if is_local_blacklisted(link):
                    is_phishing = True
                    reason = "Mahalliy qora ro'yxat (Blacklist)"
                elif check_typosquatting(link):
                    is_phishing = True
                    reason = "Soxta brend domeni (Typosquatting)"
                elif contains_phishing_keywords(text_content):
                    is_phishing = True
                    reason = "Shubhali fishing matni (Heuristic)"
                elif check_virustotal(link):
                    is_phishing = True
                    reason = "Global Antivirus Hisoboti (VirusTotal)"
                
                if is_phishing:
                    log_link(user_id, user_name, chat_title, link, f"BLOCKED ({reason})")
                    try:
                        await message.delete()
                        await message.answer(
                            f"🛡️ **UzPhishGuard Kiber-Himoya!**\n"
                            f"@{user_name} yuborgan havola xavfsizlik tizimi tomonidan o'chirildi.\n\n"
                            f"⚠️ **Sabab:** {reason}\n"
                            f"💡 *Tavsiya: Shaxsiy ma'lumotlar va plastik karta kodlarini kiritmang!*"
                        )
                    except Exception as e:
                        logging.error(f"Message delete error: {e}")
                    break
                else:
                    log_link(user_id, user_name, chat_title, link, "CLEAN (Passed)")

async def main():
    init_db()
    logging.info("UzPhishGuard Core Engine Started...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
