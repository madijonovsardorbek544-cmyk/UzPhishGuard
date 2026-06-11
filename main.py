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

# ----------------- INTELLEKTUAL KIBER-ALGORITMLAR (3-BOSQICH) -----------------

def check_virustotal(url: str) -> bool:
    """
    8-QADAM: VirusTotal API v3 orqali havolani global tekshirish.
    Antiviruslar xavfli desa True qaytaradi.
    """
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-key": VT_API_KEY}
    
    try:
        # 1. URLni scan qilish uchun yuboramiz
        response = requests.post(api_url, data={"url": url}, headers=headers, timeout=10)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            # 2. Tahlil natijasini tekshiramiz
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report = requests.get(analysis_url, headers=headers, timeout=10)
            if report.status_code == 200:
                stats = report.json()["data"]["attributes"]["stats"]
                malicious_count = stats.get("malicious", 0) + stats.get("phishing", 0)
                # Agar kamida 2ta xalqaro antivirus zararli desa, True (Xavfli)
                if malicious_count >= 2:
                    return True
    except Exception as e:
        print(f"VirusTotal API xatoligi: {e}")
    return False

def check_typosquatting(url: str) -> bool:
    """
    9-QADAM: O'zbekistondagi mashhur brendlar domenlariga
    soxta o'xshashlikni (Typosquatting) aniqlash algoritmi.
    """
    official_domains = ["payme.uz", "click.uz", "uzcard.uz", "kun.uz", "id.egov.uz", "olx.uz"]
    
    # Havoladan domenni ajratib olish (masalan, https://payme-uz.ru/ -> payme-uz.ru)
    clean_url = url.lower().replace("https://", "").replace("http://", "").split("/")[0]
    
    for official in official_domains:
        if clean_url == official:
            return False # Bu rasmiy sayt, xavfsiz
            
        # O'xshashlik foizini hisoblaymiz (SequenceMatcher yordamida)
        similarity = SequenceMatcher(None, clean_url, official).ratio()
        
        # Agar o'xshashlik 70% dan baland bo'lsa, lekin xuddi o'zi bo'lmasa - bu soxta!
        if similarity >= 0.70 and official in clean_url or (similarity >= 0.75):
            return True
    return False

def contains_phishing_keywords(text: str) -> bool:
    """
    10-QADAM: Matnli Heuristic tahlil. 
    Fishing xabarlaridagi fishing o'zbekcha kalit so'zlar.
    """
    keywords = ["yutuq", "mukofot", "aksiya", "tekin", "premium", "jamg'arma", "fondi", "tarqating", "omadli"]
    text_lower = text.lower()
    
    # Agar xabarda kamida 2ta shubhali so'z ishtirok etsa
    match_count = sum(1 for word in keywords if word in text_lower)
    if match_count >= 2:
        return True
    return False

# -----------------------------------------------------------------------------

def extract_links(text: str) -> list:
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

@dp.message()
async def check_message_for_links(message: types.Message):
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
                
                # 1-Bosqich: Mahalliy qora ro'yxatni tekshirish
                if is_local_blacklisted(link):
                    is_phishing = True
                    reason = "Mahalliy qora ro'yxat (Blacklist)"
                    
                # 2-Bosqich: Typosquatting (Brend o'xshashligi) tekshiruvi
                elif check_typosquatting(link):
                    is_phishing = True
                    reason = "Soxta brend domeni (Typosquatting)"
                    
                # 3-Bosqich: O'zbekcha matn tahlili
                elif contains_phishing_keywords(text_content):
                    is_phishing = True
                    reason = "Shubhali fishing matni (Heuristic)"
                    
                # 4-Bosqich: Global VirusTotal API tekshiruvi
                elif check_virustotal(link):
                    is_phishing = True
                    reason = "Global Antivirus Hisoboti (VirusTotal)"
                
                # YAKUNIY QAROR
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
                        print(f"Xabarni o'chirishda xatolik: {e}")
                    break # Bitta fishing link yetarli xabarni bloklashga
                else:
                    log_link(user_id, user_name, chat_title, link, "CLEAN (Passed)")
                    print(f"✅ Safe link logged: {link}")

async def main():
    init_db()
    print("UzPhishGuard TOP-TIER kiberxavfsizlik intellekti ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
