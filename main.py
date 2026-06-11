import os
import re
import sqlite3
import asyncio
import logging
from datetime import datetime
from aiogram import Bot, Dispatcher, types
from aiogram.enums import ParseMode

# BOT TOKENINI TO'GRIDAN-TO'G'RI KOD ICHIGA QO'YDIK
BOT_TOKEN = "8654394563:AAGIYkmFLi-UMo3uxTMvZKrPn5hOXVm3bcE"

# Xatoliklar va loglarni kuzatish tizimi (Logging)
logging.basicConfig(level=logging.INFO)

# Bot va Dispatcher obyektlarini yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# ----------------- MA'LUMOTLAR BAZASI BILAN ISHLASH (5 va 6-qadamlar) -----------------

DB_NAME = "phish_guard.db"

def init_db():
    """
    Tizim uchun kerakli jadvallarni yaratadi:
    1. scanned_links - barcha tahlil qilingan linklar statistikasi
    2. blacklisted_domains - kiber-firgarlik saytlari (qora ro'yxat)
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Skaner qilingan linklar jadvali
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
    
    # Qora ro'yxatdagi fishing domenlar jadvali
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklisted_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
    """)
    
    # Baza boshlanganda tahlil uchun unga bir nechta mashhur soxta namunalarni kiritib qo'yamiz
    sample_phishing = ["payme-bonus.ru", "click-uzbekistan.club", "telegram-premium-free.com", "olx-uz-safe.ru"]
    for domain in sample_phishing:
        cursor.execute("INSERT OR IGNORE INTO blacklisted_domains (domain) VALUES (?)", (domain,))
        
    conn.commit()
    conn.close()

def log_link(user_id, username, chat_title, url, status):
    """Topilgan har bir linkni bazaga yozib borish funksiyasi"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO scanned_links (scan_date, user_id, username, chat_title, url, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (current_time, user_id, username, chat_title, url, status))
    conn.commit()
    conn.close()

def is_blacklisted(url):
    """Link tarkibida qora ro'yxatdagi domen bor-yo'qligini tekshirish (7-qadam)"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM blacklisted_domains")
    blacklist = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    # Link ichidan domen nomini ajratib olamiz va solishtiramiz
    for domain in blacklist:
        if domain in url.lower():
            return True
    return False

# -------------------------------------------------------------------------------------

# Matn ichidan linklarni ajratib oluvchi funksiya (3-qadam)
def extract_links(text: str) -> list:
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

# Guruh va chatlardagi xabarlarni tutuvchi asosiy handler
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
                # 7-QADAM: Bazadagi qora ro'yxat bilan solishtirish (Logika)
                if is_blacklisted(link):
                    # Link xavfli deb topildi!
                    log_link(user_id, user_name, chat_title, link, "BLOCKED (Phishing)")
                    
                    # Xabarni o'chirish harakati
                    try:
                        await message.delete()
                        # Guruhga o'zbek tilida ogohlantirish yuborish
                        await message.answer(
                            f"🛡️ **UzPhishGuard Ogohlantirishi!**\n"
                            f"@{user_name} yuborgan havola kiber-xavfsizlik tizimi tomonidan bloklandi!\n"
                            f"⚠️ **Turi:** Fishing / Firgarlik sayti."
                        )
                    except Exception as e:
                        print(f"Xabarni o'chirishda xatolik (Bot admin emas): {e}")
                else:
                    # Hozircha xavfsiz link
                    log_link(user_id, user_name, chat_title, link, "CLEAN (Passed)")
                    print(f"✅ Safe link logged: {link}")

# Botni doimiy faol holatda ushlab turish (Polling)
async def main():
    # Bot ishga tushganda ma'lumotlar bazasini ham start qildiramiz
    init_db()
    print("UzPhishGuard ma'lumotlar bazasi va kiber-logikasi muvaffaqiyatli ulandi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
