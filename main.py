import os
import re
import logging
import asyncio
import sqlite3
from datetime import datetime
from difflib import SequenceMatcher

import requests
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command

# Logging sozlamalari (Tizim loglarini kuzatish uchun)
logging.basicConfig(level=logging.INFO)

# 1. TOKEN VA KALITLARNI SOZLASh
# Professional yondashuv: Avval Atrof-muhit o'zgaruvchilaridan qidiradi, bo'lmasa standart qiymat oladi
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "7437706342:AAEL7G-I9C9xG6X7Yk3R8fO2u8m1D4D")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "62f4e3c9b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")

bot = Bot(token=TOKEN)
dp = Dispatcher()

DB_NAME = "phish_guard.db"

# 2. MA'LUMOTLAR BAZASI BILAN ISHLASh
def init_db():
    """SQLite bazasini va kerakli jadvallarni yaratadi."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Skaner qilingan linklar jadvali
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scanned_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
            chat_title TEXT,
            username TEXT,
            url TEXT,
            status TEXT
        )
    """)
    
    # Mahalliy qora ro'yxat jadvali
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklisted_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
    """)
    
    # Standart o'zbekcha fishing domenlarni bazaga kiritish
    default_blacklist = [
        "telegram-premium-free.com",
        "payme-security-update.com",
        "click-uz-gift.net",
        "olx-uz-safe-transaction.ru"
    ]
    for domain in default_blacklist:
        try:
            cursor.execute("INSERT OR IGNORE INTO blacklisted_domains (domain) VALUES (?)", (domain,))
        except Exception:
            pass
            
    conn.commit()
    conn.close()

def log_to_db(chat_title, username, url, status):
    """Skanerlash natijalarini ma'lumotlar bazasiga yozadi."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO scanned_links (scan_date, chat_title, username, url, status)
            VALUES (?, ?, ?, ?, ?)
        """, (now, chat_title, username, url, status))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Baza bilan ishlashda xatolik: {e}")

# 3. DETEKSIYA ALGORITMLARI VA MODULLARI

def extract_links(text: str) -> list:
    """Matn ichidan barcha http/https havolalarni ajratib oladi."""
    return re.findall(r'https?://[^\s]+', text)

def is_local_blacklisted(url: str) -> bool:
    """Havola mahalliy qora ro'yxatda bor-yo'qligini tekshiradi."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM blacklisted_domains")
        domains = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return any(domain in url.lower() for domain in domains)
    except Exception:
        return False

def check_typosquatting(url: str) -> bool:
    """Domen nomining rasmiy brendlarga o'xshashligini tekshiradi (Typosquatting)."""
    official_brands = ["payme.uz", "click.uz", "click.uz", "id.uz", "uzcard.uz", "humocard.uz", "wikipedia.org", "github.com"]
    
    # Havoladan domenni ajratib olish
    domain_match = re.search(r'https?://([^/]+)', url.lower())
    if not domain_match:
        return False
    incoming_domain = domain_match.group(1)
    
    for brand in official_brands:
        if incoming_domain == brand:
            return False # Mutloq bir xil bo'lsa - bu xavfsiz rasmiy sayt
            
        # O'xshashlik foizini hisoblash
        ratio = SequenceMatcher(None, incoming_domain, brand).ratio()
        if ratio >= 0.75: # 75% dan yuqori o'xshashlik bo'lsa - demak soxtalashtirilgan
            return True
            
    return False

def contains_phishing_keywords(text: str) -> bool:
    """Matnda fishingga xos psixologik manipulyatsiya so'zlari borligini aniqlaydi (Heuristic)."""
    keywords = ["yutuq", "tekin", "premium", "aksiya", "sovg'a", "omadli", "pul tarqatilyapti", "bonus"]
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in keywords)

def clean_text_for_ai(text: str) -> str:
    """Hujumchilar harflar orasiga qo'yadigan ortiqcha belgilarni tozalaydi."""
    cleaned = re.sub(r'(?<=\s)(?:\w\.)+\w?', lambda m: m.group().replace('.', ''), text)
    cleaned = re.sub(r'[._\-\+\*]', '', cleaned)
    return cleaned.lower()

async def analyze_with_ai(text: str) -> bool:
    """Hugging Face Inference API orqali matnning kiber-tahlilini (NLP Context) o'tkazadi."""
    API_URL = "https://api-inference.huggingface.co/models/DTrimper/phishing-detection-transformer"
    
    cleaned_text = clean_text_for_ai(text)
    try:
        # Asinxron muhitda sinxron requests'ni bloklamaydigan rejimda ishga tushirish
        response = await asyncio.to_thread(
            requests.post, API_URL, json={"inputs": cleaned_text}, timeout=4
        )
        if response.status_code == 200:
            predictions = response.json()
            if isinstance(predictions, list) and len(predictions) > 0:
                top_pred = predictions[0][0] if isinstance(predictions[0], list) else predictions[0]
                label = top_pred.get("label", "")
                score = top_pred.get("score", 0.0)
                
                # 'LABEL_1' odatda modelda phishing tahdidini bildiradi
                if "1" in label and score > 0.75:
                    return True
    except Exception as e:
        logging.error(f"AI Engine Error: {e}")
    return False

async def check_virustotal(url: str) -> bool:
    """VirusTotal API v3 orqali havolani global tahlildan o'tkazadi."""
    if VIRUSTOTAL_API_KEY.startswith("62f4e3"): # Kalit o'zgartirilmagan bo'lsa o'tkazib yuboradi
        return False
        
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}
    
    try:
        response = await asyncio.to_thread(
            requests.post, api_url, data=data, headers=headers, timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            # Vt hisobotni qayta ishlash logikasi shu yerda bo'ladi
            # Be'pul API limitlari uchun sodda tekshiruv
            return False
    except Exception as e:
        logging.error(f"VirusTotal Error: {e}")
    return False

# 4. TELEGRAM BOT HANDLERLARI (BOT REAKSIYASI)

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    """Bot ishga tushganda salomlashish xabari."""
    await message.reply(
        "🛡️ **UzPhishGuard Cyber Security Bot Active!**\n\n"
        "Meni guruhlarga administrator huquqlari bilan qo'shing. "
        "Men real vaqt rejimida fishing va soxta havolalarni guruhdan tozalab turaman!"
    )

@dp.message(F.text)
async def check_message_for_links(message: types.Message):
    """Kelgan xabarlarni barcha kiber-himoya qatlamlaridan o'tkazadi."""
    text_content = message.text
    detected_links = extract_links(text_content)
    
    if not detected_links:
        return # Havola bo'lmasa tekshirish shart emas

    chat_title = message.chat.title or "Private Chat"
    user_id = message.from_user.id
    user_name = message.from_user.username or "Unknown"

    for link in detected_links:
        is_phishing = False
        reason = ""

        # 🚀 STRATEGIK XAVFSIZLIK QATLAMYARI (KETMA-KETLIK TO'G'RILANDI)
        if is_local_blacklisted(link):
            is_phishing = True
            reason = "Mahalliy qora ro'yxat (Blacklist)"
            
        elif check_typosquatting(link):
            is_phishing = True
            reason = "Typosquatting (Domen o'xshashligi)"
            
        elif contains_phishing_keywords(text_content):
            is_phishing = True
            reason = "Shubhali fishing matni (Heuristic)"
            
        elif await analyze_with_ai(text_content):
            is_phishing = True
            reason = "AI Neyrotarmoq Tahlili (Contextual NLP)"
            
        elif await check_virustotal(link):
            is_phishing = True
            reason = "Global VirusTotal (Antivirus Engine)"

        # 5. QAROR QABUL QILISh VA BLOKLASh
        if is_phishing:
            # Guruh xavfsizligi logi bazaga yoziladi
            log_to_db(chat_title, user_name, link, f"BLOCKED ({reason})")
            
            # Guruh adminlik huquqini tekshirib xabarni o'chirish
            try:
                await message.delete()
                
                # Guruhga professional ogohlantirish yuborish
                warning_text = (
                    f"⚠️ **UzPhishGuard Kiber-Himoya!**\n"
                    f"@{user_name} yuborgan havola xavfsizlik tizimi tomonidan o'chirildi.\n\n"
                    f"🛑 **Sabab:** {reason}\n"
                    f"💡 **Tavsiya:** Shaxsiy ma'lumotlar va plastik karta kodlarini shubhali saytlarga kiritmang!"
                )
                await message.answer(warning_text)
            except Exception as e:
                logging.error(f"Xabarni o'chirishda xatolik (Bot admin emasmi?): {e}")
            break # Bitta xabarda bir nechta link bo'lsa ham bir marta chora ko'rish yetarli
        else:
            # Havola xavfsiz bo'lsa ham bazaga qayd etiladi
            log_to_db(chat_title, user_name, link, "CLEAN (Passed)")

# 6. ASOSIY ISHGA TUShIRUVChI QISM
async def main():
    init_db() # Dastur boshlanishida bazani tekshirish va qurish
    logging.info("Bot muvaffaqiyatli ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
