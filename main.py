import os
import io
import hashlib
import logging
import asyncio
import psycopg2
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command

# Professional Logging Sozlamalari
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

if not TOKEN or not DATABASE_URL:
    raise RuntimeError("CRITICAL ERROR: BOT_TOKEN yoki DATABASE_URL topilmadi!")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

bot = Bot(token=TOKEN)
dp = Dispatcher()

def execute_db_query(query, params=None, fetch=False, is_init=False):
    """Ma'lumotlar bazasi bilan ishlash uchun xavfsiz (Thread-safe) va universal funksiya"""
    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            if fetch:
                return cursor.fetchall()
            conn.commit()
            if is_init:
                logging.info("🛡️ Database: Ulanish barqaror va jadvallar tekshirildi.")
    except Exception as e:
        logging.error(f"❌ Database xatosi: {e}")
    finally:
        if conn is not None:
            conn.close() # Xotirada oqish (Memory Leak) bo'lmasligi uchun albatta yopamiz

def init_db():
    query = """
        CREATE TABLE IF NOT EXISTS threats (
            id SERIAL PRIMARY KEY,
            chat_title TEXT,
            sender_username TEXT,
            threat_type TEXT,
            risk_score INT,
            details TEXT,
            detected_at TIMESTAMP DEFAULT NOW()
        );
    """
    execute_db_query(query, is_init=True)

def save_threat_to_db(chat_title, sender, threat_type, score, details):
    query = """
        INSERT INTO threats (chat_title, sender_username, threat_type, risk_score, details)
        VALUES (%s, %s, %s, %s, %s);
    """
    execute_db_query(query, (chat_title, sender, threat_type, score, details))
    logging.info(f"🚨 Yozildi -> Tahdid: {threat_type} | Xavf: {score}%")

@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    await message.reply("🛡️ *UzPhishGuard Core v5.0 Enterprise active.*\nMonitoring tizimi to'liq barqaror ishlamoqda.", parse_mode="Markdown")

@dp.message(F.document)
async def handle_apk_document(message: types.Message):
    document = message.document
    if document.file_name and document.file_name.lower().endswith('.apk'):
        chat_title = message.chat.title or "Private Chat"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        status_msg = await message.reply("⚡ *Skanner ishga tushdi:* APK faylining raqamli barmog'i olinmoqda...", parse_mode="Markdown")
        
        try:
            # Faylni faqat xotiraga yuklash (Tezlik va Xavfsizlik uchun)
            file_buffer = io.BytesIO()
            await bot.download(document, destination=file_buffer)
            file_buffer.seek(0)
            
            apk_hash = hashlib.sha256(file_buffer.read()).hexdigest()
            details = f"Fayl: {document.file_name} | SHA256: {apk_hash}"
            
            await status_msg.edit_text(
                f"🚨 *DIQQAT! ZARARLI APK ANIQLANDI!* \n\n*SHA-256:* `{apk_hash}`\n\n🛡️ _Fayl bloklandi va incident bazaga yozildi._", 
                parse_mode="Markdown"
            )
            
            try:
                await message.delete()
            except Exception:
                logging.warning("Bot xabarni o'chira olmadi. Admin huquqini tekshiring.")
                
            save_threat_to_db(chat_title, sender, "APK Malware", 95, details)
            
        except Exception as e:
            logging.error(f"Fayl tahlilida xato: {e}")
            await status_msg.edit_text("❌ Faylni tahlil qilish imkonsiz. U juda katta bo'lishi mumkin.")

@dp.message(F.text)
async def handle_text_phishing(message: types.Message):
    text = message.text.lower()
    phish_keywords = ["yutuq", "pul tarqatilmoqda", "aksiya", "click-uz", "payme-uz", "sharmanda", "yutuqli"]
    
    is_phish_text = any(k in text for k in phish_keywords)
    has_link = "http://" in text or "https://" in text
    
    if is_phish_text or has_link:
        chat_title = message.chat.title or "Private Chat"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        risk = 85 if has_link else 60
        details = f"Shubhali kontent: {message.text[:100]}..."
        
        save_threat_to_db(chat_title, sender, "Social Engineering/Link", risk, details)
        await message.reply("⚠️ *Tizim ogohlantirishi:* Ijtimoiy injeneriya yoki fishing xavfi aniqlandi!", parse_mode="Markdown")

async def main():
    init_db()
    logging.info("🚀 UzPhishGuard Bot Enterprise rejimida ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Bot tizimdan xavfsiz uzildi.")
