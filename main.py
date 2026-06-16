import os
import re
import logging
import asyncio
import hashlib
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import CommandStart
from aiogram.enums import ChatType
import psycopg2
from dotenv import load_dotenv

# 1. Loggingni sozlash
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

load_dotenv()

# 2. Muhit o'zgaruvchilari
BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

if not BOT_TOKEN:
    logger.critical("XATO: BOT_TOKEN topilmadi!")
    exit(1)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# 3. Ma'lumotlar bazasini tekshirish va yaratish
def init_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        # Yangi va mukammal jadval sxemasi (Link, APK va Matnlar uchun yagona standart)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                chat_id TEXT NOT NULL,
                chat_title TEXT,
                sender_username TEXT,
                threat_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                details TEXT,
                payload_raw TEXT,
                detected_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("🛡️ Supabase jadvali muvaffaqiyatli tekshirildi.")
    except Exception as e:
        logger.error(f"Bazaga ulanishda xatolik: {e}")

# Bazaga hisobot yozish funksiyasi
def log_threat_to_db(chat_id, chat_title, username, threat_type, risk_score, details, payload_raw=""):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        query = """
            INSERT INTO threats (chat_id, chat_title, sender_username, threat_type, risk_score, details, payload_raw)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """
        cursor.execute(query, (str(chat_id), chat_title, username, threat_type, int(risk_score), details, payload_raw))
        conn.commit()
        cursor.close()
        conn.close()
        logger.info(f"💾 [{threat_type}] xavfi bazaga muvaffaqiyatli saqlandi.")
    except Exception as e:
        logger.error(f"Bazaga yozishda xatolik: {e}")

# 4. Fishing havolalarini aniqlash mantiqi
def check_phishing(text: str) -> tuple[bool, int, str]:
    if not text:
        return False, 0, ""
    text_clean = text.lower()
    urls = re.findall(r'(https?://[^\s]+)', text_clean)
    
    phishing_keywords = [
        "aksiya", "mukofot", "yutuq", "pul-olish", "bonus", "sovg'a", "sovga",
        "click", "payme", "uzcard", "humo", "olx", "mygov", "bank", "login",
        "fondi", "omadli", "tg-premium", "premium-tekin", "karta", "pul-bermoqda"
    ]
    whitelist = ["kun.uz", "daryo.uz", "gazeta.uz", "lex.uz", "gov.uz", "telegram.org"]

    for url in urls:
        if any(good_site in url for good_site in whitelist):
            continue
        if any(keyword in url for keyword in phishing_keywords):
            return True, 95, f"Shubhali havola: {url}"
        if any(keyword in text_clean for keyword in ["yutdingiz", "pul tarqatilyapti", "aksiya"]):
            return True, 90, f"Ijtimoiy muhandislik matni va havola: {url}"
    return False, 0, ""

# 5. HANDLERS (Xabarlar nazorati)

# A. Bot shaxsiyiga yozilganda (/start)
@dp.message(CommandStart())
async def cmd_start_private(message: types.Message):
    if message.chat.type == ChatType.PRIVATE:
        await message.answer(
            "🛡️ **UzPhishGuard Enterprise tizimi ishlamoqda!**\n\n"
            "Meni guruhlaringizga qo'shib adminlik huquqini bersangiz, guruhdagi fishing "
            "linklar va zararli virusli `.apk` fayllarni avtomatik o'chirib beraman!"
        )

# B. Guruhga APK fayl tashlanganda tutib olish (Yangi qo'shilgan qism 🚀)
@dp.message(F.document)
async def monitor_apk_files(message: types.Message):
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        file_name = message.document.file_name.lower() if message.document.file_name else ""
        
        # Agar fayl formati .apk bo'lsa
        if file_name.endswith('.apk'):
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            try:
                # 1. Faylni RAM xotiraga yuklab olish (Tezlik uchun diskka yozilmaydi)
                file_info = await bot.get_file(message.document.file_id)
                file_buffer = await bot.download_file(file_info.file_path)
                file_bytes = file_buffer.read()
                
                # 2. SHA-256 xesh kodini hisoblash
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                logger.info(f"Genereatsiya qilingan APK SHA-256: {sha256_hash}")
                
                # 3. Bazaga xavf sifatida yozish
                log_threat_to_db(
                    chat_id=message.chat.id,
                    chat_title=chat_title,
                    username=username,
                    threat_type="APK",
                    risk_score=85, # Hozircha umumiy xavf balli, keyingi qadamda VirusTotal API ulanadi
                    details=f"Guruhga shubhali APK fayl yuklandi: {message.document.file_name}",
                    payload_raw=sha256_hash # Xesh kodni keyingi tahlillar uchun saqlaymiz
                )
                
                # 4. Guruhdan zararli faylni o'chirish va ogohlantirish
                await message.delete()
                warning = await message.answer(
                    f"🛡️ **UzPhishGuard Antivirus Filtr Tizimi**\n\n"
                    f"⚠️ Foydalanuvchi {username} guruhga shubhali **{message.document.file_name}** (.apk) faylini yukladi!\n"
                    f"🔒 **Xavfsizlik choralari:** Guruh a'zolarini troyan va viruslardan himoya qilish uchun fayl zudlik bilan o'chirildi.\n"
                    f"fingerprint `SHA-256`: `{sha256_hash[:20]}...`"
                )
                await asyncio.sleep(15)
                await warning.delete()
                
            except Exception as e:
                logger.error(f"APK tahlilida xatolik yuz berdi: {e}")

# C. Guruh matnlari va havolalarini nazorat qilish
@dp.message(F.text)
async def monitor_text_messages(message: types.Message):
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        if message.from_user.username == "GroupAnonymousBot":
            return

        is_phishing, risk_score, reason = check_phishing(message.text)

        if is_phishing:
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            log_threat_to_db(
                chat_id=message.chat.id,
                chat_title=chat_title,
                username=username,
                threat_type="LINK",
                risk_score=risk_score,
                details=reason,
                payload_raw=message.text
            )
            
            try:
                await message.delete()
                warning = await message.answer(
                    f"🛡️ **UzPhishGuard Himoya Tizimi**\n\n"
                    f"⚠️ Foydalanuvchi {username} yuborgan shubhali havola o'chirildi!\n"
                    f"🚫 **Sabab:** Fishing elementlari aniqlandi."
                )
                await asyncio.sleep(15)
                await warning.delete()
            except Exception as e:
                logger.error(f"Xabarni o'chirishda xatolik: {e}")

# 6. Ishga tushirish
async def main():
    logger.info("⚡ Supabase arxitekturasi tekshirilmoqda...")
    init_db()
    
    logger.info("🛡️ UzPhishGuard Enterprise Core faollashtirildi.")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
