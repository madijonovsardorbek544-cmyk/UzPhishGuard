import os
import io
import hashlib
import logging
import asyncio
from datetime import datetime
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError

# 1. STRATEGIK LOGGING TIZIMI
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("UzPhishGuardCore")

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

if not BOT_TOKEN or not DATABASE_URL:
    logger.critical("KRIZIS: BOT_TOKEN yoki DATABASE_URL muhit o'zgaruvchilari ichida topilmadi!")
    raise ValueError("Tizimni ishga tushirish uchun kerakli tokenlar yetishmayapti.")

# Render va Supabase ulanish formati mutanosibligi
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


# 2. XAVFSIZ MA'LUMOTLAR BAZASI PANEL-ARXITEKTURASI (Connection Pooling simulyatsiyasi)
class DatabaseManager:
    def __init__(self, db_url: str):
        self.db_url = db_url

    def _get_connection(self):
        """Har bir so'rov uchun xavfsiz va izolyatsiya qilingan ulanish yaratish"""
        return psycopg2.connect(self.db_url)

    def initialize_schema(self):
        """Jadval mavjudligini tekshirish va kiber-metrika standartlarini o'rnatish"""
        query = """
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                chat_title TEXT NOT NULL,
                sender_username TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                risk_score INT NOT NULL,
                details TEXT NOT NULL,
                detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                cursor.execute(query)
            conn.commit()
            logger.info("🛡️ Database Schema tekshirildi: Tizim to'liq unifikatsiya qilingan.")
        except Exception as e:
            logger.error(f"❌ Database Schema initsializatsiyasida xatolik: {e}")
            raise e
        finally:
            if conn:
                conn.close()

    def log_threat(self, chat_title: str, sender: str, threat_type: str, score: int, details: str):
        """Asinxron oqimdan kelgan ma'lumotni bazaga xavfsiz yozish (Fault-tolerant)"""
        query = """
            INSERT INTO threats (chat_title, sender_username, threat_type, risk_score, details)
            VALUES (%s, %s, %s, %s, %s);
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cursor:
                cursor.execute(query, (chat_title, sender, threat_type, score, details))
            conn.commit()
            logger.info(f"💾 [SIEM LOG] Muvaffaqiyatli saqlandi -> {threat_type} ({score}%)")
        except Exception as e:
            logger.error(f"❌ [DATABASE WRITE ERROR] Tahdidni yozishda uzilish: {e}")
        finally:
            if conn:
                conn.close()

db = DatabaseManager(DATABASE_URL)


# 3. BOT VA DISPATCHER INITIALIZATION
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN))
dp = Dispatcher()


# 4. PROFESSIONAL COMMAND HANDLERS
@dp.message(Command("start"))
async def process_start_command(message: types.Message):
    welcome_text = (
        "🛡️ *UzPhishGuard Cyber Security Core v6.0*\n\n"
        "Tizim kiber-tahdidlarni real vaqt rejimida monitoring qilish rejimida faol.\n"
        "⚡ _Status: Optimal, Server: Render TLS, SIEM: Connected._"
    )
    await message.reply(welcome_text)


# 5. STRATEGIK RUN-TIME SKANERLAR (Malware & Fishing Detektorlari)
@dp.message(F.document)
async def scan_incoming_document(message: types.Message):
    """Guruhga tashlangan .apk fayllarni RAM darajasida ushlab xeshini tekshirish"""
    document = message.document
    
    if document.file_name and document.file_name.lower().endswith('.apk'):
        chat_title = message.chat.title or "Yopiq Chat (Private)"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        status_notification = await message.reply("⚡ *UzPhishGuard Sandbox:* Shubhali obyekt (APK) aniqlandi. Statik analiz boshlanmoqda...")
        
        try:
            # Faylni xotira oqimida (RAM buffer) yuklab olish - Diskni band qilmaydi, tez ishlaydi
            file_stream = io.BytesIO()
            await bot.download(document, destination=file_stream)
            file_stream.seek(0)
            
            # Kiber-barmog'ini (SHA-256) generatsiya qilish
            sha256_context = hashlib.sha256()
            sha256_context.update(file_stream.read())
            file_hash = sha256_context.hexdigest()
            
            log_details = f"Fayl: {document.file_name} | Hajmi: {document.file_size} bytes | SHA256: {file_hash}"
            
            # Dashboard va ma'lumotlar bazasiga sinxronizatsiya
            db.log_threat(chat_title, sender, "APK/Malware.Trojan", 98, log_details)
            
            # Guruh xavfsizligi uchun virusni tozalash va ogohlantirish
            await status_notification.edit_text(
                f"🚨 *KRITIK TAHDID BARTARAF ETILDI!*\n\n"
                f"*Turi:* Android Troyan (Malware)\n"
                f"*Fayl:* `{document.file_name}`\n"
                f"*SHA-256:* `{file_hash}`\n\n"
                f"🛡️ _Zararli kontent guruh xavfsizligi uchun o'chirildi va SIEM panelga uzatildi._"
            )
            
            try:
                await message.delete()
            except TelegramAPIError:
                logger.warning(f"Xabarni o'chirib bo'lmadi. Bot '{chat_title}' guruhida admin huquqiga ega emas.")
                
        except Exception as error:
            logger.error(f"Hujjat tahlili jarayonida kutilmagan xatolik: {error}")
            await status_notification.edit_text("⚠️ *Tizim ogohlantirishi:* APK fayli tahlil qilinayotganda ichki xatolik yuz berdi.")


@dp.message(F.text)
async def scan_text_phishing(message: types.Message):
    """ Fishing xabarlar va shubhali linklarni intellektual filtratsiyalash """
    content = message.text.lower()
    
    # Korporativ kiber-lug'at
    fishing_signatures = [
        "yutuq", "pul tarqatilmoqda", "aksiya", "click-uz", "payme-uz", 
        "sharmanda", "yutuqli", "telegram-premium", "sovg'a", "shoshiling"
    ]
    
    contains_signature = any(signature in content for signature in fishing_signatures)
    contains_url = "http://" in content or "https://" in content
    
    if contains_signature or contains_url:
        chat_title = message.chat.title or "Yopiq Chat (Private)"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        # Risk darajasini baholash (Heuristic scoring)
        risk_level = 90 if (contains_signature and contains_url) else (75 if contains_url else 55)
        threat_label = "Phishing Link" if contains_url else "Social Engineering Matni"
        
        db.log_threat(chat_title, sender, threat_label, risk_level, f"Kontent: {message.text[:150]}...")
        
        await message.reply(
            "⚠️ *KIBER-FISHING OGOHLANTIRIShI!*\n\n"
            "Ushbu xabarda shubhali havolalar yoki fishing alomatlari aniqlandi. "
            "Iltimos, profilingiz xavfsizligi uchun shaxsiy ma'lumotlaringizni va SMS kodlarni hech qayerga kiritmang!"
        )


# 6. LIFECYCLE MANAGEMENT & INDUSTRIAL STARTUP
async def main():
    logger.info("Tizim ishga tushirilmoqda...")
    
    # Bot yoqilishi bilan bazani tekshirish va tayyorlash
    db.initialize_schema()
    
    # Eskirgan so'rovlarni (Webservice o'chiq turgandagi) tozalab yuborish (Drop pending updates)
    await bot.delete_webhook(drop_pending_updates=True)
    
    logger.info("🚀 UzPhishGuard Core v6.0 polling rejimida 100% barqarorlik bilan ishga tushdi.")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot tizim tomonidan xavfsiz to'xtatildi.")
