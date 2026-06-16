import os
import io
import hashlib
import logging
import asyncio
import psycopg2
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command

# Tizim loglarini konsolda ko'rish uchun yoqamiz
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

# Agar bazada postgres:// bo'lsa, uni psycopg2 tushunadigan postgresql:// formatiga o'tkazamiz
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

bot = Bot(token=TOKEN)
dp = Dispatcher()

def init_db():
    """Bot ishga tushganda Supabase bazasida jadval borligini tekshiradi va standartlashtiradi"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                chat_title TEXT,
                sender_username TEXT,
                threat_type TEXT,
                risk_score INT,
                details TEXT,
                detected_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        logging.info("🛡️ Enterprise ma'lumotlar bazasi unifikatsiya qilindi va tayyor holatga keltirildi.")
    except Exception as e:
        logging.error(f"❌ Ma'lumotlar bazasini initsializatsiya qilishda xato yuz berdi: {e}")

def save_threat_to_db(chat_title, sender_username, threat_type, risk_score, details):
    """Dashboard xatosiz o'qishi uchun ma'lumotlarni yagona standartda saqlash"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        query = """
            INSERT INTO threats (chat_title, sender_username, threat_type, risk_score, details, detected_at)
            VALUES (%s, %s, %s, %s, %s, NOW());
        """
        cursor.execute(query, (chat_title, sender_username, threat_type, risk_score, details))
        conn.commit()
        cursor.close()
        conn.close()
        logging.info(f"💾 Kiber-tahdid logi bazaga yozildi: {threat_type}")
    except Exception as e:
        logging.error(f"❌ Tahdidni bazaga yozishda uzilish: {e}")

@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    await message.reply("🛡️ *UzPhishGuard Core v4.5 active.*\nTizim kiber-xavfsizlik monitoringi rejimida ishlamoqda. Guruhni himoya qilishga tayyorman!", parse_mode="Markdown")

@dp.message(F.document)
async def handle_apk_document(message: types.Message):
    document = message.document
    if document.file_name and document.file_name.lower().endswith('.apk'):
        chat_title = message.chat.title if message.chat.title else "Private Chat"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        status_msg = await message.reply("⚡ *UzPhishGuard:* Shubhali APK aniqlandi! SHA-256 kiber-barmog'i tahlil qilinmoqda...", parse_mode="Markdown")
        
        try:
            # Faylni xotiraga (RAM) oqim ko'rinishida yuklab olish (Diskni to'ldirmaydi, tez ishlaydi)
            file_buffer = io.BytesIO()
            await bot.download(document, destination=file_buffer)
            file_buffer.seek(0)
            
            # SHA-256 xesh kodini generatsiya qilish
            sha256_gen = hashlib.sha256()
            sha256_gen.update(file_buffer.read())
            apk_hash = sha256_gen.hexdigest()
            
            details = f"Fayl nomi: {document.file_name} | SHA256 Kiber-Barmoq: {apk_hash}"
            
            # Guruhni ogohlantirish paneli
            await status_msg.edit_text(f"🚨 *DIQQAT! GURUHDA ZARARLI APK ANIQLANDI!* \n\n*Fayl:* `{document.file_name}`\n*SHA-256:* `{apk_hash}`\n\nTahdid bartaraf etildi, hodisa SOC dashboardga yuborildi.", parse_mode="Markdown")
            
            try:
                await message.delete() # Guruh xavfsizligi uchun virusli faylni o'chirish
            except Exception:
                logging.warning("⚠️ Xabarni o'chirish uchun botda adminlik huquqi yetarli emas.")
                
            save_threat_to_db(chat_title, sender, "APK", 95, details)
            
        except Exception as e:
            logging.error(f"APK tahlili jarayonida xatolik: {e}")
            await status_msg.edit_text("❌ Tizim yuklamani tahlil qilishda texnik muammoga duch keldi.")

@dp.message(F.text)
async def handle_text_phishing(message: types.Message):
    text = message.text.lower()
    # O'zbekistondagi kiber-fishing kalit so'zlari luyg'ati
    phish_keywords = ["yutuq", "pul tarqatilmoqda", "aksiya", "click-uz", "payme-uz", "sharmanda", "yutuqli o'yin", "fondi", "premiya"]
    is_threat = any(keyword in text for keyword in phish_keywords) or "http://" in text or "https://" in text
    
    if is_threat:
        chat_title = message.chat.title if message.chat.title else "Private Chat"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        # Havola bo'lsa xavf darajasini yuqori, shunchaki matn bo'lsa o'rta deb belgilaymiz
        risk = 80 if "http" in text else 55
        details = f"Matn tahlilida shubhali kontent: {message.text[:120]}"
        
        save_threat_to_db(chat_title, sender, "LINK/TEXT", risk, details)
        await message.reply("⚠️ *Diqqat!* Ushbu xabarda fishing yoki ijtimoiy injeneriya alomatlari aniqlandi! Iltimos, havolalarga kirmang va shaxsiy ma'lumotlaringizni yozmang.", parse_mode="Markdown")

async def main():
    init_db() # Bot yoqilishi bilan bazani tekshirib oladi
    logging.info("🚀 UzPhishGuard Bot polling rejimida monitoringni boshladi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
