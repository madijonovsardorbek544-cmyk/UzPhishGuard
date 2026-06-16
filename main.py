import os
import re
import logging
import asyncio
from aiogram import Bot, Dispatcher, types
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

# .env faylidan o'zgaruvchilarni yuklash (Lokal muhit uchun)
load_dotenv()

# 2. Environment Variables (Muhit o'zgaruvchilari)
BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_ID = os.getenv("ADMIN_ID")

if not BOT_TOKEN:
    logger.critical("XATO: BOT_TOKEN topilmadi! Render'da o'zgaruvchilarni tekshiring.")
    exit(1)

# 3. Bot va Dispatcher obyektlarini yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# 4. Ma'lumotlar bazasiga ulanish va jadvalni tekshirish
def init_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        # Threats jadvali mavjud bo'lmasa yaratish
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                chat_id TEXT NOT NULL,
                chat_title TEXT,
                sender_username TEXT,
                threat_type TEXT,
                risk_score INTEGER,
                details TEXT,
                detected_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("🛡️ Supabase ma'lumotlar bazasi va jadvallar muvaffaqiyatli tekshirildi.")
    except Exception as e:
        logger.error(f"Bazaga ulanishda xatolik: {e}")

# Bazaga fishing hisobotini yozish funksiyasi
def log_threat_to_db(chat_id, chat_title, username, threat_type, risk_score, details):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        query = """
            INSERT INTO threats (chat_id, chat_title, sender_username, threat_type, risk_score, details)
            VALUES (%s, %s, %s, %s, %s, %s);
        """
        cursor.execute(query, (str(chat_id), chat_title, username, threat_type, int(risk_score), details))
        conn.commit()
        cursor.close()
        conn.close()
        logger.info(f"💾 Fishing xavfi bazaga saqlandi: {details}")
    except Exception as e:
        logger.error(f"Bazaga yozishda xatolik: {e}")

# 5. Kengaytirilgan Fishing va Shubhali Link Filtr Tizimi
def check_phishing(text: str) -> tuple[bool, int, str]:
    """
    Matnni fishing havolalariga tekshiradi.
    Qaytadi: (is_phishing, risk_score, reason)
    """
    if not text:
        return False, 0, ""

    text_clean = text.lower()
    
    # URL'larni ajratib olish (RegEx)
    urls = re.findall(r'(https?://[^\s]+)', text_clean)
    
    # Fishing uchun eng ko'p ishlatiladigan kalit so'zlar
    phishing_keywords = [
        "aksiya", "mukofot", "yutuq", "pul-olish", "bonus", "sovg'a", "sovga",
        "click", "payme", "uzcard", "humo", "olx", "mygov", "bank", "login",
        "fondi", "omadli", "tg-premium", "premium-tekin", "karta", "pul-bermoqda"
    ]
    
    # Oq ro'yxat (Whitelist) - Rasmiy va xavfsiz saytlar
    whitelist = ["kun.uz", "daryo.uz", "gazeta.uz", "lex.uz", "gov.uz", "telegram.org"]

    for url in urls:
        # Agar havola oq ro'yxatda bo'lsa, uni o'tkazib yuboramiz
        if any(good_site in url for good_site in whitelist):
            continue

        # 1-Ssenariy: Havola ichida fishing kalit so'zi qatnashsa (Masalan: uz-aksiya-mukofot.com)
        if any(keyword in url for keyword in phishing_keywords):
            return True, 95, f"Shubhali havola aniqlandi (Kalit so'z: {url})"
            
        # 2-Ssenariy: Matnning o'zida ijtimoiy muhandislik so'zlari bo'lib, yonida havola kelsa
        if any(keyword in text_clean for keyword in ["yutdingiz", "pul tarqatilyapti", "aksiya", "mukofot"]):
            return True, 90, f"Ijtimoiy muhandislik matni va havola kombinatsiyasi: {url}"

    return False, 0, ""

# 6. HANDLERS (Xabarlarni boshqarish)

# A. Shaxsiy xabarlar uchun (Private DM /start) - BOT ENDI JAVOB BERADI
@dp.message(CommandStart())
async def cmd_start_private(message: types.Message):
    if message.chat.type == ChatType.PRIVATE:
        await message.answer(
            "🛡️ **UzPhishGuard Enterprise tizimiga xush kelibsiz!**\n\n"
            "Meni guruhlaringizga **Administrator** qilib qo'shing hamda xabarlarni "
            "o'chirish (`Delete Messages`) huquqini bering.\n\n"
            "Guruhga tashlanadigan har qanday soxta aksiya, mukofot yoki kiber-fishing "
            "havolalarini lahzalarda o'chirib, guruh a'zolarini firgarlardan himoya qilaman!"
        )

# B. Guruh xabarlarini tahlil qilish va himoya qilish
@dp.message()
async def monitor_group_messages(message: types.Message):
    # Faqat guruh va superguruhlarda ishlaydi
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        
        # Adminlar xabarlarini tekshirmaslik (ixtiyoriy)
        if message.from_user.username == "GroupAnonymousBot":
            return

        is_phishing, risk_score, reason = check_phishing(message.text)

        if is_phishing:
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            # 1. Bazaga yozish (Dashboard uchun)
            log_threat_to_db(
                chat_id=message.chat.id,
                chat_title=chat_title,
                username=username,
                threat_type="FISHING_LINK",
                risk_score=risk_score,
                details=reason
            )
            
            # 2. Guruhdan fishing xabarini o'chirish
            try:
                await message.delete()
                
                # 3. Guruhga ogohlantirish yuborish
                warning_text = (
                    f"🛡️ **UzPhishGuard Himoya Tizimi**\n\n"
                    f"⚠️ Foydalanuvchi {username} tomonidan yuborilgan shubhali xabar/havola o'chirildi!\n"
                    f"📈 **Xavf darajasi:** {risk_score}%\n"
                    f"🚫 **Sabab:** Fishing yoki soxta aksiya elementi aniqlandi. Guruh a'zolarini ogoh bo'lishga chaqiramiz!"
                )
                sent_msg = await message.answer(warning_text)
                
                # Ogohlantirish xabarini guruh to'lib ketmasligi uchun 15 soniyadan keyin o'chirish
                await asyncio.sleep(15)
                await sent_msg.delete()
                
            except Exception as e:
                logger.error(f"Xabarni o'chirishda admin huquqi yetishmadi: {e}")

# 7. Asosiy ishga tushirish (Main)
async def main():
    logger.info("⚡ Supabase ulanishi tekshirilmoqda...")
    init_db()
    
    logger.info("🛡️ UzPhishGuard Enterprise Core faollashtirildi.")
    logger.info(f"Run polling for bot...")
    
    # Botga kelgan eski xabarlarni o'tkazib yuborish (Skip pending updates)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
