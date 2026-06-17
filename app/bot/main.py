import os
import asyncio
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from loguru import logger
from dotenv import load_dotenv

# Biz yaratgan yadro pipeline va bazani import qilamiz
from app.scanners.core import pipeline
from app.database.database import db

load_dotenv()

# TOKEN-ni yuklash
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    logger.critical("KRIZIS: BOT_TOKEN topilmadi! Bot ishga tusha olmaydi.")
    raise ValueError("BOT_TOKEN konfiguratsiyada mavjud emas.")

# Bot va Dispatcher obyektlarini yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    """/start komandasi uchun xavfsizlik salomlashuvi."""
    welcome_text = (
        "🛡️ **UzPhishGuard Ekotizimiga Xush Kelibsiz!**\n\n"
        "Men guruhlardagi xabarlarni real vaqt rejimida fishing (soxta havolalar), "
        "ijtimoiy injeneriya va zararli APK fayllarga qarshi tahlil qiluvchi sun'iy intellekt tizimiman.\n\n"
        "💡 **Meni guruhga qo'shing va Admin huquqini bering**, qolganini o'zim xavfsiz nazorat qilaman!"
    )
    await message.reply(welcome_text, parse_mode="Markdown")

# ⚠️ ENERGIYA TEJAMKOR VA ENG ISHONCHLI FILTR (Matn, Havola, Rasm ostidagi yozuvlar uchun)
@dp.message(F.text | F.caption)
async def handle_group_messages(message: types.Message):
    """Guruhlar va shaxsiy chatdagi matnli xabarlarni asinxron tahlil qilish pipelinedi."""
    
    # 1. Agar xabar botning o'zidan yoki boshqa botdan bo'lsa - e'tiborsiz qoldiramiz
    if message.from_user.is_bot:
        return

    # 2. Xabar matnini aniqlash (Oddiy matn yoki rasm/video ostidagi matn)
    raw_text = message.text or message.caption
    
    # Agar hech qanday matn bo'lmasa (masalan faqat stiker yuborilsa), funksiyani to'xtatamiz
    if not raw_text:
        return

    # Guruh nomi yoki shaxsiy chat ekanligini aniqlash
    chat_title = message.chat.title if message.chat.title else "Shaxsiy Chat"
    sender_id = message.from_user.id
    chat_type = message.chat.type # private, group, supergroup

    logger.info(f"🔎 Tekshirilmoqda [{chat_type}]: {raw_text[:50]}...")

    # 3. Pipelinedan o'tkazish
    try:
        analysis = await pipeline.process_text_message(
            chat_title=chat_title,
            sender_id=sender_id,
            raw_text=raw_text
        )
    except Exception as e:
        logger.error(f"❌ Pipelinedagi tahlilda xatolik yuz berdi: {e}")
        return # Tizim qotib qolmasligi uchun jarayonni to'xtatamiz

    # 4. Agar fishing aniqlansa, tegishli choralarni ko'rish
    if analysis and analysis.get("is_phishing", False):
        risk_score = analysis.get("risk_score", 95) # Agar risk kelmasa default 95%
        logger.warning(f"🚨 FISHING ANIQLANDI! Guruh: {chat_title} | Risk: {risk_score}%")
        
        # Ogohlantirish xabari dizayni
        warning_message = (
            f"🚨 **DIQQAT! KIBER-TAHDID ANIQLANDI!** 🚨\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ **Turi:** Fishing / Soxta havola\n"
            f"⚡ **Xavf Darajasi:** {risk_score}%\n"
            f"📝 **Kontekst:** Sun'iy intellekt va Hevristika tizimi ushbu xabarda firgarlik alomatlarini aniqladi.\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🛑 **Fuqarolar diqqatiga:** Shaxsiy ma'lumotlaringiz va plastik karta kodlaringizni hech qachon kiritmang!"
        )
        
        # Agar xabar guruhda bo'lsa
        if chat_type in ["group", "supergroup"]:
            try:
                # Birinchi bo'lib havola xabarini o'chiramiz
                await message.delete()
                logger.info("🗑️ Fishing xabari muvaffaqiyatli o'chirildi.")
            except Exception as e:
                # Odatda bot admin bo'lmasa shu xatoni beradi
                logger.info(f"ℹ️ Xabarni o'chirib bo'lmadi (Bot guruhda admin emas deb taxmin qilinmoqda): {e}")

            # Guruhga umumiy ogohlantirishni yuboramiz
            await message.answer(warning_message, parse_mode="Markdown")
            
        # Agar xabar shaxsiy bot chatida yuborilgan bo'lsa (faqat foydalanuvchini ogohlantirish uchun)
        elif chat_type == "private":
            await message.reply(warning_message, parse_mode="Markdown")

async def main():
    """Botni ishga tushiruvchi asosiy funksiya."""
    logger.info("🚀 UzPhishGuard Asinxron Bot Tizimi ishga tushmoqda...")
    
    # Ma'lumotlar bazasi poolini ochish
    try:
        await db.initialize_pool()
        logger.info("✅ Ma'lumotlar bazasiga muvaffaqiyatli ulandi.")
    except Exception as e:
        logger.error(f"⚠️ Pool ochishda xatolik (Local test rejimida davom etiladi): {str(e)}")

    # Botni barcha ruxsat berilgan turlar bilan ishga tushirish (xabarlar doim yetib kelishi uchun)
    try:
        await dp.start_polling(bot, allowed_updates=["message", "edited_message"])
    finally:
        # Tizim o'chganda bazani xavfsiz yopish
        await db.close()
        logger.info("🛑 Tizim xavfsiz tarzda o'chirildi.")

if __name__ == "__main__":
    asyncio.run(main())
