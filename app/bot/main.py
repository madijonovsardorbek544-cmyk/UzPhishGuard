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

@dp.message(F.text)
async def handle_group_messages(message: types.Message):
    """Guruhlar va shaxsiy chatdagi matnli xabarlarni asinxron tahlil qilish pipelinedi."""
    # Agar xabar botning o'zidan bo'lsa, tekshirmaymiz
    if message.from_user.is_bot:
        return

    chat_title = message.chat.title if message.chat.title else "Shaxsiy Chat"
    sender_id = message.from_user.id
    raw_text = message.text

    # Pipelinedan o'tkazish
    analysis = await pipeline.process_text_message(
        chat_title=chat_title,
        sender_id=sender_id,
        raw_text=raw_text
    )

    # Agar fishing aniqlansa, guruhni himoya qilish choralari
    if analysis["is_phishing"]:
        logger.warning(f"🚨 FISHING ANIQLANDI! Guruh: {chat_title} | Risk: {analysis['risk_score']}%")
        
        # Guruhga kiber-tahdid haqida professional ogohlantirish yuborish
        warning_message = (
            f"🚨 **DIQQAT! KIBER-TAHDID ANIQLANDI!** 🚨\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ **Turi:** Fishing / Soxta havola\n"
            f"⚡ **Xavf Darajasi:** {analysis['risk_score']}%\n"
            f"📝 **Kontekst:** Sun'iy intellekt va Hevristika tizimi ushbu xabarda firgarlik alomatlarini aniqladi.\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🛑 **Fuqarolar diqqatiga:** Shaxsiy ma'lumotlaringiz va plastik karta kodlaringizni hech qachon kiritmang!"
        )
        
        try:
            # Xabarni guruhdan o'chirishga harakat qilish (Admin huquqi bo'lsa)
            await message.delete()
            logger.info("🗑️ Fishing xabari muvaffaqiyatli o'chirildi.")
        except Exception as e:
            logger.info(f"ℹ️ Xabarni o'chirib bo'lmadi (Bot guruhda admin emas yoki shaxsiy chat): {str(e)}")

        await message.answer(warning_message, parse_mode="Markdown")

async def main():
    """Botni ishga tushiruvchi asosiy funksiya."""
    logger.info("🚀 UzPhishGuard Asinxron Bot Tizimi ishga tushmoqda...")
    
    # Ma'lumotlar bazasi poolini ochish
    try:
        await db.initialize_pool()
    except Exception as e:
        logger.error(f"⚠️ Pool ochishda xatolik (Local test rejimida davom etiladi): {str(e)}")

    # Botni ishga tushirish (Polling)
    try:
        await dp.start_polling(bot)
    finally:
        # Tizim o'chganda bazani xavfsiz yopish
        await db.close()

if __name__ == "__main__":
    asyncio.run(main())
