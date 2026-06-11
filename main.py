import os
import re
import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.enums import ParseMode
from dotenv import load_dotenv

# .env faylidan token va konfiguratsiyalarni yuklash
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

# Xatoliklar va loglarni kuzatish tizimi (Logging)
logging.basicConfig(level=logging.INFO)

# Bot va Dispatcher obyektlarini yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# MATN ICHIDAN LINKLARNI AJRATIB OLUVCHI FUNKSIYA (3-QADAM)
def extract_links(text: str) -> list:
    """
    Regex (Muntazam ifodalar) yordamida matn ichidagi barcha 
    http:// yoki https:// bilan boshlangan havolalarni ajratib oladi.
    """
    url_pattern = r'https?://[^\s]+'
    found_urls = re.findall(url_pattern, text)
    return found_urls

# Guruh va chatlardagi xabarlarni tutuvchi asosiy handler
@dp.message()
async def check_message_for_links(message: types.Message):
    # Agar xabarda matn bo'lsa, uni tekshiramiz
    if message.text:
        text_content = message.text
        
        # Matn ichidan linklarni qidiramiz
        detected_links = extract_links(text_content)
        
        # Agar kamida bitta link topilsa, konsolga chiqarib turamiz
        if detected_links:
            chat_title = message.chat.title or "Private Chat"
            user_name = message.from_user.username or "Unknown"
            
            print(f"⚠️ LINK ANIQLANDI! | Chat: {chat_title} | User: @{user_name}")
            print(f"🔗 Topilgan havolalar: {detected_links}")
            
            # 2-BOSQICHDA SHU YERGA LINKNI BAZA BILAN SOLISHTIRISH LOGIKASINI QO'YAMIZ

# Botni doimiy faol holatda ushlab turish (Polling)
async def main():
    print("UzPhishGuard boti GitHub arxivida muvaffaqiyatli yangilandi va ishga tushishga tayyor...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
