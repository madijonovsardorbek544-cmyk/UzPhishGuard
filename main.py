import os
import re
import logging
import asyncio
import hashlib
import aiohttp
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
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") # Render'da buni qo'shish kerak bo'ladi

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

# 4. Global Threat Intel: VirusTotal API orqali xeshni tekshirish
async def check_virustotal(file_hash: str) -> tuple[bool, int, str]:
    """
    Fayl xeshini VirusTotal API orqali tekshiradi.
    Qaytadi: (is_malicious, risk_score, details)
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY topilmadi! Static checking rejimi yoqildi.")
        return False, 0, "VirusTotal API kaliti sozlanmagan."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    undetected_count = stats.get('undetected', 0)
                    total_scanners = sum(stats.values())
                    
                    # Agar kamida 2 ta global antivirus buni virus deb topsa
                    if malicious_count >= 2:
                        risk_score = int((malicious_count / (malicious_count + undetected_count + 1)) * 100)
                        risk_score = min(max(risk_score, 70), 100) # 70% va 100% orasida ball
                        
                        # Virus turini aniqlash (eng mashhur deteksiya nomi)
                        results = data['data']['attributes']['last_analysis_results']
                        virus_name = "Zararli dastur (Malware)"
                        for engine, res in results.items():
                            if res.get('result'):
                                virus_name = res['result']
                                break
                                
                        return True, risk_score, f"Global Antivirus Deteksiyasi: {virus_name} ({malicious_count} ta motor aniqladi)"
                    else:
                        return False, 0, "Global bazada xavfsiz yoki noma'lum."
                elif response.status == 404:
                    return False, 0, "Fayl xeshi global bazada mavjud emas (Yangi fayl)."
                else:
                    logger.error(f"VirusTotal API xatosi: {response.status}")
                    return False, 0, "API so'rovida xatolik."
        except Exception as e:
            logger.error(f"VirusTotal ulanish xatosi: {e}")
            return False, 0, f"Ulanish xatosi: {e}"

# 5. Fishing havolalarini aniqlash mantiqi
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

# 6. HANDLERS
@dp.message(CommandStart())
async def cmd_start_private(message: types.Message):
    if message.chat.type == ChatType.PRIVATE:
        await message.answer(
            "🛡️ **UzPhishGuard Enterprise v2.0 faol!**\n\n"
            "Meni guruhlaringizga qo'shib adminlik huquqini bering. Endi men nafaqat linklarni, "
            "balki global **VirusTotal API** orqali haqiqiy kiber-viruslarni ham aniqlay olaman!"
        )

@dp.message(F.document)
async def monitor_apk_files(message: types.Message):
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        file_name = message.document.file_name.lower() if message.document.file_name else ""
        
        # Agarda guruhga fayl tashlansa (Biz faqat .apk ni qattiq nazorat qilamiz yoki boshqa fayllarni ham)
        if file_name.endswith('.apk'):
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            try:
                # 1. Faylni RAMga yuklash
                file_info = await bot.get_file(message.document.file_id)
                file_buffer = await bot.download_file(file_info.file_path)
                file_bytes = file_buffer.read()
                
                # 2. SHA-256 xesh kodini generatsiya qilish
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                logger.info(f"Tekshirilayotgan APK SHA-256: {sha256_hash}")
                
                # 3. Global Threat Intelligence orqali tekshirish
                is_malicious, risk_score, virus_details = await check_virustotal(sha256_hash)
                
                # Bizning kiber-mantiq: Agarda global bazada virus deb topilsa YOKI har qanday holatda guruh xavfsizligi uchun .apk taqiqlangan bo'lsa
                # Enterprise himoya uchun guruhga .apk tashlashni srazi taqiqlaymiz, xavf ballini esa VT natijasiga ko'ra belgilaymiz.
                final_risk = risk_score if is_malicious else 80
                final_details = virus_details if is_malicious else "Guruh siyosatiga ko'ra taqiqlangan shubhali unverified APK fayl."
                
                # 4. Bazaga yozish
                log_threat_to_db(
                    chat_id=message.chat.id,
                    chat_title=chat_title,
                    username=username,
                    threat_type="APK",
                    risk_score=final_risk,
                    details=final_details,
                    payload_raw=sha256_hash
                )
                
                # 5. O'chirish va ogohlantirish
                await message.delete()
                
                status_icon = "🔴" if is_malicious else "⚠️"
                warning_msg = (
                    f"🛡️ **UzPhishGuard Global Malware Engine**\n\n"
                    f"{status_icon} Foydalanuvchi {username} guruhga zararli dastur yuklamoqchi bo'ldi!\n"
                    f"📦 **Fayl nomi:** {message.document.file_name}\n"
                    f"📈 **Xavf indeksi:** {final_risk}%\n"
                    f"🔍 **Tahlil:** {final_details}\n"
                    f"🔒 *Guruh a'zolarini troyan kiber-hujumlaridan himoya qilish uchun ushbu fayl tizim tomonidan yo'q qilindi!*"
                )
                sent_msg = await message.answer(warning_msg)
                await asyncio.sleep(15)
                await sent_msg.delete()
                
            except Exception as e:
                logger.error(f"APK global tahlilida xatolik: {e}")

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

async def main():
    logger.info("⚡ Supabase arxitekturasi tekshirilmoqda...")
    init_db()
    logger.info("🛡️ UzPhishGuard Enterprise Core v2.0 faollashtirildi.")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
