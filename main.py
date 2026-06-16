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

# Androguard ichki tahlil modullari
from androguard.core.apk import APK

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
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not BOT_TOKEN:
    logger.critical("XATO: BOT_TOKEN topilmadi!")
    exit(1)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# 3. Ma'lumotlar bazasini tekshirish
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

# 4. Global Threat Intel: VirusTotal API
async def check_virustotal(file_hash: str) -> tuple[bool, int, str]:
    if not VIRUSTOTAL_API_KEY:
        return False, 0, "VirusTotal API kaliti sozlanmagan."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    undetected_count = stats.get('undetected', 0)
                    
                    if malicious_count >= 2:
                        risk_score = int((malicious_count / (malicious_count + undetected_count + 1)) * 100)
                        risk_score = min(max(risk_score, 75), 100)
                        results = data['data']['attributes']['last_analysis_results']
                        virus_name = "Zararli dastur (Malware)"
                        for engine, res in results.items():
                            if res.get('result'):
                                virus_name = res['result']
                                break
                        return True, risk_score, f"Global Antivirus: {virus_name} ({malicious_count} ta deteksiya)"
                return False, 0, ""
        except Exception as e:
            logger.error(f"VirusTotal API xatosi: {e}")
            return False, 0, ""

# 5. APK Heuristic Engine: Androguard Dekompilyatsiya Tizimi
def analyze_apk_permissions(file_bytes: bytes) -> tuple[bool, int, str]:
    """
    APK faylni dekompilyatsiya qilib, uning ichki ruxsatnomalarini (Manifest) tahlil qiladi.
    """
    try:
        # Faylni xotiraning o'zida asinxron ochamiz
        apk_obj = APK(file_bytes, raw=True)
        permissions = apk_obj.get_permissions()
        
        # O'zbekistondagi eng xavfli bank troyanlari foydalanadigan ruxsatnomalar ro'yxati
        critical_permissions = [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE" # Ekran boshqaruvi (Eng xavflisi)
        ]
        
        detected_bad_perms = [perm for perm in permissions if perm in critical_permissions]
        
        if detected_bad_perms:
            clean_names = [p.split('.')[-1] for p in detected_bad_perms]
            risk_score = 85 + (len(detected_bad_perms) * 3)
            risk_score = min(risk_score, 100)
            return True, risk_score, f"Heuristic Engine: Ichki manifestda o'ta xavfli ruxsatnomalar aniqlandi: {', '.join(clean_names)}"
            
        return False, 0, "Fayl ichki ruxsatnomalari standart me'yorda."
    except Exception as e:
        logger.error(f"Androguard dekompilyatsiyada xato: {e}")
        return False, 0, "Fayl strukturasini o'qib bo'lmadi."

# 6. Fishing havolalarini aniqlash
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

# 7. HANDLERS
@dp.message(CommandStart())
async def cmd_start_private(message: types.Message):
    if message.chat.type == ChatType.PRIVATE:
        await message.answer(
            "🛡️ **UzPhishGuard Enterprise v3.0 (Heuristic Core) faol!**\n\n"
            "Meni guruhlarga qo'shing. Endi men kelgan har bir yangi `.apk` faylni "
            "**Androguard Reverse Engineering** yordamida ichini ochib, maxfiy virus mantiqlarini ham dekompilyatsiya qila olaman!"
        )

@dp.message(F.document)
async def monitor_apk_files(message: types.Message):
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        file_name = message.document.file_name.lower() if message.document.file_name else ""
        
        if file_name.endswith('.apk'):
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            try:
                # 1. Faylni RAMga yuklash
                file_info = await bot.get_file(message.document.file_id)
                file_buffer = await bot.download_file(file_info.file_path)
                file_bytes = file_buffer.read()
                
                # 2. Xesh hisoblash
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                
                # 3. 1-Bosqich: Global Antivirus Skanerlash (VirusTotal)
                is_malicious, risk_score, analysis_details = await check_virustotal(sha256_hash)
                
                # 4. 2-Bosqich: Agar global bazada topilmasa, Ichki Dekompilyatsiya (Androguard Heuristics)
                if not is_malicious:
                    is_malicious, risk_score, analysis_details = analyze_apk_permissions(file_bytes)
                
                # Yakuniy qaror va kiber-statistika
                final_risk = risk_score if is_malicious else 80
                final_details = analysis_details if is_malicious else "Guruh xavfsizlik siyosatiga ko'ra tekshirilmagan APK taqiqlandi."
                status_icon = "🔴 REAL TAHID!" if is_malicious and "Heuristic" in final_details or "Global" in final_details else "⚠️ SHUBHALI!"
                
                # 5. Bazaga hisobot yozish
                log_threat_to_db(
                    chat_id=message.chat.id,
                    chat_title=chat_title,
                    username=username,
                    threat_type="APK",
                    risk_score=final_risk,
                    details=final_details,
                    payload_raw=sha256_hash
                )
                
                # 6. Guruhdan faylni yo'q qilish
                await message.delete()
                
                warning_msg = (
                    f"🛡️ **UzPhishGuard v3.0 Deep Scan Engine**\n\n"
                    f"{status_icon}\n"
                    f"👤 **Yuboruvchi:** {username}\n"
                    f"📦 **Fayl:** {message.document.file_name}\n"
                    f"📈 **Xavf darajasi:** {final_risk}%\n"
                    f"🔬 **Tahlil natijasi:** {final_details}\n\n"
                    f"🔒 *Guruh a'zolarini kiber-troyan va josus dasturlardan himoya qilish uchun ob'ekt yo'q qilindi!*"
                )
                sent_msg = await message.answer(warning_msg)
                await asyncio.sleep(15)
                await sent_msg.delete()
                
            except Exception as e:
                logger.error(f"Deep Scan jarayonida xatolik: {e}")

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
    logger.info("🛡️ UzPhishGuard Enterprise Core v3.0 (Heuristic Mode) faollashtirildi.")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
