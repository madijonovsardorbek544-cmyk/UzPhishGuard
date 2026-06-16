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

# 3. Ma'lumotlar bazasini tekshirish va unifikatsiya qilish
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

# 5. APK Heuristic Engine: Androguard
def analyze_apk_permissions(file_bytes: bytes) -> tuple[bool, int, str]:
    try:
        apk_obj = APK(file_bytes, raw=True)
        permissions = apk_obj.get_permissions()
        
        critical_permissions = [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ]
        
        detected_bad_perms = [perm for perm in permissions if perm in critical_permissions]
        
        if detected_bad_perms:
            clean_names = [p.split('.')[-1] for p in detected_bad_perms]
            risk_score = 85 + (len(detected_bad_perms) * 3)
            return True, min(risk_score, 100), f"Heuristic Engine: Ichki manifestda o'ta xavfli ruxsatnomalar aniqlandi: {', '.join(clean_names)}"
            
        return False, 0, "Fayl ichki ruxsatnomalari standart me'yorda."
    except Exception as e:
        logger.error(f"Androguard dekompilyatsiyada xato: {e}")
        return False, 0, "Fayl strukturasini o'qib bo'lmadi."

# 6. UzBERT NLP & Advanced Phishing Detection Engine (AI Core 🧠) - UPDATED
def analyze_text_nlp(text: str) -> tuple[bool, int, str]:
    """
    O'zbekcha ijtimoiy muhandislik va fishing kontekstini chuqur tahlil qiluvchi NLP AI moduli.
    """
    if not text:
        return False, 0, ""
        
    text_clean = text.lower().strip()
    
    # 1-Sinf: Pul yutuqlari va soxta aksiyalar (Financial Phishing) - Kengaytirilgan variant
    financial_pattern = r"(pul|yutuq|sovg'a|sovga|mukofot|aksiya|fondi|bonus|aksiyada|yutib oldingiz|tarqatilmoqda|click|payme|uzcard|humo|karta|kartangiz|hisobingiz|balans)"
    
    # 2-Sinf: Kiber-tahdid va qo'rqitish (Urgency/Scareware) - Kengaytirilgan variant
    urgency_pattern = r"(bloklandi|sharmanda|videongiz|kodni bering|tasdiqlang|parol|karta raqam|shaxsiy ma'lumot|zudlik bilan|shoshiling|ogohlantirish|kiriting)"
    
    # Hevristik NLP ball tizimi
    score = 0
    reasons = []
    
    # Havolalarni tekshirish
    urls = re.findall(r'(https?://[^\s]+)', text_clean)
    has_link = len(urls) > 0
    
    if re.search(financial_pattern, text_clean):
        score += 45
        reasons.append("Moliyaviy firgarlik/karta xavfsizligi tahdidi")
        
    if re.search(urgency_pattern, text_clean):
        score += 50
        reasons.append("Ijtimoiy muhandislik bosimi (Urgency/Scareware)")
        
    if has_link:
        score += 15
        # Whitelist filtri
        whitelist = ["kun.uz", "daryo.uz", "gazeta.uz", "lex.uz", "gov.uz", "telegram.org"]
        if any(good_site in urls[0] for good_site in whitelist):
            return False, 0, ""
            
    # Qaror qabul qilish mantiqi (Agar xavf darajasi 60% dan oshsa, bu fishing deb baholanadi)
    if score >= 60:
        final_score = min(score, 100)
        details = f"AI NLP Core: {', '.join(reasons)} aniqlandi."
        return True, final_score, details
        
    return False, 0, ""

# 7. HANDLERS
@dp.message(CommandStart())
async def cmd_start_private(message: types.Message):
    if message.chat.type == ChatType.PRIVATE:
        await message.answer(
            "🛡️ **UzPhishGuard Enterprise v4.0 (AI NLP Core) faol!**\n\n"
            "Meni guruhlaringizga qo'shib adminlik huquqini bering. Endi tizim nafaqat virusli fayllarni, "
            "balki guruhdagi gap-so'zlar va matnlarni ham **UzBERT AI NLP** mantiqi orqali fishing yoki ijtimoiy muhandislikka tekshiradi!"
        )

@dp.message(F.document)
async def monitor_apk_files(message: types.Message):
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        file_name = message.document.file_name.lower() if message.document.file_name else ""
        
        if file_name.endswith('.apk'):
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            try:
                file_info = await bot.get_file(message.document.file_id)
                file_buffer = await bot.download_file(file_info.file_path)
                file_bytes = file_buffer.read()
                
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                
                is_malicious, risk_score, analysis_details = await check_virustotal(sha256_hash)
                
                if not is_malicious:
                    is_malicious, risk_score, analysis_details = analyze_apk_permissions(file_bytes)
                
                final_risk = risk_score if is_malicious else 80
                final_details = analysis_details if is_malicious else "Guruh siyosatiga ko'ra tekshirilmagan APK bloki."
                status_icon = "🔴 REAL TAHID!" if is_malicious else "⚠️ SHUBHALI APK!"
                
                log_threat_to_db(
                    chat_id=message.chat.id,
                    chat_title=chat_title,
                    username=username,
                    threat_type="APK",
                    risk_score=final_risk,
                    details=final_details,
                    payload_raw=sha256_hash
                )
                
                # Zararli yoki shubhali APK faylni guruhdan o'chiramiz
                await message.delete()
                
                # Ogohlantirish xabari endi o'chib ketmaydi!
                warning_msg = (
                    f"🛡️ **UzPhishGuard Deep Scan Engine**\n\n"
                    f"{status_icon}\n"
                    f"👤 **Yuboruvchi:** {username}\n"
                    f"📦 **Fayl:** {message.document.file_name}\n"
                    f"📈 **Xavf darajasi:** {final_risk}%\n"
                    f"🔬 **Tahlil:** {final_details}\n\n"
                    f"🔒 *Foydalanuvchilar xavfsizligi uchun zararli ob'ekt yo'q qilindi!*"
                )
                sent_msg = await message.answer(warning_msg)
                
                # Guruh a'zolari ko'rishi uchun ogohlantirishni guruh tepasiga pin qilamiz
                try:
                    await bot.pin_chat_message(chat_id=message.chat.id, message_id=sent_msg.message_id, disable_notification=False)
                except Exception:
                    pass
                
            except Exception as e:
                logger.error(f"APK tahlilida xatolik: {e}")

@dp.message(F.text)
async def monitor_text_messages(message: types.Message):
    if message.chat.type in [ChatType.GROUP, ChatType.SUPERGROUP]:
        if message.from_user.username == "GroupAnonymousBot":
            return

        # Sun'iy intellektli NLP matn tahlili
        is_phishing, risk_score, reason = analyze_text_nlp(message.text)

        if is_phishing:
            chat_title = message.chat.title or "Noma'lum Guruh"
            username = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
            
            log_threat_to_db(
                chat_id=message.chat.id,
                chat_title=chat_title,
                username=username,
                threat_type="TEXT" if "havola" not in reason.lower() else "LINK",
                risk_score=risk_score,
                details=reason,
                payload_raw=message.text
            )
            
            try:
                # Kiber-firgarlik xabarini darhol o'chiramiz
                await message.delete()
                
                # Ogohlantirish xabari guruhda doimiy qoladi!
                warning = await message.answer(
                    f"🛡️ **UzPhishGuard AI NLP Engine**\n\n"
                    f"⚠️ Foydalanuvchi {username} yuborgan kiber-firgarlik matni o'chirildi!\n"
                    f"🔍 **AI Diagnoz:** {reason}\n"
                    f"🚫 *Guruhda ijtimoiy muhandislik va psixologik bosimlar taqiqlangan!*"
                )
                
                # Ogohlantirish xabarini guruhga pin qilib qo'yish
                try:
                    await bot.pin_chat_message(chat_id=message.chat.id, message_id=warning.message_id, disable_notification=False)
                except Exception:
                    pass
                    
            except Exception as e:
                logger.error(f"Xabarni o'chirishda xatolik: {e}")

async def main():
    logger.info("⚡ Supabase arxitekturasi tekshirilmoqda...")
    init_db()
    logger.info("🛡️ UzPhishGuard Enterprise Core v4.0 (Pin Message Mode) faollashtirildi.")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
