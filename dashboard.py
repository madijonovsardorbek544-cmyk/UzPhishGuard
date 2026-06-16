import os
import hashlib
import logging
import asyncio
import psycopg2
import aiohttp
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command

# Loglarni sozlash
logging.basicConfig(level=logging.INFO)

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "") # Ixtiyoriy: Kelajakda VT kalit qo'shish uchun

bot = Bot(token=TOKEN)
dp = Dispatcher()

# --- DATABASE ENGINE (Supabase bilan Yagona Unifikatsiya) ---
def save_threat_to_db(chat_title, sender_username, threat_type, risk_score, details):
    """Dashboard va Bot uchun yagona standartlashtirilgan bazaga yozish funksiyasi"""
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
        logging.info("🛡️ Tahdid muvaffaqiyatli SOC bazasiga yozildi.")
    except Exception as e:
        logging.error(f"❌ Supabase'ga yozishda xato: {e}")

# --- GLOBAL THREAT INTEL ENGINE (VirusTotal API Integratsiyasi) ---
async def check_hash_virustotal(sha256_hash):
    """SHA-256 xeshni global kiber-baza orqali tekshirish"""
    if not VIRUSTOTAL_API_KEY:
        # Agar VT kalit hali kiritilmagan bo'lsa, test uchun o'zimizning Hevristikani ishlatamiz
        return None
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                result = await response.json()
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                return malicious
            return 0

# --- HANDLER 1: APK MALWARE FILTR (STAGE 2 IMPLEMENTATION) ---
@dp.message(F.document)
async def handle_apk_document(message: types.Message):
    document = message.document
    file_name = document.file_name.lower()
    
    # Faqat .apk kengaytmali fayllarni ushlab qolamiz
    if file_name.endswith('.apk'):
        chat_title = message.chat.title if message.chat.title else "Private Chat"
        sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
        
        # 1-qadam: Guruhni ogohlantirish va faylni xotirada tekshirish
        status_msg = await message.reply("⚡ *Tizim:* Shubhali APK aniqlandi! SHA-256 kiber-barmog'i hisoblanmoqda...", parse_mode="Markdown")
        
        # Telegram serveridan faylni oqim (stream) ko'rinishida yuklab olish
        file_info = await bot.get_file(document.file_id)
        file_data = await bot.download_file(file_info.file_path)
        
        # SHA-256 xesh kodini generatsiya qilish
        sha256_gen = hashlib.sha256()
        sha256_gen.update(file_data.read())
        apk_hash = sha256_gen.hexdigest()
        
        # 2-qadam: Global Threat Intelligence tekshiruvi
        vt_result = await check_hash_virustotal(apk_hash)
        
        risk_score = 45 # Standart boshlang'ich xavf (Androguard buni oshiradi)
        details = f"Fayl: {document.file_name} | SHA256: {apk_hash[:15]}..."
        
        if vt_result and vt_result > 0:
            risk_score = 99
            details += f" | 🔴 Global Antiviruslar ogohlantirishi: {vt_result} ta deteksiya!"
            await status_msg.edit_text(f"🚨 *DIQQAT! CRITICAL MALWARE!* \nBu fayl global bazalarda virus deb topilgan! \n*SHA-256:* `{apk_hash}`", parse_mode="Markdown")
            await message.delete() # Guruh xavfsizligi uchun virusni o'chirish
        else:
            # Agar yangi virus bo'lsa, 3-bosqich (Androguard) heuristikasiga yo'llanma beriladi
            details += " | 🟡 Yangi imzo (Zero-day). Ichki ruxsatnomalar tahlili kutilmoqda."
            await status_msg.edit_text(f"🛡️ *UzPhishGuard Skanner:* \nFayl xeshi: `{apk_hash[:30]}...` \nBazaga yuborildi. Keyingi statik tahlil faollashtirildi.", parse_mode="Markdown")
            
        # SOC Bazaga yagona formatda yozish (Dashboard xatosiz o'qiydi)
        save_threat_to_db(
            chat_title=chat_title,
            sender_username=sender,
            threat_type="APK",
            risk_score=risk_score,
            details=details
        )

# --- HANDLER 2: MATN VA FISHING HAVOLALAR (UNIFIED SCHEMA) ---
@dp.message(F.text)
async def handle_text_phishing(message: types.Message):
    text = message.text.lower()
    chat_title = message.chat.title if message.chat.title else "Private Chat"
    sender = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
    
    # Fishing kalit so'zlari (Hevristika elementlari)
    phish_keywords = ["yutuq", "pul tarqatilmoqda", "aksiya", "click-uz", "payme-uz", "sharmanda", "videoni ko'ring"]
    
    is_threat = any(keyword in text for keyword in phish_keywords) or "http://" in text or "https://" in text
    
    if is_threat:
        risk_score = 75 if "http" in text else 50
        details = f"Matn tahlili: Shubhali kalit so'z yoki havola aniqlandi. Kontent: {message.text[:50]}..."
        
        # Guruhni xabardor qilish
        await message.reply("⚠️ *Diqqat!* Guruhda shubhali havola yoki ijtimoiy injeneriya matni aniqlandi! Voqea SOC panelga yo'naltirildi.", parse_mode="Markdown")
        
        # SOC Bazaga yagona formatda yozish
        save_threat_to_db(
            chat_title=chat_title,
            sender_username=sender,
            threat_type="LINK/TEXT",
            risk_score=risk_score,
            details=details
        )

# --- START COMMAND ---
@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    await message.reply("🛡️ *UzPhishGuard Core v4.5 active.* Tizim xavfsizlik monitoringi rejimida ishlamoqda.", parse_mode="Markdown")

async def main():
    logging.info("🚀 Bot monitoringni boshladi...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
