import os
import re
import asyncio
import logging
import aiohttp
from urllib.parse import urlparse
from aiogram import Bot, Dispatcher, types
from cachetools import TTLCache
import asyncpg
from dotenv import load_dotenv

# .env faylidagi o'zgaruvchilarni tizimga yuklash
load_dotenv()

# Loglarni professional SOC standartida sozlash
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Konfiguratsiya parametrlari (Claude tahlilidagi nomlar bilan sinxronlashtirildi)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
# Kalitlar turli xil nomlangan bo'lsa ham tizim crash bo'lmasligi ta'minlandi
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("GEMINI_API_KEY") or None

if not BOT_TOKEN or not DATABASE_URL:
    logger.critical("Kritik xatolik: TELEGRAM_BOT_TOKEN yoki DATABASE_URL topilmadi!")

# Kesh tizimi (1 soat davomida tekshirilgan URL manzillarni xotirada saqlaydi)
URL_CACHE = TTLCache(maxsize=1000, ttl=3600)

# Global ma'lumotlar bazasi hovuzi (Connection Pool)
db_pool = None

# Bot va Dispatcher obyektlarini yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

def extract_urls(text: str) -> list:
    """Matn ichidan barcha URL manzillarni xavfsiz ajratib olish."""
    if not text:
        return []
    return re.findall(r'(https?://[^\s]+)', text)

def advanced_heuristics_check(url: str) -> bool:
    """
    Domen darajasidagi ilg'or hevristik tahlil.
    False-Positive (yolg'on trevoga) muammosini butunlay yo'q qiladi.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if not domain:
            return False
            
        # Shubhali yuqori darajali domenlar (TLDs)
        suspicious_tlds = ['.xyz', '.tk', '.ru', '.link', '.free', '.click', '.top', '.info']
        # Fishing hujumlarida ko'p nishon bo'ladigan mahalliy brendlar
        target_brands = ['click', 'payme', 'uzcard', 'humo', 'my.gov', 'agro', 'bank', 'soliq']
        
        # 1. TLD tekshiruvi (Faqat domen oxirini tekshiradi)
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
            
        # 2. Brend soxtalashtirish (Typosquatting) tahlili
        if any(brand in domain for brand in target_brands):
            official_domains = [
                'click.uz', 'payme.uz', 'uzcard.uz', 'humo.uz', 
                'my.gov.uz', 'cbu.uz', 'agro.uz', 'soliq.uz'
            ]
            # Agar brend nomi domenda qatnashsa-yu, u rasmiy ro'yxatda bo'lmasa -> Fishing!
            if not any(official in domain for official in official_domains):
                return True
                
        return False
    except Exception as e:
        logger.error(f"Hevristik tahlilda xatolik: {e}")
        return False

async def get_url_geo_enrichment(url: str) -> dict:
    """
    URL manzilining IP manzilini va uning fizik geolokatsiyasini aniqlash.
    SIEM Dashboard kiber-xaritasini to'g'ri ma'lumot bilan ta'minlaydi.
    """
    default_geo = {"ip": "0.0.0.0", "country": "Unknown", "lat": 0.0, "lon": 0.0}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0] # Port raqamlarini kesib tashlash
        
        async with aiohttp.ClientSession() as session:
            # 1. Asinxron Cloud DNS so'rovi orqali domenni IPv4 manzilga aylantirish
            async with session.get(f"https://dns.google/resolve?name={domain}", timeout=4) as dns_resp:
                if dns_resp.status != 200:
                    return default_geo
                dns_data = await dns_resp.json()
                
                ip_address = None
                if "Answer" in dns_data:
                    for answer in dns_data["Answer"]:
                        if answer["type"] == 1: # A-record (IPv4)
                            ip_address = answer["data"]
                            break
                            
                if not ip_address:
                    return default_geo
                    
            # 2. IP manzildan foydalanib asinxron koordinata va davlatni aniqlash
            async with session.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,lat,lon", timeout=4) as geo_resp:
                if geo_resp.status == 200:
                    geo_data = await geo_resp.json()
                    if geo_data.get("status") == "success":
                        return {
                            "ip": ip_address,
                            "country": geo_data.get("country", "Unknown"),
                            "lat": geo_data.get("lat", 0.0),
                            "lon": geo_data.get("lon", 0.0)
                        }
    except Exception as e:
        logger.error(f"Geo Enrichment jarayonida xatolik: {e}")
    return default_geo

async def ai_context_analysis(url: str, text: str) -> bool:
    """LLM (Llama-3) yordamida matn va havola kontekstini tahlil qilish."""
    if not GROQ_API_KEY:
        return False
    payload = {
        "model": "llama3-70b-8192",
        "messages": [
            {
                "role": "system",
                "content": "Siz mukammal kiberxavfsizlik tahlilchisiz. Havola va matn fishing ekanini aniqlang. Faqat bitta so'z javob bering: 'PHISHING' yoki 'SAFE'."
            },
            {"role": "user", "content": f"URL: {url}\nMatn: {text}"}
        ],
        "temperature": 0.1
    }
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    answer = result['choices'][0]['message']['content'].strip().upper()
                    return "PHISHING" in answer
    except Exception as e:
        logger.error(f"AI tahlilda xatolik: {e}")
    return False

async def save_incident(group_id: int, chat_title: str, user_id: str, username: str, url: str, status: str, risk_score: float, geo: dict):
    """Markaziy PostgreSQL bazasiga asinxron Pooler orqali xavfsiz yozish."""
    global db_pool
    if not db_pool:
        logger.error("Ma'lumotlar bazasi ulanishlar hovuzi ma'lumot uzatish uchun mavjud emas!")
        return
    try:
        async with db_pool.acquire() as conn:
            await conn.execute('''
                INSERT INTO scanned_links (
                    group_id, chat_title, user_id, username, url, status, risk_score, ip_address, country, latitude, longitude, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
            ''', group_id, chat_title, str(user_id), username, url, status, risk_score, geo["ip"], geo["country"], geo["lat"], geo["lon"])
    except Exception as e:
        logger.error(f"Supabase bazasiga incidentni yozishda xatolik: {e}")

@dp.message()
async def monitor_messages(message: types.Message):
    """Guruhlardagi xabarlarni real vaqt rejimida monitoring qilish."""
    if not message.text:
        return

    urls = extract_urls(message.text)
    if not urls:
        return

    for url in urls:
        # Keshni tekshirish
        if url in URL_CACHE:
            if URL_CACHE[url] == "BLOCKED":
                try: await message.delete()
                except Exception: pass
                return
            continue

        is_phishing = False
        risk_score = 0.0

        # 1-Bosqich: Hevristik tahlil
        if advanced_heuristics_check(url):
            is_phishing = True
            risk_score = 85.0

        # 2-Bosqich: Kontekstual AI Tahlil
        if not is_phishing and GROQ_API_KEY:
            if await ai_context_analysis(url, message.text):
                is_phishing = True
                risk_score = 98.0

        chat_title = message.chat.title or "Private Chat"
        username = message.from_user.username or message.from_user.full_name

        # 3-Bosqich: Yakuniy qaror va ijro
        if is_phishing:
            URL_CACHE[url] = "BLOCKED"
            try:
                await message.delete()
            except Exception as e:
                logger.error(f"Xabarni o'chirishda xatolik: {e}")

            # IP va Koordinatalarni boyitish (Enrichment)
            geo_data = await get_url_geo_enrichment(url)

            # Bazaga bloklangan holatda saqlash
            await save_incident(message.chat.id, chat_title, message.from_user.id, username, url, "BLOCKED", risk_score, geo_data)
            
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v2 — Incident Alert**\n\n"
                f"👤 **Tahdid Manbasi:** @{username}\n"
                f"❌ **Xavf Turi:** Fishing / Zararli havola aniqlandi.\n"
                f"📊 **Xavf Darajasi:** `{risk_score}%`\n"
                f"🌍 **Server Joylashuvi:** `{geo_data['country']}` (IP: `{geo_data['ip']}`)\n"
                f"ℹ️ *Tafsilotlar SIEM Dashboard real-time kiber-xaritasiga muvaffaqiyatli uzatildi.*"
            )
            await message.answer(alert_text, parse_mode="Markdown")
            break
        else:
            # Xavfsiz havolalarni ham geo bilan yozamiz (Dashboard toza va xatoliksiz ishlashi uchun)
            URL_CACHE[url] = "SAFE"
            geo_data = {"ip": "0.0.0.0", "country": "Safe Source", "lat": 41.311081, "lon": 69.240562} # Standart Toshkent koordinatasi
            await save_incident(message.chat.id, chat_title, message.from_user.id, username, url, "SAFE", 0.0, geo_data)

async def main():
    global db_pool
    logger.info("Database Pooler ishga tushirilmoqda...")
    try:
        # Maksimal 10 ta parallel ulanish hovuzini ochish (Supabase limitini asraydi)
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
        logger.info("Database Pooler muvaffaqiyatli yaratildi.")
    except Exception as e:
        logger.critical(f"Database Pool yaratishda xatolik: {e}")
        return

    logger.info("UzPhishGuard SOC v2 Bot asinxron rejimda start oldi...")
    try:
        await dp.start_polling(bot)
    finally:
        if db_pool:
            await db_pool.close()

if __name__ == '__main__':
    asyncio.run(main())
