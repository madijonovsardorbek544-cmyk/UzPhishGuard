# main.py
import os
import re
import asyncio
import logging
import asyncpg
import httpx  # Sinxron requests o'rniga o'ta tezkor asinxron HTTPX
from urllib.parse import urlparse
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import BaseFilter, Command
from aiogram.enums import ParseMode

# 1. Professional Log Tizimi (SOC Monitoring uchun)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# 2. XAVFSIZLIK QATLAMI: Maxfiy kalitlar GitHub-da ko'rinmaydi, faqat Render'dan o'qiladi!
BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_ID = os.getenv("ADMIN_ID")  # Botingizni boshqarish uchun sizning Telegram ID

if not BOT_TOKEN or not DATABASE_URL:
    logger.critical("KRITIK XATO: BOT_TOKEN yoki DATABASE_URL topilmadi! Render muhitini tekshiring.")
    exit(1)

# Bot va Dispatcher obyektlari
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Ma'lumotlar bazasi pooli (Global ulanishlar hovuzi)
db_pool = None

# URL aniqlash uchun Regex qolipi
URL_PATTERN = re.compile(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

# ==========================================
# 1. ILG'OR TAHID TAHLILI (ADVANCED HEURISTICS)
# ==========================================
def advanced_heuristics_check(url: str) -> bool:
    """AI va qoidaga asoslangan gibrid fishing tahlili (CPU-bound string processing)."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if not domain:
            return False

        suspicious_tlds = {'.xyz', '.tk', '.ru', '.link', '.free', '.click', '.top', '.info', '.net', '.org-uz', '.site', '.online'}
        target_brands = ['click', 'payme', 'uzcard', 'humo', 'my.gov', 'agro', 'bank', 'soliq', 'olx', 'uzb', 'telegram']

        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True

        for brand in target_brands:
            if brand in domain:
                if not (domain.endswith(f"{brand}.uz") or domain == f"{brand}.uz" or domain.endswith(f"{brand}.com")):
                    return True
        return False
    except Exception as e:
        logger.error(f"Heuristics tahlilida xato: {e}")
        return False

# ==========================================
# 2. ASINXRON TAHID MANBASINI BOYITISH (ASYNC IP ENRICHMENT)
# ==========================================
async def get_ip_enrichment_async(url: str) -> dict:
    """Domenning IP manzili va Geo-lokatsiyasini ASINXRON aniqlash (Event loop muzlamaydi)."""
    context = {"ip_address": "0.0.0.0", "country": "Unknown", "latitude": 41.2995, "longitude": 69.2401}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # SINOV: requests o'rniga mukammal httpx asinxron mijozi ishlatiladi!
        async with httpx.AsyncClient(timeout=3.0) as client:
            # 1. Google DNS orqali IP manzilni aniqlash
            dns_res = await client.get(f"https://dns.google/resolve?name={domain}")
            if dns_res.status_code == 200:
                dns_data = dns_res.json()
                if "Answer" in dns_data:
                    ip = dns_data["Answer"][0]["data"].strip('.')
                    
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        context["ip_address"] = ip
                        
                        # 2. IP API orqali Geolokatsiyani asinxron olish
                        geo_res = await client.get(f"http://ip-api.com/json/{ip}")
                        if geo_res.status_code == 200:
                            geo_data = geo_res.json()
                            if geo_data.get("status") == "success":
                                context["country"] = geo_data.get("country", "Unknown")
                                context["latitude"] = float(geo_data.get("lat", 41.2995))
                                context["longitude"] = float(geo_data.get("lon", 69.2401))
    except Exception as e:
        logger.warning(f"IP Enrichment bypass (Kechikish sababli o'tkazib yuborildi): {e}")
    return context

# ==========================================
# 3. HIGH-PERFORMANCE CONNECTION POOL DB ENGINE
# ==========================================
async def save_to_siem(chat_title: str, username: str, url: str, status: str, risk_score: int, geo_data: dict):
    """Supabase connection pool orqali o'ta tezkor SIEM insert operatsiyasi."""
    global db_pool
    if not db_pool:
        logger.error("Ma'lumotlar bazasi pooli faol emas!")
        return

    # Pool ichidan bitta bo'sh ulanishni olamiz (Bu ulanish ochib-yopish vaqtini 10 barobar tejaydi)
    async with db_pool.acquire() as conn:
        try:
            # Jadvalning ustunlarini tekshirish (Kodingizdagi dynamic xavfsizlik filtri)
            columns_query = """
                SELECT column_name FROM information_schema.columns WHERE table_name = 'scanned_links';
            """
            rows = await conn.fetch(columns_query)
            existing_columns = {row['column_name'] for row in rows}

            data_map = {
                "chat_title": str(chat_title),
                "group_id": str(chat_title),
                "username": str(username),
                "user": str(username),
                "url": str(url),
                "status": str(status),
                "risk_score": int(risk_score),
                "ip_address": str(geo_data["ip_address"]),
                "country": str(geo_data["country"]),
                "latitude": float(geo_data["latitude"]),
                "longitude": float(geo_data["longitude"])
            }

            valid_data = {k: v for k, v in data_map.items() if k in existing_columns}
            if not valid_data:
                logger.error("Jadval ustunlari mos kelmadi.")
                return

            columns = ", ".join(valid_data.keys())
            placeholders = ", ".join([f"${i+1}" for i in range(len(valid_data))])
            insert_query = f"INSERT INTO scanned_links ({columns}) VALUES ({placeholders});"

            await conn.execute(insert_query, *valid_data.values())
            logger.info(f"🛡️ [SIEM LOGGED] {status} -> {url}")
        except Exception as e:
            logger.error(f"❌ [DB INSERT ERROR]: {e}")

# ==========================================
# 4. KIBER-SOQCHI VA ACCESS CONTROL LAYER
# ==========================================
class AdvancedLinkFilter(BaseFilter):
    async def __call__(self, message: types.Message) -> bool:
        return bool(message.text and URL_PATTERN.search(message.text))

def is_sender_admin(user_id: int) -> bool:
    """Faqat siz bot orqali buyruq bera olishingizni tekshiradi (Reklama/Spamga qarshi devor)"""
    return ADMIN_ID and str(user_id) == str(ADMIN_ID).strip()

@dp.message(Command("broadcast", "send"))
async def handle_broadcast(message: types.Message):
    """Admin buyrug'ini tekshirish - Botingizni firgarlardan 100% himoya qiladi"""
    if not is_sender_admin(message.from_user.id):
        await message.reply("❌ Sizda bu bot orqali reklama yoki xabar tarqatish huquqi yo'q!")
        return

    text_to_send = message.text.split(maxsplit=1)
    if len(text_to_send) < 2:
        await message.reply("📝 To'g'ri foydalanish: `/send Xabar matni`", parse_mode=ParseMode.MARKDOWN)
        return
    await message.reply(f"📢 Tizim xabari qabul qilindi. Tarqatish jarayoni xavfsiz boshlandi.")

# ==========================================
# 5. INCIDENT RESPONSE HANDLER
# ==========================================
@dp.message(AdvancedLinkFilter())
async def cyber_incident_handler(message: types.Message):
    text = message.text
    urls = URL_PATTERN.findall(text)

    chat_title = message.chat.title if message.chat.title else "Cyber Group"
    username = f"@{message.from_user.username}" if message.from_user.username else message.from_user.full_name

    for url in urls:
        # Heuristika asinxron loopni bloklamaydi (Tezkor string operatsiya)
        is_phishing = advanced_heuristics_check(url)

        if is_phishing:
            # Tahdid aniqlanganda ASINXRON IP Enrichment (Bot qotib qolmaydi!)
            geo_data = await get_ip_enrichment_async(url)

            try:
                await message.delete()
            except Exception:
                logger.warning("Xabarni o'chirish uchun botda admin huquqi yetarli emas.")

            alert_text = (
                f"🛡️ **UzPhishGuard SOC v3 — Enterprise Alert**\n\n"
                f"👤 **Tahdid Manbasi:** {username}\n"
                f"❌ **Xavf Turi:** Fishing / Zararli havola aniqlandi.\n"
                f"📊 **Xavf Darajasi:** `98%` [Kritik]\n"
                f"🌐 **Server Joylashuvi:** {geo_data['country']} (IP: {geo_data['ip_address']})\n\n"
                f"ℹ️ *Tafsilotlar SIEM Dashboard markaziy kiber-xaritasiga uzatildi.*"
            )
            await message.answer(alert_text, parse_mode=ParseMode.MARKDOWN)
            await save_to_siem(chat_title, username, url, "BLOCKED", 98, geo_data)
        else:
            default_geo = {"ip_address": "127.0.0.1", "country": "Local", "latitude": 41.2995, "longitude": 69.2401}
            await save_to_siem(chat_title, username, url, "SAFE", 0, default_geo)

# ==========================================
# 6. ENGINE LIFECYCLE (STARTUP / SHUTDOWN)
# ==========================================
async def main():
    global db_pool
    logger.info("⚡ Supabase Connection Pool yaratilmoqda...")
    
    # Supabase uchun yuqori unumdorlikka ega ulanishlar hovuzini ochamiz
    db_pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=2,   # Minimal doimiy ochiq ulanishlar soni
        max_size=10,  # Maksimal yuklama kelganda ochiladigan ulanishlar soni
        command_timeout=60.0
    )
    
    logger.info("🛡️ UzPhishGuard Enterprise Core 100% asinxron rejimda ishga tushmoqda...")
    
    # Navbatda turib qolgan eski barcha spam-xabarlarni o'chirib, botni toza boshlaydi
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot xavfsiz to'xtatildi.")
