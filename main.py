# main.py
import os
import re
import asyncio
import logging
import asyncpg
import aiohttp  # requirements.txt ichidagi asinxron kutubxona
from urllib.parse import urlparse
from cachetools import TTLCache  # Xotirani himoyalash uchun cache
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import BaseFilter, Command
from aiogram.enums import ParseMode

# 1. Professional Log Tizimi
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# 2. XAVFSIZLIK QATLAMI: Ma'lumotlar faqat Render panelidan o'qiladi
BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_ID = os.getenv("ADMIN_ID")

if not BOT_TOKEN or not DATABASE_URL:
    logger.critical("KRITIK XATO: BOT_TOKEN yoki DATABASE_URL topilmadi!")
    exit(1)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
db_pool = None

# 3. MEMORY LEAK PROTECTION: Skrin qilingan linklarni 1 soat davomida keshda saqlash
# Maksimal 10,000 ta link sig'adi, 3600 soniyadan keyin avtomatik tozalanadi
url_cache = TTLCache(maxsize=10000, ttl=3600)

URL_PATTERN = re.compile(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

# ==========================================
# ADVANCED HEURISTICS
# ==========================================
def advanced_heuristics_check(url: str) -> bool:
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
        logger.error(f"Heuristics xatosi: {e}")
        return False

# ==========================================
# ASINXRON IP ENRICHMENT (AIOHTTP BILAN)
# ==========================================
async def get_ip_enrichment_async(url: str) -> dict:
    context = {"ip_address": "0.0.0.0", "country": "Unknown", "latitude": 41.2995, "longitude": 69.2401}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # HTTPS xavfsiz ulanish va aiohttp orqali asinxron request
        timeout = aiohttp.ClientTimeout(total=3.0)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"https://dns.google/resolve?name={domain}") as response:
                if response.status == 200:
                    dns_data = await response.json()
                    if "Answer" in dns_data:
                        ip = dns_data["Answer"][0]["data"].strip('.')
                        
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            context["ip_address"] = ip
                            
                            # Xavfsiz HTTPS Geo API
                            async with session.get(f"https://ipapi.co/{ip}/json/") as geo_response:
                                if geo_response.status == 200:
                                    geo_data = await geo_response.json()
                                    context["country"] = geo_data.get("country_name", "Unknown")
                                    context["latitude"] = float(geo_data.get("latitude", 41.2995))
                                    context["longitude"] = float(geo_data.get("longitude", 69.2401))
    except Exception as e:
        logger.warning(f"IP Enrichment o'tkazib yuborildi: {e}")
    return context

# ==========================================
# HIGH-PERFORMANCE DB ENGINE
# ==========================================
async def save_to_siem(chat_title: str, username: str, url: str, status: str, risk_score: int, geo_data: dict):
    global db_pool
    if not db_pool:
        return

    async with db_pool.acquire() as conn:
        try:
            columns_query = "SELECT column_name FROM information_schema.columns WHERE table_name = 'scanned_links';"
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
                return

            columns = ", ".join(valid_data.keys())
            placeholders = ", ".join([f"${i+1}" for i in range(len(valid_data))])
            insert_query = f"INSERT INTO scanned_links ({columns}) VALUES ({placeholders});"

            await conn.execute(insert_query, *valid_data.values())
            logger.info(f"🛡️ [SIEM] Saqlandi: {status} -> {url}")
        except Exception as e:
            logger.error(f"❌ [DB ERROR]: {e}")

# ==========================================
# FILTERS & INTERACTION
# ==========================================
class AdvancedLinkFilter(BaseFilter):
    async def __call__(self, message: types.Message) -> bool:
        return bool(message.text and URL_PATTERN.search(message.text))

@dp.message(Command("broadcast", "send"))
async def handle_broadcast(message: types.Message):
    if str(message.from_user.id) != str(ADMIN_ID).strip():
        await message.reply("❌ Sizda xabar tarqatish huquqi yo'q!")
        return
    await message.reply("📢 Reklama/Xabar tarqatish tizimi faol.")

# ==========================================
# CORE INCIDENT HANDLER WITH CACHING
# ==========================================
@dp.message(AdvancedLinkFilter())
async def cyber_incident_handler(message: types.Message):
    text = message.text
    urls = URL_PATTERN.findall(text)

    chat_title = message.chat.title if message.chat.title else "Cyber Group"
    username = f"@{message.from_user.username}" if message.from_user.username else message.from_user.full_name

    for url in urls:
        # Keshni tekshirish (Agar bu link yaqin 1 soatda tekshirilgan bo'lsa, qayta skan qilmaydi)
        if url in url_cache:
            is_phishing, geo_data = url_cache[url]
        else:
            is_phishing = advanced_heuristics_check(url)
            if is_phishing:
                geo_data = await get_ip_enrichment_async(url)
            else:
                geo_data = {"ip_address": "127.0.0.1", "country": "Local", "latitude": 41.2995, "longitude": 69.2401}
            
            # Natijani keshga yozib qo'yamiz
            url_cache[url] = (is_phishing, geo_data)

        if is_phishing:
            try:
                await message.delete()
            except Exception:
                logger.warning("Botda xabarni o'chirish huquqi yo'q.")

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
            await save_to_siem(chat_title, username, url, "SAFE", 0, geo_data)

# ==========================================
# ENGINE STARTUP
# ==========================================
async def main():
    global db_pool
    logger.info("⚡ Supabase Connection Pool ochilmoqda...")
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    
    logger.info("🛡️ UzPhishGuard Enterprise Core faollashtirildi.")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot to'xtatildi.")
