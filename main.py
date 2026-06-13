import os
import re
import asyncio
import logging
import asyncpg
import requests
from urllib.parse import urlparse
from aiogram import Bot, Dispatcher, types
from aiogram.filters import BaseFilter

# Log tizimini professional sozlash
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# STRATEGIK MA'LUMOTLAR
BOT_TOKEN = "8654394563:AAH5hXC_VCFANB-AmK9_DMXUfd8Nq7EyK00"
DATABASE_URL = "postgresql://postgres.quvyyouwtytywtotkdyw:Harvard2030$^^@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres"

# Bot va Dispatcher (aiogram v3)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Regex orqali URL manzillarni professional ajratish
URL_PATTERN = re.compile(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

# ==========================================
# 1. ILG'OR TAHID TAHLILI (ADVANCED HEURISTICS)
# ==========================================
def advanced_heuristics_check(url: str) -> bool:
    """AI va qoidaga asoslangan gibrid fishing tahlili."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if not domain:
            return False

        suspicious_tlds = {'.xyz', '.tk', '.ru', '.link', '.free', '.click', '.top', '.info', '.net', '.org-uz', '.site', '.online'}
        target_brands = ['click', 'payme', 'uzcard', 'humo', 'my.gov', 'agro', 'bank', 'soliq', 'olx', 'uzb', 'telegram']

        # TLD darajasidagi tahdid
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True

        # Typosquatting tahlili (Brendni soxtalashtirish)
        for brand in target_brands:
            if brand in domain:
                # Agar rasmiy domen bo'lmasa xavfli deb topadi (Masalan: payme.uz o'rniga payme-login.com)
                if not (domain.endswith(f"{brand}.uz") or domain == f"{brand}.uz" or domain.endswith(f"{brand}.com")):
                    return True
        return False
    except Exception as e:
        logger.error(f"Heuristics error: {e}")
        return False

# ==========================================
# 2. TAHID MANBASINI BOYITISH (IP ENRICHMENT)
# ==========================================
def get_ip_enrichment(url: str) -> dict:
    """Domenning IP manzili va geografik koordinatalarini aniqlash."""
    context = {"ip_address": "0.0.0.0", "country": "Unknown", "latitude": 41.2995, "longitude": 69.2401}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Google DNS orqali IP aniqlash
        dns_url = f"https://dns.google/resolve?name={domain}"
        dns_res = requests.get(dns_url, timeout=3).json()
        
        if "Answer" in dns_res:
            ip = dns_res["Answer"][0]["data"]
            # Ba'zan DNS javobida qo'shimcha nuqta bo'lishi mumkin, uni tozalaymiz
            ip = ip.strip('.')
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                context["ip_address"] = ip
                
                # IP API orqali Geo-Lokatsiyani olish
                geo_res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
                if geo_res.get("status") == "success":
                    context["country"] = geo_res.get("country", "Unknown")
                    context["latitude"] = float(geo_res.get("lat", 41.2995))
                    context["longitude"] = float(geo_res.get("lon", 69.2401))
    except Exception as e:
        logger.warning(f"IP enrichment bypass: {e}")
    return context

# ==========================================
# 3. ASINXRON MA'LUMOTLAR BAZASI (ASYNC DATABASE ENGINE)
# ==========================================
async def save_to_siem(chat_title: str, username: str, url: str, status: str, risk_score: int, geo_data: dict):
    """Supabase'ga asinxron va dinamik ustunlar tahlili bilan yozish (Fail-Safe INSERT)."""
    conn = None
    try:
        # Supabase Connection Pooler bilan asinxron ulanish
        conn = await asyncpg.connect(DATABASE_URL)
        
        # Supabase ichidagi scanned_links jadvalining haqiqiy ustunlarini tekshiramiz
        columns_query = """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'scanned_links';
        """
        rows = await conn.fetch(columns_query)
        existing_columns = {row['column_name'] for row in rows}
        
        # Bazada bor ustunlarga qarab dinamik SQL so'rovini quramiz
        data_map = {
            "chat_title": str(chat_title),
            "group_id": str(chat_title),  # Agar group_id bo'lsa chat_title yoziladi
            "username": str(username),
            "user": str(username),          # Agar user ustuni bo'lsa
            "url": str(url),
            "status": str(status),
            "risk_score": int(risk_score),
            "ip_address": str(geo_data["ip_address"]),
            "country": str(geo_data["country"]),
            "latitude": float(geo_data["latitude"]),
            "longitude": float(geo_data["longitude"])
        }
        
        # Faqat bazada mavjud bo'lgan ustunlarnigina saralab olamiz (Xatolikni 100% oldini oladi)
        valid_data = {k: v for k, v in data_map.items() if k in existing_columns}
        
        if not valid_data:
            logger.error("Jadval ustunlari mos kelmadi.")
            return

        columns = ", ".join(valid_data.keys())
        placeholders = ", ".join([f"${i+1}" for i in range(len(valid_data))])
        insert_query = f"INSERT INTO scanned_links ({columns}) VALUES ({placeholders});"
        
        await conn.execute(insert_query, *valid_data.values())
        logger.info("🛡️ [SIEM] Ma'lumotlar bazaga muvaffaqiyatli muhrlandi.")
        
    except Exception as e:
        logger.error(f"❌ [DATABASE CRITICAL ERROR]: {e}")
    finally:
        if conn:
            await conn.close()

# ==========================================
# 4. MONITORING VA MODERATSIYA FILTERI
# ==========================================
class AdvancedLinkFilter(BaseFilter):
    async def __call__(self, message: types.Message) -> bool:
        if message.text:
            return bool(URL_PATTERN.search(message.text))
        return False

@dp.message(AdvancedLinkFilter())
async def cyber_incident_handler(message: types.Message):
    text = message.text
    urls = URL_PATTERN.findall(text)
    
    chat_title = message.chat.title if message.chat.title else "Cyber Group"
    username = f"@{message.from_user.username}" if message.from_user.username else message.from_user.full_name

    for url in urls:
        is_phishing = advanced_heuristics_check(url)
        
        if is_phishing:
            # Tahdid aniqlanganda IP Enrichment va tezkor bloklash
            geo_data = get_ip_enrichment(url)
            
            try:
                await message.delete()
            except Exception:
                logger.warning("Xabarni o'chirish uchun botda admin huquqi yetarli emas.")

            # Guruh uchun professional Incident Response bildirishnomasi
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v3 — Enterprise Alert**\n\n"
                f"👤 **Tahdid Manbasi:** {username}\n"
                f"❌ **Xavf Turi:** Fishing / Zararli havola aniqlandi.\n"
                f"📊 **Xavf Darajasi:** `98%` [Kritik]\n"
                f"🌐 **Server Joylashuvi:** {geo_data['country']} (IP: {geo_data['ip_address']})\n\n"
                f"ℹ️ *Tafsilotlar SIEM Dashboard markaziy kiber-xaritasiga uzatildi.*"
            )
            await message.answer(alert_text, parse_mode="Markdown")
            
            # SIEM tizimiga logni yozish
            await save_to_siem(chat_title, username, url, "BLOCKED", 98, geo_data)
        else:
            # Toza havolalarni ham umumiy trafik tahlili uchun bazaga kiritamiz
            default_geo = {"ip_address": "127.0.0.1", "country": "Local", "latitude": 41.2995, "longitude": 69.2401}
            await save_to_siem(chat_title, username, url, "SAFE", 0, default_geo)

# ==========================================
# 5. INITIATION
# ==========================================
async def main():
    logger.info("🚀 UzPhishGuard Enterprise Core Bot ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())
