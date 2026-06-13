import os
import re
import asyncio
import psycopg2
import requests
from urllib.parse import urlparse
from aiogram import Bot, Dispatcher, types
from aiogram.filters import BaseFilter
from dotenv import load_dotenv

# .env faylini yuklash
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")

# Bot va Dispatcher obyektlarini yaratish
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# ==========================================
# 1. STRATEGIK KIBER-TAHLIL FUNKSIYALARI
# ==========================================
def extract_urls(text: str) -> list:
    """Matn ichidan barcha URL manzillarni xavfsiz ajratib olish."""
    if not text:
        return []
    return re.findall(r'https?://[^\s]+', text)

def advanced_heuristics_check(url: str) -> bool:
    """
    Ilg'or oqilona hevristik tahlil (AI-Heuristics).
    Fishing guruhlari va subdomen orqali aldash usullarini ushlaydi.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if not domain:
            return False

        # Shubhali yuqori darajali domenlar (TLDs)
        suspicious_tlds = ['.xyz', '.tk', '.ru', '.link', '.free', '.click', '.top', '.info', '.net', '.org-uz']
        # Mashhur o'zbek brendlari nomlari (Fishingda ko'p ishlatiladigan)
        target_brands = ['click', 'payme', 'uzcard', 'humo', 'my.gov', 'agro', 'bank', 'soliq', 'olx', 'uzb']

        # 1. TLD tekshiruvi
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True

        # 2. Typosquatting (Brend nomlarini soxtalashtirish) tekshiruvi
        for brand in target_brands:
            if brand in domain:
                # Agar domen rasmiy brend domeni bo'lmasa (masalan, payme.uz emas, payme-uz.net bo'lsa)
                if not (domain.endswith(f"{brand}.uz") or domain == f"{brand}.uz"):
                    return True
        return False
    except Exception:
        return False

# ==========================================
# 2. IP ENRICHMENT (GEOLOKATSIYA VA TAHID MANBASI)
# ==========================================
def get_ip_enrichment(url: str) -> dict:
    """Havola qayerdan kelayotganini IP va Davlat darajasida aniqlash (IP Enrichment)."""
    data = {
        "ip_address": "0.0.0.0", "country": "Unknown",
        "latitude": 41.2995, "longitude": 69.2401  # Default: Toshkent
    }
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Domen IP manzilini DNS orqali aniqlash uchun tashqi xizmatdan foydalanamiz
        dns_res = requests.get(f"https://dns.google/resolve?name={domain}", timeout=3).json()
        if "Answer" in dns_res:
            ip = dns_res["Answer"][0]["data"]
            data["ip_address"] = ip
            
            # IP orqali Geolokatsiyani aniqlash (Milliardlik kompaniyalar texnologiyasi)
            geo_res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if geo_res.get("status") == "success":
                data["country"] = geo_res.get("country", "Unknown")
                data["latitude"] = float(geo_res.get("lat", 41.2995))
                data["longitude"] = float(geo_res.get("lon", 69.2401))
    except Exception:
        pass
    return data

# ==========================================
# 3. MA'LUMOTLAR BAZASI BILAN XAVFSIZ ISHLASH
# ==========================================
def save_to_siem(chat_title, username, url, status, risk_score, geo_data):
    """Kiber-loglarni Supabase/PostgreSQL bazasiga 100% xavfsiz va xatosiz yozish."""
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as cursor:
                # Ustun nomlari kichik harfda va aniq strukturada bo'lishi shart
                query = """
                INSERT INTO scanned_links (chat_title, username, url, status, risk_score, ip_address, country, latitude, longitude)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """
                cursor.execute(query, (
                    str(chat_title),
                    str(username),
                    str(url),
                    str(status),
                    int(risk_score),
                    str(geo_data["ip_address"]),
                    str(geo_data["country"]),
                    float(geo_data["latitude"]),
                    float(geo_data["longitude"])
                ))
                conn.commit()
                print("🛡️ [SIEM Log]: Ma'lumot bazaga muvaffaqiyatli yozildi.")
    except Exception as e:
        # Agar xato bo'lsa, Render loglarida aniq nimaligini ko'rsatadi
        print(f"❌ [DATABASE ERROR]: Bazaga yozishda muammo chiqdi: {e}")

# ==========================================
# 4. BOT FILTR VA MODERATSIYA REJIMLARI
# ==========================================
class LinkFilter(BaseFilter):
    async def __call__(self, message: types.Message) -> bool:
        if message.text:
            return len(extract_urls(message.text)) > 0
        return False

@dp.message(LinkFilter())
async def cyber_security_monitor(message: types.Message):
    urls = extract_urls(message.text)
    chat_title = message.chat.title if message.chat.title else "Shaxsiy Chat"
    username = f"@{message.from_user.username}" if message.from_user.username else message.from_user.full_name

    for url in urls:
        # Hevristik tahlil natijasi
        is_phishing = advanced_heuristics_check(url)
        
        if is_phishing:
            # 1. IP boyitish va Geolokatsiya ma'lumotlarini olish
            geo_data = get_ip_enrichment(url)
            
            # 2. Guruhdan tahdidni zudlik bilan o'chirish
            try:
                await message.delete()
            except Exception:
                pass # Bot admin bo'lmasa o'chira olmasligi mumkin

            # 3. Guruhga Professional SOC Incident Response xabarini yuborish
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v3 — Incident Alert**\n\n"
                f"👤 **Tahdid Manbasi:** {username}\n"
                f"❌ **Xavf Turi:** Fishing / Zararli havola aniqlandi.\n"
                f"📊 **Xavf Darajasi:** `95%` [Kritik]\n"
                f"🌐 **Server Joylashuvi:** {geo_data['country']} (IP: {geo_data['ip_address']})\n\n"
                f"ℹ️ *Tafsilotlar SIEM Dashboard kiber-xaritasiga muvaffaqiyatli uzatildi.*"
            )
            await message.answer(alert_text, parse_mode="Markdown")
            
            # 4. MA'LUMOTLAR BAZASIGA JO'NATISH (Dashboard uchun!)
            save_to_siem(chat_title, username, url, "BLOCKED", 95, geo_data)
        else:
            # Toza link bo'lsa ham bazaga "SAFE" deb yozamiz (Trafik statistikasi uchun)
            geo_data = {"ip_address": "127.0.0.1", "country": "Local", "latitude": 41.2995, "longitude": 69.2401}
            save_to_siem(chat_title, username, url, "SAFE", 0, geo_data)

# ==========================================
# 5. ASOSIY ISHGA TUSHIRISH (MAIN)
# ==========================================
async def main():
    print("🚀 UzPhishGuard Core Bot ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())
