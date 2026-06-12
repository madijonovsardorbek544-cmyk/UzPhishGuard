import os
import re
import asyncio
import logging
import aiohttp  # Asinxron HTTP so'rovlar uchun
from aiogram import Bot, Dispatcher, types
from cachetools import TTLCache
import asyncpg  # Asinxron PostgreSQL kutubxonasi

# Loglarni professional sozlash
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Konfiguratsiyalar (Render Environment Variables'dan olinadi)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")
GROQ_API_KEY = os.getenv("GEMINI_API_KEY")  # Groq/AI kalitingiz
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Resurslarni asraydigan Kesh (Max 1000 ta URL, 1 soat TTL)
URL_CACHE = TTLCache(maxsize=1000, ttl=3600)

# Bot va Dispatcher
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Matn ichidan URL manzillarni xirurgik ajratib olish (Regex)
def extract_urls(text: str) -> list:
    if not text:
        return []
    return re.findall(r'(https?://[^\s]+)', text)

# 1. Murakkab Kiber-Hevristika (Advanced Heuristics)
def advanced_heuristics_check(url: str) -> bool:
    suspicious_tlds = ['.xyz', '.tk', '.ru', '.link', '.free', '.click', '.top', '.info']
    target_brands = ['click', 'payme', 'uzcard', 'humo', 'my.gov', 'agro', 'bank', 'soliq']
    
    url_lower = url.lower()
    
    # TLD Tekshiruvi
    if any(url_lower.endswith(tld) or (tld + "/") in url_lower for tld in suspicious_tlds):
        return True
        
    # O'zbek brendlariga Typosquatting (soxtalashtirish) hujumi
    if any(brand in url_lower for brand in target_brands):
        # Agar domen tarkibida brend nomi bo'lsa-yu, rasmiy domen bo'lmasa -> Shubhali!
        official_domains = ['click.uz', 'payme.uz', 'uzcard.uz', 'humo.uz', 'my.gov.uz', 'cbu.uz']
        if not any(official in url_lower for official in official_domains):
            return True
            
    return False

# 2. AI Orqali Kontent va Ijtimoiy Ingeneriya tahlili (Asinxron Groq Llama-3)
async def ai_context_analysis(url: str, text: str) -> bool:
    if not GROQ_API_KEY:
        return False
        
    url_text = f"URL: {url}\nKontekst: {text}"
    payload = {
        "model": "llama3-70b-8192",
        "messages": [
            {
                "role": "system",
                "content": "Siz kiberxavfsizlik tahlilchisiz. Berilgan URL va matn fishing (phishing), soxta aksiya yoki firbgarlik ekanini aniqlang. Faqat bitta so'z javob bering: 'PHISHING' yoki 'SAFE'."
            },
            {"role": "user", "content": url_text}
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

# Hodisalarni markaziy PostgreSQL (Supabase) bazasiga asinxron yozish
async def save_incident(group_id: int, user_id: str, url: str, status: str, risk_score: float):
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        await conn.execute('''
            INSERT INTO scanned_links (group_id, user_id, url, status, risk_score, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
        ''', group_id, str(user_id), url, status, risk_score)
        await conn.close()
    except Exception as e:
        logger.error(f"Supabase bazasiga yozishda xatolik: {e}")

# Xabarlarni real vaqtda asinxron monitoring qilish
@dp.message()
async def monitor_messages(message: types.Message):
    if not message.text:
        return

    urls = extract_urls(message.text)
    if not urls:
        return

    for url in urls:
        # 1. Keshni tekshirish (Tezlik uchun)
        if url in URL_CACHE:
            if URL_CACHE[url] == "BLOCKED":
                try:
                    await message.delete()
                except Exception:
                    pass
                return
            continue

        # Tahlil jarayoni boshlandi
        is_phishing = False
        risk_score = 0.0

        # Hevristik qoida ishladi
        if advanced_heuristics_check(url):
            is_phishing = True
            risk_score = 85.0

        # Agar hevristika shubhalansa, AI orqali chuqur tekshiramiz
        if not is_phishing:
            if await ai_context_analysis(url, message.text):
                is_phishing = True
                risk_score = 95.0

        # Natija: Fishing aniqlansa
        if is_phishing:
            URL_CACHE[url] = "BLOCKED"
            
            # Xabarni guruhdan o'chirish
            try:
                await message.delete()
            except Exception as e:
                logger.error(f"Xabarni o'chirishda xatolik: {e}")

            # Bazaga yozish
            await save_incident(message.chat.id, message.from_user.id, url, "BLOCKED", risk_score)
            
            # Guruhga professional ogohlantirish
            alert_text = (
                f"🛡️ **UzPhishGuard SOC v2 — Incident Alert**\n\n"
                f"👤 **Tahdid Manbasi:** @{message.from_user.username or message.from_user.full_name}\n"
                f"❌ **Xavf Turi:** Fishing / Soxta Havola Yo'q Qilindi.\n"
                f"📊 **Xavf Darajasi:** `{risk_score}%`\n"
                f"ℹ️ *Tafsilotlar Supabase real-time kiber-xaritasiga muvaffaqiyatli yuklandi.*"
            )
            await message.answer(alert_text, parse_mode="Markdown")
            break
        else:
            # Havola xavfsiz bo'lsa
            URL_CACHE[url] = "SAFE"
            await save_incident(message.chat.id, message.from_user.id, url, "SAFE", 0.0)

# Botni ishga tushirish (Asinxron Polling)
async def main():
    logger.info("Asinxron UzPhishGuard SOC v2 Enterprise Bot ishga tushdi...")
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())
