# 🛡️ UzPhishGuard SOC v2 — Enterprise Hybrid Threat Intelligence

UzPhishGuard SOC v2 — bu Telegram guruhlarida real vaqt rejimida (Real-Time) fishing va zararli havolalarni aniqlash, o'chirish hamda ularni vizualizatsiya qilish uchun mo'ljallangan SIEM Dashboard va Bot ekotizimidir.

## 🚀 Texnologik Stak (Tech Stack)
* **Backend:** Python 3.10+ (Telebot / Migration slated for Aiogram)
* **Database:** Supabase Cloud PostgreSQL (Transaction Pooler - IPv4 Direct Bridge)
* **Frontend/SOC Dashboard:** Streamlit, Plotly (Dynamic Geo-Location Mapping)
* **AI Core:** Groq Cloud API (Llama-3 70B Language Model)
* **Threat Intel APIs:** PhishTank, URLScan, VirusTotal, IP-API

---

## 🛡️ Kiber-Hevristika va Aniqlovchi Algoritm (Detection Logic)
Tizim fishing havolalarni shunchaki matn kalit so'zlari orqali emas, balki chuqurlashtirilgan **URL Feature Extraction** (Heuristics) orqali tahlil qiladi:
1. **Domen va TLD tahlili:** Yuqori xavfli TLD zonalar (`.xyz`, `.tk`, `.ru`, `.link`) filtrlanishi.
2. **Typosquatting & Levenshtein Distansiyasi:** O'zbekistondagi yirik moliya va davlat tashkilotlari (Click, Payme, Uzcard, YAIDX) nomlarini qasddan soxtalashtirishni aniqlash.
3. **Entropy & Subdomain Count:** URL tarkibidagi shubhali subdomenlar va noodatiy simvollar sonini hisoblash.
4. **AI-Empowered Context Analysis:** Llama-3 AI modeli orqali fishing xabarning ijtimoiy injeneriya (social engineering) elementlarini chuqur skanerlash.

---

## 💾 Xotira va Resurslarni Boshqarish (Optimization)
* **RAM barqarorligi:** `cachetools.TTLCache` yordamida `maxsize=1000` va `ttl=3600` sekundlik xotira kesh rejimi o'rnatilgan. Bu xizmatni **Out Of Memory (OOM)** crashlaridan himoya qiladi.
* **Ma'lumotlar yaxlitligi:** SQLite faylli tizimidan bulutli **PostgreSQL** (Supabase) arxitekturasiga o'tilgan bo'lib, Render nusxalari (instances) o'rtasida ma'lumotlar sinxronizatsiyasi muvaffaqiyatli ta'minlangan.

---

## ⚙️ O'rnatish va Ishga Tushirish (Installation)

1. Repozitoriyani nusxalang:
```bash
git clone [https://github.com/SizningProfil/UzPhishGuard.git](https://github.com/SizningProfil/UzPhishGuard.git)
cd UzPhishGuard
