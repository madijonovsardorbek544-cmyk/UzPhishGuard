from loguru import logger
from app.database.database import db
from app.database.ethics import governance
from app.scanners.url_scanner import url_scanner
from app.scanners.apk_scanner import apk_scanner

class UzPhishCorePipeline:
    """Barcha deteksiya modullarini, etika qoidalarini va bazani birlashtiruvchi universal boshqaruvchi (Orkestrator)."""
    
    def __init__(self):
        logger.info("🧠 UzPhishGuard Core Detection Pipeline muvaffaqiyatli yuklandi.")

    async def process_text_message(self, chat_title: str, sender_id: str, raw_text: str) -> dict:
        """Kelgan matnli xabarni to'liq kiber-tahlil pipeline'idan o'tkazish."""
        logger.info(r"📥 Yangi xabar keldi. Tahlil boshlanmoqda...")

        # 1. Privacy-by-Design: Shaxsiy ma'lumotlarni (PII) maskalash
        masked_text = governance.mask_text(raw_text)
        
        # 2. Havolalar (URL) tahlili
        urls = url_scanner.extract_urls(masked_text)
        
        highest_risk_score = 0
        is_phishing_detected = False
        analysis_results = []
        detected_ioc_list = []

        for url in urls:
            url_report = url_scanner.analyze_url(url)
            analysis_results.append(url_report)
            
            if url_report["is_phishing"]:
                is_phishing_detected = True
                detected_ioc_list.append(("DOMAIN", url_report["domain"]))
            
            if url_report["risk_score"] > highest_risk_score:
                highest_risk_score = url_report["risk_score"]

        # 3. Agar fishing aniqlansa, ma'lumotlarni Supabase'ga asinxron zanjirlash
        if is_phishing_detected:
            threat_type = "Phishing Link / Typosquatting"
            # Bazaga faqat maskalangan matn yoziladi (Etika talabi)
            threat_id = await db.log_threat(
                chat_title=chat_title,
                sender_id=str(sender_id),
                threat_type=threat_type,
                risk_score=highest_risk_score,
                raw_content=masked_text
            )
            
            # Aniqlangan domenlarni (IOC) indicators jadvaliga yozish
            if threat_id:
                for ioc_type, ioc_value in detected_ioc_list:
                    await db.log_indicator(
                        threat_id=threat_id,
                        indicator_type=ioc_type,
                        indicator_value=ioc_value,
                        reputation_score=highest_risk_score
                    )
        
        return {
            "is_phishing": is_phishing_detected,
            "risk_score": highest_risk_score,
            "masked_content": masked_text,
            "extracted_urls_count": len(urls),
            "detailed_reports": analysis_results
        }

    async def process_file_message(self, file_path: str, chat_title: str, sender_id: str, file_name: str) -> dict:
        """Kelgan fayllarni (ayniqsa APK) chuqur skanerdan o'tkazish orkestratsiyasi."""
        if not file_name.lower().endswith('.apk'):
            return {"is_malware": False, "risk_score": 0, "status": "Faqat APK fayllar skaner qilinadi"}

        logger.info(f"📦 APK fayl aniqlandi: {file_name}. Statik tahlil boshlanmoqda...")
        
        # 1. APK-ni chuqur tahlil qilish va MITRE ATT&CK xaritasini tuzish
        apk_report = apk_scanner.analyze_apk(file_path)
        
        # 2. Xavfli deb topilsa, Supabase'ga yozish logikasi (Kelajakda Faza 4 kengaytmasi uchun)
        # Hozircha hisobotni qaytaramiz
        return apk_report

# Global orkestrator ob'ekti (Singleton)
pipeline = UzPhishCorePipeline()
