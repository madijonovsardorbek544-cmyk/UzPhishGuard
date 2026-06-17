import regex as re
from urllib.parse import urlparse
from loguru import logger

class SmartURLScanner:
    """Fishing havolalarini Regex va Typosquatting (Hevristika) orqali tahlil qiluvchi modul."""
    
    def __init__(self):
        # Matn ichidan URL'larni aniqlash uchun mukammal Regex
        self.url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        )
        
        # O'zbekistondagi eng ko'p soxtalashtiriladigan maqsadli brendlar (White-list)
        self.target_brands = ["click.uz", "payme.uz", "uzcard.uz", "humocard.uz", "id.gov.uz", "post.uz"]
        
        # Fishingchilar ko'p ishlatadigan yuqori xavfli domen zonalari
        self.high_risk_tlds = [".xyz", ".tk", ".click", ".link", ".cf", ".gq", ".ml", ".ga", ".live", ".info", ".online"]

    def extract_urls(self, text: str) -> list:
        """Matn ichidagi barcha havolalarni ajratib olish."""
        if not text:
            return []
        return self.url_pattern.findall(text)

    def _jaro_winkler_distance(self, s1: str, s2: str) -> float:
        """Ikki matn o'rtasidagi o'xshashlik darajasini hisoblash (Typosquatting uchun)."""
        if s1 == s2:
            return 1.0

        len1, len2 = len(s1), len(s2)
        max_dist = int(max(len1, len2) / 2) - 1
        match = 0
        hash_s1 = [0] * len1
        hash_s2 = [0] * len2

        for i in range(len1):
            for j in range(max(0, i - max_dist), min(len2, i + max_dist + 1)):
                if s1[i] == s2[j] and hash_s2[j] == 0:
                    hash_s1[i] = 1
                    hash_s2[j] = 1
                    match += 1
                    break

        if match == 0:
            return 0.0

        t = 0
        point = 0
        for i in range(len1):
            if hash_s1[i]:
                while hash_s2[point] == 0:
                    point += 1
                if s1[i] != s2[point]:
                    t += 1
                point += 1
        t /= 2

        sim = (match / len1 + match / len2 + (match - t) / match) / 3.0
        
        # Winkler modifikatsiyasi (boshidagi bir xil harflar uchun bonus)
        p = 0.1
        l = 0
        for i in range(min(4, min(len1, len2))):
            if s1[i] == s2[i]:
                l += 1
            else:
                break
        
        return sim + l * p * (1 - sim)

    def analyze_url(self, url: str) -> dict:
        """Havolani kiber-tahlil qilish va xavf ballini (Risk Score) hisoblash."""
        risk_score = 0
        reasons = []
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
        except Exception as e:
            logger.error(f"⚠️ URL parslashda xatolik: {str(e)}")
            return {"is_phishing": True, "risk_score": 95, "reasons": ["Siniq yoki buzilgan URL formati"]}

        # 1. High-Risk TLD tekshiruvi
        for tld in self.high_risk_tlds:
            if domain.endswith(tld):
                risk_score += 45
                reasons.append(f"Yuqori xavfli domen zonasi aniqlandi ({tld})")
                break

        # 2. Typosquatting tekshiruvi (Brendlarni soxtalashtirish)
        for brand in self.target_brands:
            if domain == brand:
                # Haqiqiy brend bo'lsa, xavf ballini nol qilamiz va chiqamiz
                return {"is_phishing": False, "risk_score": 0, "reasons": ["Ishonchli rasmiy resurs"]}
            
            # Agar brend nomi domen ichida shubhali qatnashsa (masalan: click-uzcard.xyz yoki payme-login.com)
            brand_clean = brand.split('.')[0]
            if brand_clean in domain and domain != brand:
                risk_score += 50
                reasons.append(f"Taniqli brend nomi shubhali domenda ishlatilgan: {brand_clean}")
                
            # Jaro-Winkler orqali harflar almashinishini tekshirish
            similarity = self._jaro_winkler_distance(domain, brand)
            if 0.75 <= similarity < 1.0:
                risk_score += 60
                reasons.append(f"Typosquatting alomati: '{brand}' brendiga {int(similarity*100)}% o'xshash soxta domen")

        # Ballar chegarasini 0-100 oralig'ida saqlash
        risk_score = min(risk_score, 100)
        is_phishing = risk_score >= 50

        return {
            "url": url,
            "domain": domain,
            "is_phishing": is_phishing,
            "risk_score": risk_score,
            "reasons": reasons if reasons else ["Shubhali belgilar topilmadi"]
        }

# Global ob'ekt (Singleton)
url_scanner = SmartURLScanner()
