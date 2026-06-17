import regex as re
from loguru import logger

class DataGovernanceManager:
    """Privacy-by-Design tamoyili asosida PII (Shaxsiy ma'lumotlar)ni maskalash va etika moduli."""
    
    def __init__(self):
        # O'zbekiston telefon raqamlari formati uchun xavfsiz regex (+998, 998 yoki shunchaki 90, 91 va h.k.)
        self.phone_pattern = re.compile(r'(?:\+?998)?\s?\(?\d{2}\)?\s?\d{3}\s?\d{2}\s?\d{2}')
        
        # Plastik kartalar (Uzcard, Humo, Visa, Mastercard) uchun 16 xonali raqamlar regexi
        self.card_pattern = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')

    def mask_text(self, raw_text: str) -> str:
        """Matn ichidagi barcha maxfiy ma'lumotlarni (Telefon va Karta) avtomatik maskalash."""
        if not raw_text:
            return raw_text
            
        masked_text = raw_text
        
        # 1. Telefon raqamlarini maskalash (Faqat kod va boshlanishi qoladi, qolgani XXXX bo'ladi)
        try:
            phones = self.phone_pattern.findall(masked_text)
            for phone in phones:
                clean_phone = re.sub(r'\D', '', phone) # faqat raqamlarni qoldirish
                if len(clean_phone) >= 9:
                    # Masalan: 998901234567 -> 99890XXXXXXX
                    prefix = clean_phone[:-7]
                    masked_phone = f"{prefix}XXXXXXX"
                    masked_text = masked_text.replace(phone, masked_phone)
        except Exception as e:
            logger.error(f"⚠️ Telefon raqamini maskalashda xatolik: {str(e)}")

        # 2. Plastik karta raqamlarini maskalash (Boshidagi 6 ta va oxiridagi 4 ta raqam qoladi)
        try:
            cards = self.card_pattern.findall(masked_text)
            for card in cards:
                clean_card = re.sub(r'\D', '', card)
                if len(clean_card) == 16:
                    # Masalan: 8600123456789012 -> 860012XXXXXX9012
                    masked_card = f"{clean_card[:6]}XXXXXX{clean_card[12:]}"
                    masked_text = masked_text.replace(card, masked_card)
        except Exception as e:
            logger.error(f"⚠️ Karta raqamini maskalashda xatolik: {str(e)}")

        return masked_text

    def get_license_info(self) -> dict:
        """Dataset va loyiha litsenziya ma'lumotlarini qaytarish (Apache 2.0 Akademik talab)."""
        return {
            "license": "Apache License 2.0",
            "ethics_compliant": True,
            "pii_masking_active": True,
            "purpose": "Academic and Cyber Threat Intelligence Research Only"
        }

# Global ob'ekt (Singleton) hamma modullar ishlata olishi uchun
governance = DataGovernanceManager()
