import hashlib
from loguru import logger

class ThreatCampaignAnalyzer:
    """Fishing hujumlari va kiber-tahdidlarni klasterlab, kampaniyalarni (Campaign Detection) aniqlovchi modul."""
    
    def __init__(self):
        logger.info("🕵️ Threat Intelligence Campaign Analyzer moduli yuklandi.")

    def generate_campaign_id(self, domain: str, threat_type: str) -> str:
        """Domen va tahdid turiga asoslanib unikal Kampaniya ID yaratish (Hevristik zanjirlash)."""
        if not domain or domain == "unknown":
            return "CAMPAIGN-GENERIC-MISC"
            
        # Domenning asosiy nomini ajratib olish (subdomenlarni tozalash)
        parts = domain.split('.')
        base_identifier = parts[-2] if len(parts) > 1 else domain
        
        # Unikal xesh yaratish
        raw_seed = f"{base_identifier}_{threat_type.upper()}"
        campaign_hash = hashlib.md5(raw_seed.encode()).hexdigest()[:8].upper()
        
        return f"CAMP-{base_identifier.upper()}-{campaign_hash}"

    def cross_reference_indicators(self, active_threats: list) -> list:
        """Mavjud tahdidlar o'rtasidagi o'xshashlikni tahlil qilib, ularni bitta kampaniyaga bog'lash."""
        analyzed_campaigns = []
        
        for threat in active_threats:
            domain = threat.get("domain", "unknown")
            threat_type = threat.get("threat_type", "Phishing")
            
            # Kampaniya ID biriktirish
            campaign_id = self.generate_campaign_id(domain, threat_type)
            
            threat["campaign_id"] = campaign_id
            analyzed_campaigns.append(threat)
            
            logger.info(f"🎯 Tahdid zanjirlandi -> ID: {threat.get('id', 'NEW')} | Kampaniya: {campaign_id}")
            
        return analyzed_campaigns

# Global ob'ekt (Singleton) hamma modullar ishlata olishi uchun
campaign_analyzer = ThreatCampaignAnalyzer()
