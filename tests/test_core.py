import pytest
from app.database.ethics import governance
from app.scanners.url_scanner import url_scanner
from app.threat_intel.campaign_analyzer import campaign_analyzer

def test_pii_masking():
    """Etika va maxfiylik moduli to'g'ri ishlayotganini tekshirish."""
    raw_text = "Mening telefonim +998901234567 va kartam 8600123456789012"
    masked = governance.mask_text(raw_text)
    
    assert "1234567" not in masked
    assert "56789012" not in masked
    assert "XXXXXXX" in masked

def test_url_scanner_phishing():
    """URL skaner fishing va typosquattingni topa olishini tekshirish."""
    fake_url = "https://cllck-uzcard.xyz/login"
    result = url_scanner.analyze_url(fake_url)
    
    assert result["is_phishing"] is True
    assert result["risk_score"] >= 50

def test_campaign_generator():
    """Threat Intel moduli unikal Campaign ID yarata olishini tekshirish."""
    domain = "click-secure.xyz"
    threat_type = "Phishing Link"
    campaign_id = campaign_analyzer.generate_campaign_id(domain, threat_type)
    
    assert campaign_id.startswith("CAMP-")
    assert len(campaign_id) > 10
