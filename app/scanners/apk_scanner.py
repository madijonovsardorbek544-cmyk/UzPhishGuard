import hashlib
from androguard.core.bytecodes.apk import APK
from loguru import logger

class DeepAPKScanner:
    """Zararli APK fayllarini statik tahlil qiluvchi va MITRE ATT&CK matritsasiga bog'lovchi modul."""
    
    def __init__(self):
        # Fishing va troyan dasturlari ko'p suiiste'mol qiladigan kritik ruxsatnomalar
        self.high_risk_permissions = {
            "android.permission.RECEIVE_SMS": {"score": 35, "mitre": "T1641", "technique": "Access SMS Logs (Credential Theft)"},
            "android.permission.READ_SMS": {"score": 30, "mitre": "T1641", "technique": "Read SMS Content"},
            "android.permission.SEND_SMS": {"score": 25, "mitre": "T1517", "technique": "Exfiltration via SMS (Exfiltrate Data)"},
            "android.permission.READ_CONTACTS": {"score": 15, "mitre": "T1430", "technique": "Location/Contact Discovery"},
            "android.permission.BIND_ACCESSIBILITY_SERVICE": {"score": 50, "mitre": "T1513", "technique": "Input Injection / Screen Capture (Malicious Accessibility)"}
        }

    def calculate_sha256(self, file_path: str) -> str:
        """Faylning SHA-256 xesh qiymatini hisoblash (Kiber-identifikator)."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def analyze_apk(self, file_path: str) -> dict:
        """APK faylini statik tahlil qilish va MITRE xaritasini chizish."""
        risk_score = 0
        detected_permissions = []
        mitre_mappings = []
        
        try:
            # Androguard orqali APK paketini parslash
            apk_obj = APK(file_path)
            
            package_name = apk_obj.get_package()
            app_name = apk_obj.get_app_name()
            permissions = apk_obj.get_permissions()
            
            # Fayl xeshini olish
            file_hash = self.calculate_sha256(file_path)
            
            # Ruxsatnomalar tahlili va xavf ballini hisoblash
            for perm in permissions:
                if perm in self.high_risk_permissions:
                    perm_meta = self.high_risk_permissions[perm]
                    risk_score += perm_meta["score"]
                    detected_permissions.append(perm)
                    
                    # MITRE formatida xaritalash
                    mapping = {
                        "mitre_id": perm_meta["mitre"],
                        "technique_name": perm_meta["technique"],
                        "trigger_permission": perm
                    }
                    if mapping not in mitre_mappings:
                        mitre_mappings.append(mapping)

            # Maxsus dynamic troyan indikatori (Accessibility Service so'ralsa xavf 99% ga chiqadi)
            if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
                risk_score = max(risk_score, 95)

            # Chegarani to'g'rilash
            risk_score = min(risk_score, 100)
            is_malware = risk_score >= 45

            return {
                "package_name": package_name,
                "app_name": app_name,
                "sha256": file_hash,
                "is_malware": is_malware,
                "risk_score": risk_score,
                "detected_permissions": detected_permissions,
                "mitre_mappings": mitre_mappings,
                "total_permissions_requested": len(permissions)
            }

        except Exception as e:
            logger.error(f"❌ APK statik tahlilida jiddiy xatolik: {str(e)}")
            return {
                "is_malware": False,
                "risk_score": 0,
                "error": f"Faylni analiz qilib bo'lmadi: {str(e)}"
            }

# Global ob'ekt (Singleton)
apk_scanner = DeepAPKScanner()
