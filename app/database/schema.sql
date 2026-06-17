-- 1. THREATS JADVALI: Fishing va ijtimoiy injeneriya voqealari
CREATE TABLE IF NOT EXISTS threats (
    id BIGSERIAL PRIMARY KEY,
    chat_title VARCHAR(255) NOT NULL,
    sender_identifier VARCHAR(100) NOT NULL, -- Telegram ID yoki Maskalangan Username
    threat_type VARCHAR(100) NOT NULL,       -- Phishing Link, Social Engineering, Spam
    risk_score INT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    raw_content TEXT NOT NULL,                -- PII Masking qilingan matn
    campaign_id VARCHAR(50) DEFAULT NULL,     -- Faza 7 uchun Kampaniya ID
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. INDICATORS JADVALI: Kiber-razvedka ko'rsatkichlari (IOC Extraction)
CREATE TABLE IF NOT EXISTS indicators (
    id BIGSERIAL PRIMARY KEY,
    threat_id BIGINT REFERENCES threats(id) ON DELETE CASCADE,
    indicator_type VARCHAR(50) NOT NULL,      -- DOMAIN, IP, TELEGRAM_USER, TELEGRAM_BOT
    indicator_value TEXT NOT NULL,            -- Masalan: "click-uzcard-bot.xyz"
    reputation_score INT DEFAULT 0,           -- Threat Intel API'lardan olingan ball
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. MALWARE_SAMPLES JADVALI: APK fayllar tahlili (Enterprise Standart)
CREATE TABLE IF NOT EXISTS malware_samples (
    id BIGSERIAL PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    sha256_hash VARCHAR(64) UNIQUE NOT NULL,  -- APK identifikatori
    file_size_bytes BIGINT NOT NULL,
    risk_score INT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    mitre_mappings JSONB DEFAULT '[]'::jsonb, -- MITRE ATT&CK Taktikalari (Faza 4)
    static_analysis_summary JSONB DEFAULT '{}'::jsonb,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tezkor qidiruv va SIEM Dashboard yuklanishini optimallashtirish uchun indekslar
CREATE INDEX IF NOT EXISTS idx_threats_campaign ON threats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_malware_hash ON malware_samples(sha256_hash);
