import os
import asyncpg
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

class AsyncDatabaseManager:
    """Supabase/PostgreSQL bilan asinxron va xavfsiz aloqani boshqaruvchi Enterprise drayver."""
    
    def __init__(self):
        self.db_url = os.getenv("DATABASE_URL")
        if self.db_url and self.db_url.startswith("postgres://"):
            self.db_url = self.db_url.replace("postgres://", "postgresql://", 1)
        
        self.pool = None

    async def initialize_pool(self):
        """Asinxron ulanishlar hovuzini (Connection Pool) yaratish."""
        if not self.db_url:
            logger.critical("KRIZIS: DATABASE_URL muhit o'zgaruvchisi topilmadi!")
            raise ValueError("DATABASE_URL konfiguratsiyada mavjud emas.")
        
        try:
            # Sanoat standarti: minimal 2 ta, maksimal 10 ta parallel faol ulanish
            self.pool = await asyncpg.create_pool(
                self.db_url,
                min_size=2,
                max_size=10,
                command_timeout=30.0
            )
            logger.info("🚀 Supabase Enterprise Async Connection Pool muvaffaqiyatli ishga tushdi.")
        except Exception as e:
            logger.error(f"❌ Ma'lumotlar bazasi poolini yaratishda xatolik: {str(e)}")
            raise e

    async def close(self):
        """Ulanishlar poolini xavfsiz yopish (Tizim o'chganda)."""
        if self.pool:
            await self.pool.close()
            logger.info("🔒 Ma'lumotlar bazasi pooli xavfsiz yopildi.")

    async def log_threat(self, chat_title: str, sender_id: str, threat_type: str, risk_score: int, raw_content: str, campaign_id: str = None) -> int:
        """Threats jadvaliga yangi tahdid voqeasini asinxron yozish."""
        if not self.pool:
            await self.initialize_pool()
            
        query = """
            INSERT INTO threats (chat_title, sender_identifier, threat_type, risk_score, raw_content, campaign_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id;
        """
        async with self.pool.acquire() as connection:
            try:
                threat_id = await connection.fetchval(query, chat_title, sender_id, threat_type, risk_score, raw_content, campaign_id)
                logger.info(f"💾 Tahdid saqlandi. ID: {threat_id} | Turi: {threat_type}")
                return threat_id
            except Exception as e:
                logger.error(f"❌ threats jadvaliga yozishda xatolik: {str(e)}")
                return None

    async def log_indicator(self, threat_id: int, indicator_type: str, indicator_value: str, reputation_score: int = 0):
        """Indicators (IOC) jadvaliga asinxron ma'lumot qo'shish."""
        if not self.pool:
            await self.initialize_pool()
            
        query = """
            INSERT INTO indicators (threat_id, indicator_type, indicator_value, reputation_score)
            VALUES ($1, $2, $3, $4);
        """
        async with self.pool.acquire() as connection:
            try:
                await connection.execute(query, threat_id, indicator_type, indicator_value, reputation_score)
                logger.info(f"🎯 Kiber-ko'rsatkich (IOC) zanjirlandi: {indicator_value} ({indicator_type})")
            except Exception as e:
                logger.error(f"❌ indicators jadvaliga yozishda xatolik: {str(e)}")

# Global singleton ob'ekt kelajakdagi hamma modullar ishlata olishi uchun
db = AsyncDatabaseManager()
