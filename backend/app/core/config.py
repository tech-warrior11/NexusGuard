"""
Core settings and configuration for NexusGuard
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory of Backend
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load secure environment variables from .env file
load_dotenv(os.path.join(BASE_DIR, ".env"))

class Settings:
    PROJECT_NAME: str = "NexusGuard"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database Configuration (SQLite for local dev, path points to backend/nexusguard.db)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        f"sqlite:///{BASE_DIR}/nexusguard.db"
    )
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    # Security & JWT Token Configurations
    # 100% Secure: Dynamically generate a strong key if not set via environment variable
    # Note: Using os.urandom means JWT tokens will invalidate on server restart unless SECRET_KEY is explicitly set.
    SECRET_KEY: str = os.getenv("SECRET_KEY") or os.urandom(32).hex()
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours


settings = Settings()
