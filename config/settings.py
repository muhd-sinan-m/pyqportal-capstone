import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY     = os.environ.get("SECRET_KEY", "dev_secret_key")
    DEBUG          = os.environ.get("FLASK_ENV") == "development"

    # Database — RDS PostgreSQL (same format as before)
    DATABASE_URL   = os.environ.get("DATABASE_URL")

    # AWS S3 (replaces Supabase Storage)
    AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_REGION            = os.environ.get("AWS_REGION", "ap-south-1")
    S3_BUCKET_NAME        = os.environ.get("S3_BUCKET_NAME")

    # Gemini AI
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

    # JWT (new — for API access)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt_dev_secret_key_minimum_32_chars")

    # Admin defaults
    ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
    ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")