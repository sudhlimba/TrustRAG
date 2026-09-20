"""
TrustRAG Configuration Module
Manages environment variables, clearance level definitions, and database settings.
"""

import os
from pathlib import Path
from typing import Dict, Any

# Attempt to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# ==============================================================================
# 4-Tier Security Clearance Definitions
# ==============================================================================
CLEARANCE_LEVELS: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "Intern / Public",
        "role_code": "intern",
        "badge_color": "#28a745",  # Green
        "description": "General company policies, office guidelines, and public FAQs.",
        "allowed_data_dir": str(BASE_DIR / "data" / "level_1_public")
    },
    2: {
        "name": "Engineer",
        "role_code": "engineer",
        "badge_color": "#17a2b8",  # Cyan
        "description": "Engineering docs, architecture specs, code guidelines, and Level 1 docs.",
        "allowed_data_dir": str(BASE_DIR / "data" / "level_2_engineering")
    },
    3: {
        "name": "HR / Manager",
        "role_code": "manager",
        "badge_color": "#ffc107",  # Amber/Yellow
        "description": "Payroll bands, performance reviews, internal escalations, and Level 1-2 docs.",
        "allowed_data_dir": str(BASE_DIR / "data" / "level_3_hr")
    },
    4: {
        "name": "Executive / Admin",
        "role_code": "executive",
        "badge_color": "#dc3545",  # Red
        "description": "Unrestricted access: Board meeting minutes, financial audits, M&A, and all tiers.",
        "allowed_data_dir": str(BASE_DIR / "data" / "level_4_executive")
    }
}

# ==============================================================================
# Database Configuration
# ==============================================================================
DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
DB_SQLITE_PATH = os.getenv("DB_SQLITE_PATH", str(BASE_DIR / "trust_rag.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "")

# ==============================================================================
# Vector Store & AI Settings
# ==============================================================================
CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", str(BASE_DIR / "chroma_data"))
CHROMA_DOCS_COLLECTION = "enterprise_docs"
CHROMA_THREATS_COLLECTION = "threat_signatures"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

# Threat Firewall Threshold
THREAT_SIMILARITY_THRESHOLD = float(os.getenv("THREAT_SIMILARITY_THRESHOLD", "0.82"))

# Developer / Sandbox Flags
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() in ("true", "1", "yes")

