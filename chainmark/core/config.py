"""
Core configuration settings for Chainmark AI.
"""

from typing import List, Optional
import os
import secrets
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Gateway Host & Port
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Upstream Foundation Model Endpoints
    UPSTREAM_OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    UPSTREAM_GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com"

    # API Key Strategy: "pass-through" (client header) or "managed" (injected by proxy)
    AUTH_MODE: str = "pass-through"
    MANAGED_OPENAI_API_KEY: Optional[str] = None
    MANAGED_GEMINI_API_KEY: Optional[str] = None

    # Cryptographic Vault Key (32 bytes / 64 hex chars for AES-256-GCM)
    # Defaults to auto-generated secret if not provided in environment
    VAULT_MASTER_KEY: str = os.getenv("CHAINMARK_VAULT_MASTER_KEY", secrets.token_hex(32))

    # Evidence Signing Key (Path to ECDSA P-256 PEM or auto-generated)
    SIGNING_PRIVATE_KEY_PATH: Optional[str] = None

    # Session & Taint Tracking
    SESSION_SLIDING_WINDOW_TURNS: int = 5
    SESSION_TTL_SECONDS: int = 3600
    ENABLED_DETECTORS: List[str] = [
        "aadhaar_verhoeff",
        "pan_strict",
        "luhn_card",
        "us_ssn",
        "mrn_health",
    ]

    # Policy Enforcement
    ACTIVE_POLICIES: List[str] = ["DPDP_INDIA", "HIPAA_SAFE_HARBOR"]
    FAIL_CLOSED: bool = True
    STREAM_BUFFER_WINDOW_TOKENS: int = 32

    model_config = {
        "env_file": ".env",
        "env_prefix": "CHAINMARK_",
        "extra": "ignore",
    }


settings = Settings()
