"""
TrustRAG Authentication & Authorization Engine
Handles bcrypt salted password hashing, credential verification, and user management.
Pre-seeds the 4-tier clearance hierarchy accounts.
"""

from typing import Optional, Dict, Any, Tuple
import bcrypt
import db
import config

# Pre-defined test accounts representing the 4-tier clearance hierarchy
DEFAULT_USERS = [
    {
        "username": "intern_bob",
        "password": "Password@123",
        "role": "Public / Intern",
        "clearance_level": 1
    },
    {
        "username": "dev_sarah",
        "password": "Password@123",
        "role": "Software Engineer",
        "clearance_level": 2
    },
    {
        "username": "hr_elena",
        "password": "Password@123",
        "role": "HR Manager",
        "clearance_level": 3
    },
    {
        "username": "exec_david",
        "password": "Password@123",
        "role": "Executive / CTO",
        "clearance_level": 4
    }
]


def hash_password(password: str) -> str:
    """Hashes a plain text password with a secure bcrypt salt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def register_user(
    username: str,
    password: str,
    role: str,
    clearance_level: int
) -> Tuple[bool, str]:
    """Registers a new user after validation."""
    username = username.strip().lower()
    if not username:
        return False, "Username cannot be empty."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if clearance_level not in config.CLEARANCE_LEVELS:
        return False, f"Invalid clearance level: {clearance_level}. Must be 1 to 4."

    existing = db.get_user_by_username(username)
    if existing:
        return False, f"User '{username}' already exists."

    pwd_hash = hash_password(password)
    success = db.create_user(username, pwd_hash, role, clearance_level)
    if success:
        return True, "User created successfully."
    return False, "Database error creating user."


import time
from collections import defaultdict

# Security notice: DEFAULT_USERS are seeded for evaluation and demonstration purposes only.
# Production deployments should rotate credentials and enforce multi-factor authentication (MFA).
_FAILED_ATTEMPTS = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 60


def is_rate_limited(username: str) -> Tuple[bool, int]:
    """Checks if a username has exceeded failed login attempts within the lockout window."""
    now = time.time()
    attempts = [t for t in _FAILED_ATTEMPTS[username] if now - t < LOCKOUT_WINDOW_SECONDS]
    _FAILED_ATTEMPTS[username] = attempts
    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        remaining_lockout = int(LOCKOUT_WINDOW_SECONDS - (now - attempts[0]))
        return True, max(1, remaining_lockout)
    return False, 0


def record_failed_attempt(username: str):
    """Records a failed authentication timestamp."""
    _FAILED_ATTEMPTS[username].append(time.time())


def clear_failed_attempts(username: str):
    """Resets failed attempts upon successful authentication."""
    if username in _FAILED_ATTEMPTS:
        del _FAILED_ATTEMPTS[username]


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Validates user credentials with brute-force rate-limiting.
    Returns the user dict (excluding password_hash) if valid, or None if invalid or locked.
    """
    username = username.strip().lower()
    
    locked, remaining_sec = is_rate_limited(username)
    if locked:
        print(f"[Auth Security] User '{username}' locked out. Retry in {remaining_sec}s.")
        return None

    user = db.get_user_by_username(username)
    if not user:
        record_failed_attempt(username)
        return None

    if verify_password(password, user["password_hash"]):
        clear_failed_attempts(username)
        # Do not expose password hash to caller
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "clearance_level": user["clearance_level"],
            "clearance_info": config.CLEARANCE_LEVELS.get(user["clearance_level"], {})
        }
        return user_info

    record_failed_attempt(username)
    return None


def can_access_clearance(user_clearance: int, required_clearance: int) -> bool:
    """Zero-Trust clearance policy: Level N can access any document requiring Level <= N."""
    return user_clearance >= required_clearance


def seed_default_users():
    """Initializes the 4 canonical test users if they don't already exist."""
    db.init_db()
    for u in DEFAULT_USERS:
        existing = db.get_user_by_username(u["username"])
        if not existing:
            pwd_hash = hash_password(u["password"])
            db.create_user(u["username"], pwd_hash, u["role"], u["clearance_level"])
            print(f"[Seed] Created test user: {u['username']} (Level {u['clearance_level']})")
        else:
            print(f"[Seed] User {u['username']} already present.")
