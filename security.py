
import bcrypt

def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(password: str, hashed: str) -> bool:
    """Verify password with bcrypt"""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
