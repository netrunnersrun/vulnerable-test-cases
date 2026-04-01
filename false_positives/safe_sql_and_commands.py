"""
False positive test cases for Python SQL injection and command injection.
All functions here are SAFE despite matching vulnerability patterns.
"""
import subprocess
import sqlite3
import hashlib
import os


# --- SQL Injection False Positives ---

def get_user_by_id(db, user_id: int):
    """Parameterized query - NOT SQL injection despite variable in execute()."""
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def search_users(db, name: str):
    """Parameterized query with LIKE - NOT injection."""
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{name}%",))
    return cursor.fetchall()


def bulk_insert_users(db, users: list):
    """executemany with parameterized values - NOT injection."""
    cursor = db.cursor()
    cursor.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [(u["name"], u["email"]) for u in users]
    )
    db.commit()


def get_user_sqlalchemy(session, user_id):
    """ORM query with filter - NOT injection despite dynamic value."""
    from sqlalchemy import select
    from models import User
    stmt = select(User).where(User.id == user_id)
    return session.execute(stmt).scalar_one_or_none()


def get_orders_django(user_id):
    """Django ORM filter - NOT injection."""
    from orders.models import Order
    return Order.objects.filter(user_id=user_id).select_related("product")


# --- Command Injection False Positives ---

def run_linter(filename: str):
    """subprocess with shell=False and validated filename - NOT injection."""
    if not filename.endswith((".py", ".js", ".java")):
        raise ValueError("Invalid file type")
    safe_path = os.path.basename(filename)
    result = subprocess.run(
        ["flake8", "--max-line-length", "120", safe_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout


def get_git_log():
    """Hardcoded command - NOT injection."""
    result = subprocess.run(
        ["git", "log", "--oneline", "-10"],
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_tests(test_module: str):
    """Command with allowlist validation - NOT injection."""
    ALLOWED_MODULES = {"test_auth", "test_api", "test_models", "test_views"}
    if test_module not in ALLOWED_MODULES:
        raise ValueError(f"Unknown test module: {test_module}")
    result = subprocess.run(
        ["python", "-m", "pytest", f"tests/{test_module}.py"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.returncode


def compress_file(filepath: str):
    """subprocess.run with list args (no shell) and path validation - NOT injection."""
    real_path = os.path.realpath(filepath)
    if not real_path.startswith("/data/uploads/"):
        raise ValueError("Access denied")
    subprocess.run(["gzip", real_path], check=True)


# --- Crypto / Hashing False Positives ---

def compute_file_checksum(filepath: str) -> str:
    """MD5 for file integrity checksum, NOT for password hashing - acceptable use."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_etag(content: bytes) -> str:
    """SHA-1 for HTTP ETag generation - NOT a security context."""
    return hashlib.sha1(content).hexdigest()


def hash_password_safely(password: str) -> str:
    """Proper password hashing with bcrypt - SAFE."""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
