"""
False positive test cases for Python web security patterns.
All functions here are SAFE despite matching vulnerability patterns.
"""
import os
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# --- Path Traversal False Positives ---

def read_config_file(config_name: str) -> dict:
    """File read with basename stripping and allowlist - NOT path traversal."""
    ALLOWED_CONFIGS = {"database.json", "logging.json", "cache.json"}
    safe_name = os.path.basename(config_name)
    if safe_name not in ALLOWED_CONFIGS:
        raise ValueError(f"Unknown config: {safe_name}")
    config_path = Path("/etc/myapp") / safe_name
    with open(config_path, "r") as f:
        return json.load(f)


def serve_static_asset(filename: str) -> bytes:
    """Static file serving with path canonicalization - NOT path traversal."""
    base_dir = Path("/var/www/static").resolve()
    requested = (base_dir / filename).resolve()
    if not str(requested).startswith(str(base_dir)):
        raise PermissionError("Access denied")
    with open(requested, "rb") as f:
        return f.read()


def read_user_avatar(user_id: int) -> bytes:
    """File read with integer-only ID (no string injection possible) - SAFE."""
    avatar_path = f"/data/avatars/{int(user_id)}.png"
    with open(avatar_path, "rb") as f:
        return f.read()


# --- XSS / Template Injection False Positives ---

def render_user_greeting(username: str) -> str:
    """String returned but properly escaped before rendering - NOT XSS."""
    from markupsafe import escape
    safe_name = escape(username)
    return f"<p>Welcome, {safe_name}!</p>"


def render_markdown_safe(content: str) -> str:
    """Markdown rendered with bleach sanitization - NOT XSS."""
    import markdown
    import bleach
    html = markdown.markdown(content)
    return bleach.clean(html, tags=["p", "em", "strong", "a", "code", "pre"])


# --- SSRF False Positives ---

def fetch_approved_webhook(url: str) -> dict:
    """HTTP request with URL allowlist validation - NOT SSRF."""
    import urllib.parse
    import requests
    parsed = urllib.parse.urlparse(url)
    ALLOWED_HOSTS = {"api.github.com", "hooks.slack.com", "api.stripe.com"}
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    if parsed.scheme != "https":
        raise ValueError("HTTPS required")
    response = requests.get(url, timeout=10)
    return response.json()


def download_from_cdn(asset_id: str) -> bytes:
    """URL constructed from trusted base + validated ID - NOT SSRF."""
    import re
    import requests
    if not re.match(r"^[a-f0-9]{32}$", asset_id):
        raise ValueError("Invalid asset ID")
    url = f"https://cdn.internal.example.com/assets/{asset_id}"
    return requests.get(url, timeout=30).content


# --- Error Handling False Positives ---

def handle_api_error(error: Exception) -> dict:
    """Logs full error server-side but returns generic message - SAFE."""
    logger.exception("API error occurred: %s", error)
    return {
        "error": "An internal error occurred. Please try again.",
        "status": 500,
    }


def validate_input(data: dict) -> dict:
    """Returns validation error messages (not stack traces) - SAFE."""
    errors = {}
    if "email" not in data:
        errors["email"] = "Email is required"
    if "password" not in data or len(data["password"]) < 8:
        errors["password"] = "Password must be at least 8 characters"
    return errors


# --- Secrets / API Key False Positives ---

def get_openai_client():
    """API key from environment variable - NOT hardcoded secret."""
    import openai
    openai.api_key = os.environ["OPENAI_API_KEY"]
    return openai


def get_database_url() -> str:
    """Database URL from environment - NOT hardcoded credential."""
    return os.environ.get("DATABASE_URL", "sqlite:///dev.db")
