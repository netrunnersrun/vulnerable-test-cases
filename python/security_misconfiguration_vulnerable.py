"""
Test cases for security misconfiguration vulnerabilities.
Targets rules in rules/traditional/security_misconfiguration.yml.
For security scanner testing only.
"""
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_flask_debug_mode():
    """Flask app.run() with debug=True exposes the Werkzeug debugger and
    allows arbitrary code execution in production."""
    from flask import Flask
    app = Flask(__name__)
    app.run(host="0.0.0.0", debug=True, port=5000)


def vulnerable_django_debug_true():
    """Django DEBUG = True leaks stack traces and config details to users."""
    # settings.py equivalent
    DEBUG = True
    ALLOWED_HOSTS = ["*"]


def vulnerable_cors_allow_all_origins():
    """CORS configured with a wildcard origin permits any website to make
    cross-origin requests to the API."""
    from flask import Flask
    from flask_cors import CORS
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}}, origins="*")


def vulnerable_xml_parsing_xxe():
    """Parsing XML with the standard library without defusedxml is
    susceptible to XXE (XML External Entity) attacks."""
    user_file = "uploaded.xml"
    tree = xml.etree.ElementTree.parse(user_file)
    root = tree.getroot()
    return root


def vulnerable_hardcoded_secret_key():
    """Hardcoded SECRET_KEY in source code can be extracted from version
    control or binary artefacts."""
    SECRET_KEY = "super-secret-key-12345-do-not-share"
    return SECRET_KEY


def vulnerable_flask_send_file_user_input():
    """send_file() called with user-controlled path allows path traversal
    and arbitrary file reads."""
    from flask import Flask, request, send_file
    app = Flask(__name__)

    @app.route("/download")
    def download():
        filename = request.args.get("file")
        return send_file(filename)


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_flask_no_debug():
    """Flask app started without debug mode -- safe for production."""
    from flask import Flask
    app = Flask(__name__)
    app.run(host="0.0.0.0", debug=False, port=5000)


def safe_django_debug_false():
    """Django DEBUG disabled in production settings."""
    DEBUG = False
    ALLOWED_HOSTS = ["myapp.example.com"]


def safe_cors_restricted_origins():
    """CORS limited to a specific trusted origin."""
    from flask import Flask
    from flask_cors import CORS
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "https://trusted.example.com"}})


def safe_xml_with_defusedxml():
    """Using defusedxml to parse XML prevents XXE attacks."""
    import defusedxml.ElementTree as SafeET
    tree = SafeET.parse("uploaded.xml")
    root = tree.getroot()
    return root


def safe_secret_key_from_env():
    """Secret key loaded from an environment variable at runtime."""
    import os
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    return SECRET_KEY
