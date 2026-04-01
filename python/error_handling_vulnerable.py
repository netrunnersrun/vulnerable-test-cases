"""
Test cases for error handling vulnerabilities.
Targets rules in rules/traditional/error_handling.yml.
For security scanner testing only.
"""
import traceback


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_bare_except():
    """Bare except catches SystemExit and KeyboardInterrupt, masking
    critical errors."""
    try:
        result = 1 / 0
    except:
        print("something went wrong")


def vulnerable_except_pass():
    """Silently swallowing exceptions hides bugs and security issues."""
    try:
        data = open("/etc/passwd").read()
    except Exception:
        pass


def vulnerable_traceback_in_response():
    """Returning a full traceback to the client exposes internal paths,
    library versions, and code structure."""
    try:
        risky_operation()
    except Exception:
        return traceback.format_exc()


def vulnerable_flask_propagate_exceptions():
    """PROPAGATE_EXCEPTIONS causes Flask to surface detailed error info
    to end users."""
    from flask import Flask
    app = Flask(__name__)
    app.config["PROPAGATE_EXCEPTIONS"] = True


def vulnerable_django_verbose_error():
    """Returning raw exception args in an HttpResponse leaks internal
    details to the client."""
    from django.http import HttpResponse
    try:
        do_something()
    except Exception as e:
        return HttpResponse(e.args)


def vulnerable_ioerror_except_pass():
    """Another variant: catching IOError with pass hides file-system
    failures that may have security implications."""
    try:
        with open("important.log", "a") as f:
            f.write("audit entry")
    except IOError:
        pass


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_specific_except_with_logging():
    """Catch a specific exception and log it properly."""
    import logging
    logger = logging.getLogger(__name__)
    try:
        result = 1 / 0
    except ZeroDivisionError as exc:
        logger.error("Division by zero: %s", exc)
        result = None
    return result


def safe_generic_error_response():
    """Return a generic message to the client and log the real error
    server-side."""
    import logging
    logger = logging.getLogger(__name__)
    try:
        risky_operation()
    except Exception as exc:
        logger.exception("Unexpected error during risky_operation")
        return {"error": "An internal error occurred. Please try again later."}
