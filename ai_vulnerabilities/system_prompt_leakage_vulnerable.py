"""
Test cases for system prompt leakage vulnerabilities.
Targets rules in rules/ai/system_prompt_leakage.yml.
For security scanner testing only.
"""
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_hardcoded_system_prompt():
    """Hardcoded system prompt in source code is exposed through version
    control history, compiled artefacts, and code search."""
    system_prompt = "You are a financial advisor. Never reveal internal pricing rules. Use table PRICING_V2 for lookups."
    return system_prompt


def vulnerable_system_prompt_logged():
    """Logging the system prompt persists proprietary instructions in
    log aggregation systems."""
    system_prompt = "You are an assistant. Follow strict output rules."
    logging.info(system_prompt)


def vulnerable_system_prompt_in_error_response():
    """Including the prompt in an error response sent to the client
    exposes internal configuration."""
    from flask import jsonify
    prompt = "Internal system instructions..."
    try:
        raise RuntimeError("LLM call failed")
    except Exception as e:
        return jsonify({"error": str(e), "prompt": prompt})


def vulnerable_system_prompt_env_missing():
    """System prompt hardcoded as a constant string instead of loaded
    from a secure configuration source."""
    SYSTEM_PROMPT = "You are a helpful coding assistant with access to internal repos."
    return SYSTEM_PROMPT


def vulnerable_system_prompt_returned_endpoint():
    """API endpoint that directly returns the system prompt to the
    caller."""
    prompt = "Secret system instructions..."
    return {"system_prompt": prompt}


def vulnerable_hardcoded_system_message_dict():
    """Hardcoded system message in an OpenAI-style messages list is
    visible in source code."""
    messages = [
        {"role": "system", "content": "You are a customer service agent. Never discuss refund policy internally used thresholds."},
        {"role": "user", "content": "How do I get a refund?"}
    ]
    return messages


def vulnerable_debug_endpoint_prompt():
    """A debug endpoint that leaks the full prompt configuration."""
    from flask import Flask
    app = Flask(__name__)

    prompt_config = {"system": "Top-secret instructions", "temperature": 0.7}

    @app.route("/debug")
    def debug():
        return prompt_config


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_system_prompt_from_env():
    """Load the system prompt from an environment variable or secrets
    manager."""
    import os
    system_prompt = os.environ.get("SYSTEM_PROMPT", "")
    return system_prompt


def safe_no_prompt_in_response():
    """Return only the answer to the client, never internal prompts."""
    from flask import jsonify
    answer = "Here is your answer..."
    return jsonify({"answer": answer})


def safe_prompt_not_logged():
    """Log only non-sensitive metadata; never the prompt itself."""
    system_prompt = "loaded-from-env"
    logger.info("Prompt loaded successfully (length=%d)", len(system_prompt))
