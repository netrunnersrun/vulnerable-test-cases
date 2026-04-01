"""
Test cases for sensitive information disclosure vulnerabilities.
Targets rules in rules/ai/sensitive_info_disclosure.yml.
For security scanner testing only.
"""
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_pii_ssn_in_prompt():
    """SSN sent directly inside an LLM prompt exposes PII to the model
    provider and any downstream logging."""
    from openai import OpenAI
    client = OpenAI()
    ssn = "123-45-6789"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"Look up records for SSN {ssn}"}
        ]
    )
    return response


def vulnerable_logging_full_response():
    """Logging the entire LLM response object may persist PII or
    sensitive content to log files."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Summarize the document."}]
    )
    logging.info(response)
    return response


def vulnerable_system_prompt_in_api_response():
    """Returning the system prompt in an API response reveals proprietary
    instructions to the client."""
    from flask import jsonify
    system_prompt = "You are a financial advisor with access to internal pricing."
    return jsonify({"system_prompt": system_prompt})


def vulnerable_raw_model_output_to_client():
    """Returning the full LLM message object exposes tool calls, metadata,
    and potentially sensitive content."""
    from flask import jsonify
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Help me."}]
    )
    return jsonify(response.choices[0].message)


def vulnerable_llm_response_written_to_file():
    """Writing raw LLM response content to a file without sanitization
    persists potentially sensitive data."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Generate report."}]
    )
    with open("output.txt", "w") as f:
        f.write(response.content)


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_pii_redacted_before_prompt():
    """Redact PII before sending to the LLM provider."""
    from openai import OpenAI
    client = OpenAI()
    ssn = "123-45-6789"
    redacted = "***-**-" + ssn[-4:]
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Look up records ending in {redacted}"}
        ]
    )
    return response


def safe_logging_filtered_fields():
    """Log only non-sensitive metadata from the response."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Summarize the document."}]
    )
    logger.info("LLM call succeeded, model=%s, usage=%s",
                response.model, response.usage)
    return response


def safe_generic_api_response():
    """Return only the answer text, not internal prompt data."""
    from flask import jsonify
    answer = "Based on the analysis, here are the results..."
    return jsonify({"answer": answer})
