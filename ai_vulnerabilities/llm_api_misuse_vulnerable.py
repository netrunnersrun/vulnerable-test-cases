"""Test cases for LLM API misuse vulnerabilities."""
import openai
import anthropic


def vulnerable_hardcoded_openai_key():
    """Vulnerable: Hardcoded OpenAI API key."""
    openai.api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    client = openai.OpenAI(api_key="sk-hardcoded-key-12345")
    return client


def vulnerable_hardcoded_anthropic_key():
    """Vulnerable: Hardcoded Anthropic API key."""
    client = anthropic.Anthropic(api_key="sk-ant-1234567890abcdefghijklmnopqrstu")
    return client


def vulnerable_user_controlled_model(model_name):
    """Vulnerable: User-controlled model selection."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": "Hello"}]
    )
    return response.choices[0].message.content


def vulnerable_excessive_tokens():
    """Vulnerable: Excessive max_tokens without limit."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
        max_tokens=100000
    )
    return response


def vulnerable_no_timeout():
    """Vulnerable: No timeout on LLM API call."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Long computation..."}]
    )
    return response


def vulnerable_response_logging(response):
    """Vulnerable: Logging LLM response content."""
    import logging
    logging.info(response.choices[0].message.content)
    logging.warning(response.choices[0].message.content)


def vulnerable_user_controlled_temperature(temp):
    """Vulnerable: User-controlled temperature parameter."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
        temperature=temp
    )
    return response


def vulnerable_function_calling_no_validation():
    """Vulnerable: LLM function calling without validation."""
    client = openai.OpenAI()
    functions = [
        {
            "name": "execute_command",
            "description": "Execute a system command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                }
            }
        }
    ]

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Run ls command"}],
        functions=functions
    )
    return response


def vulnerable_no_error_handling():
    """Vulnerable: No error handling for API call."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
    return response


def safe_api_usage():
    """Safe: Proper API key management and error handling."""
    import os
    api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        raise ValueError("API key not configured")

    client = openai.OpenAI(api_key=api_key)

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=150,
            timeout=30.0
        )
        return response.choices[0].message.content
    except openai.APIError as e:
        print(f"API error: {e}")
        return None
