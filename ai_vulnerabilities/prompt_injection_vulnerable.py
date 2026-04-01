"""Test cases for prompt injection vulnerabilities."""
import openai
import anthropic
from langchain.prompts import PromptTemplate


def vulnerable_openai_fstring(user_input):
    """Vulnerable: User input in OpenAI prompt via f-string."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": f"Translate the following to French: {user_input}"}
        ]
    )
    return response.choices[0].message.content


def vulnerable_openai_concat(user_query):
    """Vulnerable: User input concatenated into OpenAI prompt."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": "Answer this question: " + user_query}
        ]
    )
    return response.choices[0].message.content


def vulnerable_system_message(user_instruction):
    """Vulnerable: User-controlled system message."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": user_instruction},
            {"role": "user", "content": "Hello"}
        ]
    )
    return response.choices[0].message.content


def vulnerable_anthropic_fstring(user_text):
    """Vulnerable: User input in Claude message via f-string."""
    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": f"Summarize: {user_text}"}
        ]
    )
    return message.content


def vulnerable_format_method(user_data):
    """Vulnerable: Using .format() with user input."""
    client = openai.OpenAI()
    prompt = "Process this data: {}".format(user_data)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


def vulnerable_langchain_template(user_template):
    """Vulnerable: User input used as LangChain template."""
    template = PromptTemplate.from_template(user_template)
    return template


def vulnerable_indirect_injection(file_path):
    """Vulnerable: Loading file content without validation."""
    with open(file_path) as f:
        content = f.read()

    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Analyze: {content}"}]
    )
    return response.choices[0].message.content


def safe_parameterized_prompt(user_input):
    """Safe: Using structured prompt with clear boundaries."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful translator. Only translate the text provided."},
            {"role": "user", "content": json.dumps({"text_to_translate": user_input})}
        ]
    )
    return response.choices[0].message.content
