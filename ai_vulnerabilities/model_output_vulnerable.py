"""Test cases for model output validation vulnerabilities."""
import openai
import os
import subprocess
from flask import render_template_string, redirect


def vulnerable_llm_to_sql(user_question):
    """Vulnerable: LLM output used directly in SQL."""
    import sqlite3

    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate SQL for: {user_question}"}]
    )

    sql_query = response.choices[0].message.content
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE {sql_query}")
    return cursor.fetchall()


def vulnerable_llm_to_command(task):
    """Vulnerable: LLM output executed as system command."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate shell command for: {task}"}]
    )

    command = response.choices[0].message.content
    os.system(command)


def vulnerable_llm_to_eval(problem):
    """Vulnerable: LLM output passed to eval()."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Write Python code to solve: {problem}"}]
    )

    code = response.choices[0].message.content
    result = eval(code)
    return result


def vulnerable_llm_to_exec(task_description):
    """Vulnerable: LLM output executed as Python code."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate Python code for: {task_description}"}]
    )

    code = response.choices[0].message.content
    exec(code)


def vulnerable_llm_to_file_path(filename):
    """Vulnerable: LLM output used in file operation."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Suggest file path for: {filename}"}]
    )

    file_path = response.choices[0].message.content
    with open(file_path, 'w') as f:
        f.write("data")


def vulnerable_llm_to_subprocess(task):
    """Vulnerable: LLM output in subprocess with shell=True."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate command for: {task}"}]
    )

    command = response.choices[0].message.content
    subprocess.run(command, shell=True)


def vulnerable_llm_output_no_validation(query):
    """Vulnerable: LLM output returned without validation."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": query}]
    )

    return response.choices[0].message.content


def vulnerable_llm_to_html_render(content_request):
    """Vulnerable: LLM output rendered as HTML template."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate HTML for: {content_request}"}]
    )

    html_content = response.choices[0].message.content
    return render_template_string(html_content)


def vulnerable_llm_json_no_validation(data_request):
    """Vulnerable: LLM JSON output parsed without schema validation."""
    import json

    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": data_request}],
        response_format={"type": "json_object"}
    )

    data = json.loads(response.choices[0].message.content)
    return data


def vulnerable_llm_to_redirect(destination):
    """Vulnerable: LLM output used in redirect."""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate URL for: {destination}"}]
    )

    url = response.choices[0].message.content
    return redirect(url)


def safe_llm_output_with_validation(user_query):
    """Safe: LLM output with proper validation and sanitization."""
    import re
    import json
    from jsonschema import validate, ValidationError

    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_query}],
        response_format={"type": "json_object"}
    )

    content = response.choices[0].message.content

    schema = {
        "type": "object",
        "properties": {
            "result": {"type": "string", "maxLength": 1000}
        },
        "required": ["result"]
    }

    try:
        data = json.loads(content)
        validate(instance=data, schema=schema)

        sanitized = re.sub(r'[<>\"\'&]', '', data['result'])
        return sanitized
    except (json.JSONDecodeError, ValidationError) as e:
        return None
