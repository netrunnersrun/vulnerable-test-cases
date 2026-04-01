"""
Test cases for misinformation guardrail vulnerabilities.
Targets rules in rules/ai/misinformation_guardrails.yml.
For security scanner testing only.
"""


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_no_content_filter():
    """LLM response returned to the user without any content moderation
    or filtering step."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Tell me about this topic."}]
    )
    # No content filter applied
    return response.choices[0].message.content


def vulnerable_no_confidence_score():
    """Response returned without attaching a confidence score, giving the
    user no way to assess reliability."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "What is the capital of France?"}]
    )
    return response.choices[0].message.content


def vulnerable_no_source_citation():
    """Factual answer served via API without any source citation or
    references for user verification."""
    from flask import jsonify
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "What are the side effects of aspirin?"}]
    )
    return jsonify({"answer": response.choices[0].message.content})


def vulnerable_medical_no_disclaimer():
    """Handling a medical/health query without a professional disclaimer
    can lead users to rely on unqualified advice."""
    from openai import OpenAI
    client = OpenAI()
    # medical query without disclaimer
    medical_query = "What are the symptoms of diabetes?"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": medical_query}]
    )
    return response.choices[0].message.content


def vulnerable_langchain_no_output_parser():
    """LangChain chain without an OutputParser -- the raw LLM string is
    used directly without structured validation."""
    from langchain.prompts import ChatPromptTemplate
    from langchain.chat_models import ChatOpenAI

    prompt = ChatPromptTemplate.from_messages([("user", "{question}")])
    llm = ChatOpenAI()
    chain = prompt | llm
    return chain


def vulnerable_llm_to_database_no_check():
    """LLM output stored directly in a database without fact-checking or
    human review -- treats hallucinations as authoritative data."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Summarize the Q3 earnings."}]
    )
    result = response.choices[0].message.content
    # Simulated DB insert
    db = {}
    db.update({"summary": result})


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_with_content_filter():
    """Apply a moderation / content filter before returning the LLM
    output."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Tell me about this topic."}],
        max_tokens=500,
    )
    raw_content = response.choices[0].message.content
    # Run content moderation
    moderation = client.moderations.create(input=raw_content)
    if moderation.results[0].flagged:
        return "Content has been flagged and cannot be displayed."
    return raw_content


def safe_with_source_citation():
    """Include source citations alongside the answer."""
    from flask import jsonify
    answer = "Aspirin may cause stomach irritation."
    sources = [
        "https://www.mayoclinic.org/drugs-supplements/aspirin",
        "https://medlineplus.gov/aspirin.html"
    ]
    return jsonify({"answer": answer, "sources": sources, "disclaimer": "This is not medical advice."})


def safe_langchain_with_output_parser():
    """Chain includes an OutputParser for structured validation."""
    from langchain.prompts import ChatPromptTemplate
    from langchain.chat_models import ChatOpenAI
    from langchain.output_parsers import PydanticOutputParser

    parser = PydanticOutputParser()
    prompt = ChatPromptTemplate.from_messages([("user", "{question}")])
    llm = ChatOpenAI()
    chain = prompt | llm | parser
    return chain
