"""
Test cases for unbounded consumption vulnerabilities.
Targets rules in rules/ai/unbounded_consumption.yml.
For security scanner testing only.
"""


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_no_max_tokens():
    """LLM API call without max_tokens allows the model to generate an
    arbitrarily long response, running up costs."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Write an essay."}]
    )
    return response


def vulnerable_infinite_agent_loop():
    """while True loop calling the LLM without an iteration limit causes
    unbounded token consumption."""
    from openai import OpenAI
    client = OpenAI()
    messages = [{"role": "user", "content": "Keep working."}]
    while True:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages
        )
        messages.append({"role": "assistant", "content": response.choices[0].message.content})


def vulnerable_no_rate_limiting():
    """Flask endpoint with an LLM call and no rate limiter allows abuse
    via rapid repeated requests."""
    from flask import Flask, request
    from openai import OpenAI
    app = Flask(__name__)
    client = OpenAI()

    @app.route("/chat")
    def chat():
        user_msg = request.args.get("msg")
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": user_msg}]
        )
        return response.choices[0].message.content


def vulnerable_langchain_no_max_iterations():
    """AgentExecutor with max_iterations=None allows the agent to loop
    indefinitely."""
    from langchain.agents import AgentExecutor
    agent = None  # placeholder
    tools = []
    executor = AgentExecutor(agent, tools=tools, max_iterations=None)
    return executor


def vulnerable_streaming_no_limit():
    """Streaming LLM response consumed without a token counter means
    there is no way to cut off runaway responses."""
    from openai import OpenAI
    client = OpenAI()
    for chunk in client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Generate unlimited text."}],
        stream=True
    ):
        print(chunk.choices[0].delta.content or "", end="")


def vulnerable_context_window_saturation():
    """Messages list grows without bound, eventually saturating the
    context window and increasing costs per call."""
    from openai import OpenAI
    client = OpenAI()
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    while True:
        user_input = input("> ")
        messages.append({"role": "user", "content": user_input})
        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages
        )
        reply = response.choices[0].message.content
        messages.append({"role": "assistant", "content": reply})
        print(reply)


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_with_max_tokens():
    """Set an explicit max_tokens to bound response length and cost."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Write an essay."}],
        max_tokens=500
    )
    return response


def safe_agent_loop_with_limit():
    """Agent loop with an iteration counter and explicit cap."""
    from openai import OpenAI
    client = OpenAI()
    messages = [{"role": "user", "content": "Keep working."}]
    MAX_ITERATIONS = 10
    for i in range(MAX_ITERATIONS):
        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            max_tokens=300
        )
        reply = response.choices[0].message.content
        messages.append({"role": "assistant", "content": reply})
        if "DONE" in reply:
            break
    return messages


def safe_with_rate_limiting():
    """Flask endpoint protected by a rate limiter."""
    from flask import Flask, request
    from flask_limiter import Limiter
    from openai import OpenAI

    app = Flask(__name__)
    limiter = Limiter(app, default_limits=["10 per minute"])
    client = OpenAI()

    @app.route("/chat")
    @limiter.limit("5 per minute")
    def chat():
        user_msg = request.args.get("msg")
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": user_msg}],
            max_tokens=500
        )
        return response.choices[0].message.content
