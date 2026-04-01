"""
Test cases for agent goal hijack vulnerabilities.
Targets rules in rules/agentic/agent_goal_hijack.yml.
For security scanner testing only.
"""


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_langchain_user_system_message():
    """User-controlled system_message in AgentExecutor allows an attacker
    to completely override the agent's intended behaviour."""
    from langchain.agents import AgentExecutor
    user_input = input("Enter system message: ")
    agent = None  # placeholder
    executor = AgentExecutor(agent, tools=[], agent_kwargs={"system_message": user_input})
    return executor


def vulnerable_autogen_user_system_message():
    """User-controlled system_message in AutoGen AssistantAgent lets the
    caller redefine the agent's purpose."""
    from autogen import AssistantAgent
    user_input = input("Describe the assistant: ")
    agent = AssistantAgent(name="assistant", system_message=user_input)
    return agent


def vulnerable_crewai_user_goal():
    """User-controlled goal in CrewAI Agent redirects the agent to
    perform arbitrary tasks."""
    from crewai import Agent
    user_goal = input("Enter agent goal: ")
    agent = Agent(goal=user_goal, role="researcher", backstory="A researcher.")
    return agent


def vulnerable_openai_assistant_user_instructions():
    """User-controlled instructions in OpenAI Assistants API enables
    complete goal hijacking."""
    from openai import OpenAI
    client = OpenAI()
    user_instructions = input("Enter assistant instructions: ")
    assistant = client.beta.assistants.create(instructions=user_instructions, model="gpt-4")
    return assistant


def vulnerable_agent_goal_from_url():
    """Agent goal fetched from an external URL that could be compromised
    or supply a malicious payload."""
    import requests
    from crewai import Agent
    goal_url = "https://config.example.com/agent-goal"
    goal = requests.get(goal_url).text
    agent = Agent(role="worker", goal=goal, backstory="A diligent worker.")
    return agent


def vulnerable_agent_dynamic_instruction_update():
    """Agent instructions modified at runtime, enabling post-init goal
    hijacking."""
    from crewai import Agent
    agent = Agent(role="writer", goal="Write articles", backstory="A writer.")
    new_instructions = input("Update instructions: ")
    agent.instructions = new_instructions
    return agent


def vulnerable_agent_goal_string_concat():
    """Agent goal built via unsanitised string concatenation allows
    injection of malicious instructions."""
    from crewai import Agent
    topic = input("Enter topic: ")
    agent = Agent(role="researcher", goal="Research about " + topic + " and summarise findings.", backstory="Researcher.")
    return agent


def vulnerable_anthropic_agent_user_system():
    """User-controlled system prompt in Anthropic API call used for
    agent behaviour can hijack the agent entirely."""
    import anthropic
    client = anthropic.Anthropic()
    user_system = input("Enter system prompt: ")
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        system=user_system,
        messages=[{"role": "user", "content": "Do your job."}],
        max_tokens=500
    )
    return response


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_hardcoded_system_message():
    """System message is a static, developer-controlled string."""
    from autogen import AssistantAgent
    agent = AssistantAgent(
        name="assistant",
        system_message="You are a helpful research assistant. Only answer questions about science."
    )
    return agent


def safe_goal_from_allowlist():
    """Validate the goal against an allowlist of approved objectives."""
    from crewai import Agent
    ALLOWED_GOALS = {
        "summarise": "Summarise the provided document.",
        "translate": "Translate the document to English.",
    }
    user_choice = input("Choose goal (summarise/translate): ")
    goal = ALLOWED_GOALS.get(user_choice)
    if goal is None:
        raise ValueError("Invalid goal choice")
    agent = Agent(role="worker", goal=goal, backstory="Worker.")
    return agent


def safe_instructions_locked_after_init():
    """Instructions set once at construction time and never mutated."""
    from crewai import Agent
    agent = Agent(
        role="writer",
        goal="Write SEO-optimised blog posts about technology.",
        backstory="An experienced tech blogger."
    )
    # No runtime mutation of agent.instructions
    return agent
