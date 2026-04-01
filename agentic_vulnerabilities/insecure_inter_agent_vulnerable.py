"""
Test cases for insecure inter-agent communication vulnerabilities.
Targets rules in rules/agentic/insecure_inter_agent.yml.
For security scanner testing only.
"""
import requests


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_http_no_tls():
    """Agent-to-agent communication over plain HTTP allows interception
    and modification of messages in transit."""
    response = requests.get("http://agent-service.internal:8080/task")
    return response.json()


def vulnerable_http_post_no_tls():
    """POST variant -- sending task payloads over unencrypted HTTP."""
    data = {"task": "summarise", "document_id": "doc-123"}
    response = requests.post("http://agent-service.internal:8080/run", json=data)
    return response.json()


def vulnerable_message_no_auth():
    """Inter-agent message sent without authentication token or API key,
    allowing message injection by any network participant."""
    url = "https://agent-b.internal/inbox"
    msg = {"from": "agent-a", "content": "Process the next batch."}
    requests.post(url, json={"message": msg})


def vulnerable_message_no_signature():
    """Agent message sent without HMAC or digital signature -- the
    recipient cannot verify message integrity."""
    class MockAgent:
        def send_message(self, target, msg):
            pass

    agent = MockAgent()
    agent.send_message("agent-b", "Transfer $10,000 to account XYZ")


def vulnerable_autogen_groupchat_no_auth():
    """AutoGen GroupChat without inter-agent authentication allows any
    process to impersonate a group member."""
    from autogen import GroupChat, AssistantAgent

    researcher = AssistantAgent(name="researcher", system_message="Research.")
    writer = AssistantAgent(name="writer", system_message="Write.")
    chat = GroupChat(agents=[researcher, writer], messages=[])
    return chat


def vulnerable_crewai_crew_no_auth():
    """CrewAI Crew without message authentication between agents."""
    from crewai import Agent, Task, Crew

    researcher = Agent(role="researcher", goal="Research", backstory="R")
    writer = Agent(role="writer", goal="Write", backstory="W")
    task1 = Task(description="Research topic", agent=researcher)
    task2 = Task(description="Write article", agent=writer)
    crew = Crew(agents=[researcher, writer], tasks=[task1, task2])
    return crew


def vulnerable_broadcast_no_acl():
    """Broadcasting messages to all agents without an ACL leaks data
    to agents that should not receive it."""
    class MockAgent:
        def broadcast(self, msg):
            pass

    agent = MockAgent()
    agent.broadcast("Secret internal pricing data: $42.50/unit")


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_https_with_tls():
    """All inter-agent communication over HTTPS with TLS."""
    response = requests.get("https://agent-service.internal:8443/task",
                            verify=True)
    return response.json()


def safe_message_with_auth():
    """Inter-agent message includes an authentication token."""
    url = "https://agent-b.internal/inbox"
    headers = {"Authorization": "Bearer agent-a-token-xyz"}
    msg = {"from": "agent-a", "content": "Process the next batch."}
    requests.post(url, json={"message": msg}, headers=headers)


def safe_message_with_hmac():
    """Sign inter-agent messages with HMAC for integrity verification."""
    import hmac
    import hashlib
    import json

    secret = b"inter-agent-shared-secret"
    msg = {"from": "agent-a", "content": "Process the next batch."}
    raw = json.dumps(msg).encode()
    signature = hmac.new(secret, raw, hashlib.sha256).hexdigest()

    url = "https://agent-b.internal/inbox"
    headers = {"X-Message-Signature": signature, "Authorization": "Bearer token"}
    requests.post(url, json={"message": msg}, headers=headers)
