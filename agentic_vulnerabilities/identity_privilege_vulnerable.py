"""
Test cases for identity and privilege abuse vulnerabilities.
Targets rules in rules/agentic/identity_privilege.yml.
For security scanner testing only.
"""
import subprocess


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_agent_root_execution():
    """Agent executing commands with sudo/root privileges violates the
    principle of least privilege."""
    cmd = "sudo apt-get update"
    subprocess.run(["sudo", "apt-get", "update"])


def vulnerable_agent_root_popen():
    """Another variant: subprocess.Popen with sudo."""
    subprocess.Popen(["sudo", "rm", "-rf", "/tmp/cache"])


def vulnerable_shared_credentials():
    """Multiple agents sharing the same API key makes it impossible to
    audit which agent performed which action."""
    shared_key = "sk-shared-key-12345"
    agent1 = dict(name="researcher", api_key=shared_key)
    agent2 = dict(name="writer", api_key=shared_key)
    return agent1, agent2


def vulnerable_agent_admin_role():
    """Agent configured with an admin role has far more permissions than
    necessary for its task."""
    agent_config = {
        "name": "data-fetcher",
        "role": "admin",
        "tools": ["read_db", "write_db", "delete_db", "manage_users"],
    }
    return agent_config


def vulnerable_agent_wildcard_permissions():
    """Wildcard permissions grant the agent access to everything."""
    agent_config = {
        "name": "helper",
        "permissions": "*",
    }
    return agent_config


def vulnerable_agent_root_access_level():
    """access_level set to root gives the agent unrestricted system
    access."""
    agent_config = {
        "name": "deployer",
        "access_level": "root",
    }
    return agent_config


def vulnerable_agent_token_no_expiry():
    """JWT issued without an expiration claim remains valid forever if
    compromised."""
    import jwt
    payload = {"agent_id": "agent-001", "scope": "full"}
    secret = "my-jwt-secret"
    token = jwt.encode(payload, secret)
    return token


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_agent_least_privilege():
    """Agent configured with a minimal, scoped role."""
    agent_config = {
        "name": "data-fetcher",
        "role": "reader",
        "tools": ["read_db"],
    }
    return agent_config


def safe_unique_credentials():
    """Each agent receives its own dedicated API key."""
    agent1 = dict(name="researcher", api_key="sk-researcher-key-111")
    agent2 = dict(name="writer", api_key="sk-writer-key-222")
    return agent1, agent2


def safe_token_with_expiry():
    """JWT includes an expiration claim to limit the window of abuse."""
    import jwt
    import datetime
    payload = {
        "agent_id": "agent-001",
        "scope": "read-only",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    secret = "my-jwt-secret"
    token = jwt.encode(payload, secret, algorithm="HS256")
    return token


def safe_no_sudo():
    """Commands executed without elevated privileges."""
    subprocess.run(["ls", "-la", "/tmp/cache"], check=True)
