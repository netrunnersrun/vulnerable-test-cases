"""
Test cases for agentic supply chain vulnerabilities.
Targets rules in rules/agentic/agentic_supply_chain.yml.
For security scanner testing only.
"""
import importlib
import subprocess


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_unverified_plugin():
    """Loading an agent plugin without hash or signature verification
    allows execution of tampered code."""
    plugin_path = "/plugins/user_uploaded_plugin.py"
    plugin = load_plugin(plugin_path)
    return plugin


def vulnerable_dynamic_tool_import():
    """importlib.import_module with a user-controlled tool name can load
    arbitrary malicious modules."""
    tool_name = input("Enter tool module name: ")
    tool_module = importlib.import_module(tool_name)
    return tool_module


def vulnerable_langchain_hub_pull_untrusted():
    """Pulling from LangChain Hub with user-controlled input can load
    malicious prompt templates or chains."""
    from langchain import hub
    user_ref = input("Enter hub reference: ")
    prompt = hub.pull(user_ref)
    return prompt


def vulnerable_agent_pip_install_runtime():
    """Installing Python packages at runtime inside an agent introduces
    severe supply chain risk."""
    package = "some-user-requested-package"
    subprocess.run(["pip", "install", package])


def vulnerable_agent_model_from_user_input():
    """Loading a model from a user-specified source can introduce
    backdoored or poisoned weights."""
    from transformers import AutoModel
    user_model = input("Enter model identifier: ")
    model = AutoModel.from_pretrained(user_model)
    return model


def vulnerable_agent_config_from_url():
    """Agent configuration fetched from a remote URL without validation
    or schema enforcement can redefine agent behaviour."""
    import requests
    from crewai import Agent
    config_url = "https://remote-config.example.com/agent.json"
    config = requests.get(config_url).json()
    agent = Agent(**config)
    return agent


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_plugin_with_signature_check():
    """Verify plugin integrity via a cryptographic signature before
    loading."""
    import hashlib
    plugin_path = "/plugins/verified_plugin.py"
    expected_hash = "a1b2c3d4e5f6..."
    with open(plugin_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError("Plugin integrity check failed")
    plugin = load_plugin(plugin_path)
    return plugin


def safe_tool_import_from_allowlist():
    """Import tool modules only from a static allowlist."""
    ALLOWED_TOOLS = {"tools.search", "tools.calculator", "tools.weather"}
    tool_name = input("Enter tool module name: ")
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(f"Tool '{tool_name}' is not in the trusted allowlist")
    tool_module = importlib.import_module(tool_name)
    return tool_module


def safe_model_from_allowlist():
    """Validate model identifiers against a trusted allowlist."""
    from transformers import AutoModel
    ALLOWED_MODELS = {"bert-base-uncased", "distilbert-base-uncased"}
    model_name = input("Enter model: ")
    if model_name not in ALLOWED_MODELS:
        raise ValueError("Model not allowed")
    model = AutoModel.from_pretrained(model_name)
    return model
