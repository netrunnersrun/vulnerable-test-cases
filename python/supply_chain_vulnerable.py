"""
Test cases for supply chain vulnerabilities.
Targets rules in rules/traditional/supply_chain.yml.
For security scanner testing only.
"""
import os
import subprocess
import pickle
import importlib
import yaml


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_pickle_load_file():
    """pickle.load on untrusted data allows arbitrary code execution during
    deserialization."""
    with open("user_upload.pkl", "rb") as f:
        data = pickle.load(f)
    return data


def vulnerable_pickle_loads_bytes():
    """pickle.loads on raw bytes from an external source enables RCE."""
    raw = b"\x80\x04\x95..."  # attacker-controlled bytes
    obj = pickle.loads(raw)
    return obj


def vulnerable_importlib_user_input():
    """Dynamic import with user-controlled module name can load malicious
    packages from the Python path."""
    module_name = input("Enter module name: ")
    mod = importlib.import_module(module_name)
    return mod


def vulnerable_runtime_pip_os_system():
    """Installing packages at runtime with os.system allows supply chain
    attacks via typosquatting or dependency confusion."""
    package = "some-untrusted-package"
    os.system("pip install " + package)


def vulnerable_runtime_pip_subprocess():
    """subprocess.run pip install at runtime is equally dangerous."""
    pkg = "malicious-pkg"
    subprocess.run(["pip", "install", pkg])


def vulnerable_yaml_load_no_safeloader():
    """yaml.load without SafeLoader allows arbitrary Python object
    instantiation through YAML deserialization."""
    with open("config.yaml") as f:
        config = yaml.load(f)
    return config


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_json_serialization():
    """Use JSON instead of pickle for safe serialization."""
    import json
    with open("data.json") as f:
        data = json.load(f)
    return data


def safe_importlib_allowlist():
    """Validate module name against an allowlist before importing."""
    ALLOWED_MODULES = {"math", "statistics", "json"}
    module_name = input("Enter module name: ")
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module '{module_name}' is not allowed")
    mod = importlib.import_module(module_name)
    return mod


def safe_yaml_safe_load():
    """Use yaml.safe_load to prevent arbitrary code execution."""
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    return config
