"""
Test cases for tool misuse and exploitation vulnerabilities.
Targets rules in rules/agentic/tool_misuse.yml.
For security scanner testing only.
"""
import json


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_shell_tool():
    """ShellTool gives the agent direct, unrestricted shell access."""
    from langchain.tools import ShellTool
    shell = ShellTool()
    return shell


def vulnerable_bash_process():
    """BashProcess provides unrestricted bash access identical to
    ShellTool."""
    from langchain_experimental.tools import BashProcess
    bash = BashProcess()
    return bash


def vulnerable_tool_no_validation():
    """LangChain tool that performs file reads without any input
    validation or path sanitisation."""
    from langchain.tools import tool

    @tool
    def read_file(filepath):
        """Read a file from disk."""
        with open(filepath) as f:
            return f.read()

    return read_file


def vulnerable_file_tool_no_sandbox():
    """FileSystemToolkit without path restrictions allows the agent to
    read, write, or delete arbitrary files."""
    from langchain_community.agent_toolkits import FileSystemToolkit
    toolkit = FileSystemToolkit(root_dir="/")
    return toolkit


def vulnerable_sql_tool_readwrite():
    """SQL database toolkit with a read-write connection enables the
    agent to modify or drop tables."""
    from langchain_community.agent_toolkits import SQLDatabaseToolkit
    from langchain_community.utilities import SQLDatabase
    db = SQLDatabase.from_uri("sqlite:///production.db")
    toolkit = SQLDatabaseToolkit(llm=None, db=db)
    return toolkit


def vulnerable_openai_function_no_param_check():
    """OpenAI function-call arguments passed directly to a function
    without any parameter validation."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Delete the temp files."}],
        functions=[{"name": "delete_files", "parameters": {}}]
    )
    result = json.loads(response.choices[0].message.function_call.arguments)
    delete_files(**result)


def vulnerable_crewai_tool_no_permission():
    """CrewAI custom tool without any permission or access control
    checks."""
    from crewai.tools import BaseTool

    class DangerousTool(BaseTool):
        name = "dangerous_tool"
        description = "Performs dangerous operations"

        def _run(self, command):
            import subprocess
            return subprocess.check_output(command, shell=True).decode()


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_tool_with_validation():
    """LangChain tool that validates its input against an allowlist
    before executing."""
    from langchain.tools import tool
    import os

    ALLOWED_DIR = "/data/public"

    @tool
    def read_file(filepath):
        """Read a file from the public data directory."""
        if not filepath:
            raise ValueError("filepath is required")
        abs_path = os.path.abspath(filepath)
        if not abs_path.startswith(ALLOWED_DIR):
            raise ValueError("Access denied: path is outside the allowed directory")
        with open(abs_path) as f:
            return f.read()

    return read_file


def safe_sql_tool_readonly():
    """Use a read-only database connection for the agent's SQL toolkit."""
    from langchain_community.agent_toolkits import SQLDatabaseToolkit
    from langchain_community.utilities import SQLDatabase
    # Read-only connection string
    db = SQLDatabase.from_uri("sqlite:///production.db?mode=ro")
    toolkit = SQLDatabaseToolkit(llm=None, db=db)
    return toolkit


def safe_function_call_with_schema_validation():
    """Validate LLM-generated function call arguments against a schema
    before execution."""
    from openai import OpenAI
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "List files in /data."}],
        functions=[{"name": "list_files", "parameters": {"type": "object", "properties": {"directory": {"type": "string"}}}}]
    )
    raw = json.loads(response.choices[0].message.function_call.arguments)
    # Validate
    allowed_dirs = {"/data", "/data/public"}
    if raw.get("directory") not in allowed_dirs:
        raise ValueError("Directory not allowed")
    list_files(**raw)
