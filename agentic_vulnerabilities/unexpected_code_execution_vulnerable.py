"""
Test cases for unexpected code execution (RCE) vulnerabilities.
Targets rules in rules/agentic/unexpected_code_execution.yml.
For security scanner testing only.
"""
import os
import subprocess


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_eval_llm_output():
    """eval() on LLM-generated code allows arbitrary code execution.
    An attacker can manipulate the LLM via prompt injection to produce
    malicious payloads."""
    from langchain.llms import OpenAI
    llm = OpenAI()
    result = llm.invoke("Write a Python expression that calculates 2+2")
    answer = eval(result)
    return answer


def vulnerable_exec_llm_output():
    """exec() on LLM-generated code provides full arbitrary code
    execution including imports and system calls."""
    from langchain.llms import OpenAI
    llm = OpenAI()
    result = llm.invoke("Write Python code to list files in /tmp")
    exec(result)


def vulnerable_python_repl_tool():
    """PythonREPLTool grants the agent unrestricted Python execution,
    including file system access and network operations."""
    from langchain_experimental.tools import PythonREPLTool
    repl = PythonREPLTool()
    return repl


def vulnerable_compile_exec():
    """compile() followed by exec() on dynamically generated code is
    functionally equivalent to eval/exec on raw strings."""
    from langchain.llms import OpenAI
    llm = OpenAI()
    source = llm.invoke("Generate code to process data")
    code_obj = compile(source, "<llm>", "exec")
    exec(code_obj)


def vulnerable_subprocess_shell_true():
    """subprocess.run with shell=True and an LLM-influenced command
    enables command injection."""
    cmd = "ls -la /tmp"  # could be LLM-generated
    subprocess.run(cmd, shell=True)


def vulnerable_os_system():
    """os.system() invokes a shell and is vulnerable to command injection
    when the command string comes from untrusted sources."""
    cmd = "echo hello"  # could be LLM-generated
    os.system(cmd)


def vulnerable_exec_raw_code():
    """exec() on code without any sandboxing -- if this is an agent's
    code interpreter, it has full system access."""
    code = "import os; os.listdir('/')"
    exec(code)


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_sandboxed_execution():
    """Execute LLM-generated code inside a restricted sandbox."""
    from RestrictedPython import compile_restricted, safe_globals
    code = "result = 2 + 2"
    byte_code = compile_restricted(code, "<llm>", "exec")
    restricted_globals = safe_globals.copy()
    exec(byte_code, restricted_globals)
    return restricted_globals.get("result")


def safe_ast_analysis_before_exec():
    """Parse the code with ast to detect dangerous operations before
    executing."""
    import ast
    code = "result = 2 + 2"
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ValueError("Imports not allowed in generated code")
    exec(compile(tree, "<llm>", "exec"))


def safe_subprocess_no_shell():
    """subprocess.run with shell=False and explicit argument list
    prevents command injection."""
    subprocess.run(["ls", "-la", "/tmp"], check=True)
