"""
Vulnerable Python code with command injection flaws.
For security scanner testing only.
"""
import os
import subprocess


def ping_host_vulnerable(hostname):
    """Command injection via os.system."""
    os.system(f"ping -c 4 {hostname}")


def execute_command_vulnerable(cmd):
    """Command injection via subprocess with shell=True."""
    subprocess.call(cmd, shell=True)


def run_script_vulnerable(script_name):
    """Command injection via subprocess.run with shell=True."""
    subprocess.run(f"python {script_name}", shell=True)


def check_file_vulnerable(filename):
    """Command injection via os.popen."""
    result = os.popen(f"ls -la {filename}").read()
    return result


def process_file_vulnerable(filepath):
    """Command injection via subprocess.Popen."""
    subprocess.Popen(f"cat {filepath}", shell=True, stdout=subprocess.PIPE)


def eval_vulnerable(user_code):
    """Arbitrary code execution via eval."""
    result = eval(user_code)
    return result


def exec_vulnerable(user_code):
    """Arbitrary code execution via exec."""
    exec(user_code)


def ping_host_safe(hostname):
    """Safe version using argument list."""
    subprocess.run(['ping', '-c', '4', hostname], check=True)


def run_command_safe(filename):
    """Safe version with proper argument passing."""
    subprocess.run(['ls', '-la', filename], check=True)
