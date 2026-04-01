"""
Test cases for cascading failure vulnerabilities.
Targets rules in rules/agentic/cascading_failures.yml.
For security scanner testing only.
"""


# ---------------------------------------------------------------------------
# Vulnerable patterns
# ---------------------------------------------------------------------------

def vulnerable_chain_no_error_handler():
    """Sequential agent chain without try/except between steps -- a
    failure in agent1 propagates unchecked to agent2."""
    class MockAgent:
        def run(self, input_data):
            return f"processed: {input_data}"

    agent1 = MockAgent()
    agent2 = MockAgent()
    result1 = agent1.run("raw data")
    result2 = agent2.run(result1)
    return result2


def vulnerable_no_circuit_breaker():
    """Iterating over agents without a circuit breaker means repeated
    failures overwhelm the entire system."""
    class MockAgent:
        def __init__(self, name):
            self.name = name
        def run(self, task):
            return f"{self.name} done"

    agents = [MockAgent("a1"), MockAgent("a2"), MockAgent("a3")]
    for agent in agents:
        agent.run("process data")


def vulnerable_chain_no_timeout():
    """Agent-to-agent call without a timeout -- a hanging agent blocks
    the entire pipeline indefinitely."""
    class MockAgent:
        def run(self, data):
            import time
            time.sleep(9999)  # simulates a hanging agent
            return data

    agent = MockAgent()
    result = agent.run("important task")
    return result


def vulnerable_trust_chain_no_validation():
    """Downstream agent blindly trusts upstream output without verifying
    the format or content, propagating corrupted data."""
    class UpstreamAgent:
        def run(self, data):
            return data.upper()

    class DownstreamAgent:
        def run(self, data):
            return f"Final: {data}"

    upstream = UpstreamAgent()
    downstream = DownstreamAgent()
    result = upstream.run("task data")
    downstream.run(result)


def vulnerable_no_fallback_chain():
    """Agent chain without a fallback strategy -- if any agent fails the
    whole pipeline fails."""
    from langchain.schema.runnable import RunnableSequence

    agent1 = lambda x: x
    agent2 = lambda x: x
    agent3 = lambda x: x
    chain = agent1 | agent2 | agent3
    return chain


def vulnerable_error_propagation():
    """Raw exception details forwarded to a downstream agent may leak
    sensitive system information."""
    class NextAgent:
        def run(self, data):
            return data

    next_agent = NextAgent()
    try:
        raise RuntimeError("DB connection failed: host=db.internal password=s3cret")
    except Exception as e:
        next_agent.run(str(e))


def vulnerable_retry_no_limit():
    """Retry decorator without a max count causes infinite retries,
    amplifying failures across the system."""
    from tenacity import retry

    @retry()
    def call_agent():
        raise ConnectionError("Agent unreachable")

    call_agent()


# ---------------------------------------------------------------------------
# Safe patterns
# ---------------------------------------------------------------------------

def safe_chain_with_error_handling():
    """Each agent call wrapped in try/except with fallback logic."""
    class MockAgent:
        def run(self, data):
            return f"processed: {data}"

    agent1 = MockAgent()
    agent2 = MockAgent()

    try:
        result1 = agent1.run("raw data")
    except Exception:
        result1 = "default fallback data"

    try:
        result2 = agent2.run(result1)
    except Exception:
        result2 = "pipeline degraded gracefully"

    return result2


def safe_with_circuit_breaker():
    """Circuit breaker stops calling a failing agent after a threshold."""
    class CircuitBreaker:
        def __init__(self, max_failures=3):
            self.max_failures = max_failures
            self.failures = 0
            self.open = False

        def call(self, func, *args):
            if self.open:
                return "circuit open -- using fallback"
            try:
                result = func(*args)
                self.failures = 0
                return result
            except Exception:
                self.failures += 1
                if self.failures >= self.max_failures:
                    self.open = True
                return "fallback"

    breaker = CircuitBreaker(max_failures=3)
    return breaker


def safe_with_timeout():
    """Agent call wrapped in a timeout to prevent indefinite blocking."""
    import signal

    def timeout_handler(signum, frame):
        raise TimeoutError("Agent call timed out")

    class MockAgent:
        def run(self, data):
            return f"processed: {data}"

    agent = MockAgent()
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(30)  # 30-second timeout
    try:
        result = agent.run("task")
    finally:
        signal.alarm(0)
    return result
