# Vulnerable Test Cases

Intentionally vulnerable code samples for validating SAST scanner detection capabilities across traditional, AI/LLM, and agentic vulnerability categories.

## Structure

```
├── python/                      # Python vulnerable patterns
├── javascript/                  # JavaScript vulnerable patterns
├── php/                         # PHP vulnerable patterns
├── go/                          # Go vulnerable patterns
├── java/                        # Java vulnerable patterns
├── ai_vulnerabilities/          # OWASP LLM Top 10 (2025)
├── agentic_vulnerabilities/     # OWASP Agentic Top 10 (2026)
└── false_positives/             # Safe code that should NOT trigger alerts
```

## Traditional Vulnerabilities

| Vulnerability | Python | JavaScript | PHP | Go | Java |
|---|---|---|---|---|---|
| SQL Injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| Cross-Site Scripting (XSS) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Command Injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| Error Handling | ✓ | ✓ | ✓ | ✓ | ✓ |
| Security Misconfiguration | ✓ | ✓ | ✓ | ✓ | ✓ |
| Path Traversal | | | ✓ | ✓ | ✓ |
| SSRF | | | ✓ | ✓ | ✓ |
| XXE | | | ✓ | | |
| Crypto Misuse | | | ✓ | ✓ | |
| Deserialization | | | ✓ | | ✓ |
| Supply Chain | ✓ | | | | |

## AI/LLM Vulnerabilities (OWASP LLM Top 10 2025)

| Vulnerability | File |
|---|---|
| Prompt Injection | `prompt_injection_vulnerable.py` |
| LLM API Misuse | `llm_api_misuse_vulnerable.py` |
| RAG Security | `rag_security_vulnerable.py` |
| Model Output Validation | `model_output_vulnerable.py` |
| Sensitive Info Disclosure | `sensitive_info_disclosure_vulnerable.py` |
| Data/Model Poisoning | `data_model_poisoning_vulnerable.py` |
| System Prompt Leakage | `system_prompt_leakage_vulnerable.py` |
| Misinformation Guardrails | `misinformation_guardrails_vulnerable.py` |
| Unbounded Consumption | `unbounded_consumption_vulnerable.py` |

## Agentic Vulnerabilities (OWASP Agentic Top 10 2026)

| Vulnerability | File |
|---|---|
| Agent Goal Hijack | `agent_goal_hijack_vulnerable.py` |
| Tool Misuse | `tool_misuse_vulnerable.py` |
| Identity & Privilege Abuse | `identity_privilege_vulnerable.py` |
| Cascading Failures | `cascading_failures_vulnerable.py` |
| Unexpected Code Execution | `unexpected_code_execution_vulnerable.py` |
| Memory/Context Poisoning | `memory_context_poisoning_vulnerable.py` |
| Insecure Inter-Agent Comms | `insecure_inter_agent_vulnerable.py` |
| Rogue Agents | `rogue_agents_vulnerable.py` |
| Trust Exploitation | `trust_exploitation_vulnerable.py` |
| Agentic Supply Chain | `agentic_supply_chain_vulnerable.py` |

## False Positives

The `false_positives/` directory contains **safe code** that uses security-sensitive APIs correctly. A good scanner should NOT flag these. Useful for measuring false positive rates.

## Usage

These files are scanned automatically by [Mantis SAST](https://mantiseu.com) via GitHub Actions on every push.
