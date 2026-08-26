import json, logging, time
from typing import Any, Dict, List, Optional
import httpx
from .models import AIResponse

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are Keres AI, embedded in a professional bug bounty hunting tool.
STRICT RULES:
- Never suggest testing out-of-scope targets.
- Never recommend any illegal action.
- Flag findings needing human verification with [VERIFY].
- Output is terse, technical, command-focused.
- No bounty amounts. No program names.
- Curl commands preferred over theory."""


class AIEngine:
    def __init__(self, cfg_dict: Dict[str, Any]):
        self._backends = []
        if cfg_dict.get("deepseek_key"):
            self._backends.append({
                "name": "deepseek",
                "key": cfg_dict["deepseek_key"],
                "model": cfg_dict.get("deepseek_model", "deepseek-chat"),
                "url": "https://api.deepseek.com/v1/chat/completions"
            })
        if cfg_dict.get("groq_key"):
            self._backends.append({
                "name": "groq",
                "key": cfg_dict["groq_key"],
                "model": cfg_dict.get("groq_model", "llama3-70b-8192"),
                "url": "https://api.groq.com/openai/v1/chat/completions"
            })

    def available(self):
        return len(self._backends) > 0

    def complete(self, user_message, context=None, max_tokens=1024):
        messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
        if context:
            messages.extend(context)
        messages.append({"role": "user", "content": user_message})

        for backend in self._backends:
            try:
                start = time.monotonic()
                with httpx.Client(timeout=30) as client:
                    resp = client.post(
                        backend["url"],
                        headers={
                            "Authorization": f"Bearer {backend['key']}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": backend["model"],
                            "messages": messages,
                            "max_tokens": max_tokens,
                            "temperature": 0.3
                        }
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    tokens = data.get("usage", {}).get("total_tokens")
                    return AIResponse(
                        content=content,
                        model=backend["model"],
                        provider=backend["name"],
                        tokens_used=tokens,
                        latency_ms=(time.monotonic() - start) * 1000
                    )
            except Exception as e:
                log.warning("backend %s failed: %s", backend["name"], e)
        return None

    def analyze_response(self, url, method, status, headers, body_snippet, target_context=None):
        prompt = f"""Analyze this HTTP response for vulnerabilities.
URL: {url}
Method: {method}
Status: {status}
Headers: {json.dumps(headers, indent=2)}
Body (first 2000 chars):
{body_snippet[:2000]}
"""
        if target_context:
            prompt += f"""
ADDITIONAL CONTEXT (provided by operator):
{target_context}

Use this context to skip blocked tests, tailor payloads to tech stack, and consider auth type.
"""
        prompt += "\nList specific findings with curl PoC commands. Mark anything needing manual verification with [VERIFY]."
        return self.complete(prompt)

    def suggest_tests(self, endpoint, method, params):
        prompt = f"Generate specific test cases for:\n  Endpoint: {method} {endpoint}\n  Parameters: {', '.join(params) or 'none'}\n\nOutput: numbered list of curl commands with expected indicators."
        return self.complete(prompt)

    def adapt_blocked_tool(self, tool, block_type, original_command, target):
        prompt = f"Tool '{tool}' was blocked ({block_type}) on target: {target}\nOriginal command: {original_command}\n\nSuggest 2-3 alternative approaches using passive techniques or different endpoints."
        return self.complete(prompt)

    def generate_report_draft(self, finding_dict):
        prompt = f"Draft a concise bug bounty report:\n{json.dumps(finding_dict, indent=2, default=str)}\n\nFormat:\n## Title\n## Severity\n## CVSS\n## Description\n## Reproduction (curl)\n## Impact\n## Remediation\n\nNo bounty amounts."
        return self.complete(prompt, max_tokens=2048)
