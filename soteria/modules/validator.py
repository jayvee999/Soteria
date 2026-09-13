import json, subprocess
from pathlib import Path
import httpx
from .. import database as db

KNOWLEDGE_BASE_PATH = Path.home() / ".soteria" / "validator_kb.json"


def load_knowledge_base():
    if KNOWLEDGE_BASE_PATH.exists():
        return json.loads(KNOWLEDGE_BASE_PATH.read_text())
    return []


def save_knowledge(entry):
    kb = load_knowledge_base()
    kb.append(entry)
    KNOWLEDGE_BASE_PATH.write_text(json.dumps(kb[-200:], indent=2))


def execute_curl(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr, r.returncode
    except Exception:
        return "TIMEOUT", -1


def ask_deepseek(prompt, api_key):
    resp = httpx.post(
        "https://api.deepseek.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": "deepseek-chat", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1},
        timeout=30
    )
    return resp.json()["choices"][0]["message"]["content"]


def validate_finding(finding: dict, deepseek_key: str) -> dict:
    curl_command = finding.get("curl_command", "")
    if not curl_command:
        return {"verdict": "INCONCLUSIVE", "confidence": 0, "reason": "No curl command"}

    resp_text, exit_code = execute_curl(curl_command)

    if "root:" in resp_text and "/bin/bash" in resp_text:
        return {"verdict": "REAL", "confidence": 98, "reason": "LFI confirmed - /etc/passwd exposed"}
    if "ami-id" in resp_text or "instance-id" in resp_text:
        return {"verdict": "REAL", "confidence": 98, "reason": "SSRF confirmed - AWS metadata exposed"}

    kb = load_knowledge_base()

    assistant = ask_deepseek(f"""You are presenting a security finding. Be honest.
Finding: {finding.get('description', '')}
Curl: {curl_command}
Response: {resp_text[:2000]}
Exit code: {exit_code}
1. What vulnerability? 2. Evidence? 3. Confidence 1-10. 4. What would prove you wrong?""", deepseek_key)

    critic = ask_deepseek(f"""You are a SKEPTIC. Destroy this finding.
Assistant's case: {assistant}
Known false positives: {json.dumps([e for e in kb if e.get('verdict') == 'FALSE_POSITIVE'][-5:], indent=2)}
1. Find EVERY assumption. 2. Why could it be wrong? 3. Alternative explanations.""", deepseek_key)

    judge_raw = ask_deepseek(f"""You are a JUDGE.
Assistant: {assistant}
Critic: {critic}
Return JSON: {{"verdict": "REAL"|"FALSE_POSITIVE"|"INCONCLUSIVE", "confidence":0-100, "reasoning":"..."}}""", deepseek_key)

    try:
        verdict = json.loads(judge_raw)
    except Exception:
        verdict = {"verdict": "INCONCLUSIVE", "confidence": 0, "reasoning": "JSON parse error"}

    save_knowledge({
        "finding_id": finding.get("finding_id", ""),
        "verdict": verdict["verdict"],
        "confidence": verdict["confidence"],
        "reasoning": verdict.get("reasoning", "")
    })

    if verdict["verdict"] == "REAL" and finding.get("finding_id"):
        db.finding_update_verification(finding["finding_id"], True, False)
    elif verdict["verdict"] == "FALSE_POSITIVE" and finding.get("finding_id"):
        db.finding_update_verification(finding["finding_id"], False, True)

    return verdict


def explain(result: dict) -> None:
    emoji = {"REAL": "✅", "FALSE_POSITIVE": "❌", "INCONCLUSIVE": "🟡"}
    print(f"\n{emoji.get(result['verdict'], '❓')} {result['verdict']} ({result.get('confidence', 0)}%)")
    print(f"   {result.get('reasoning', 'No reasoning provided')}")
