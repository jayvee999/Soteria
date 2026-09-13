import json, logging
from pathlib import Path
from typing import Optional
from . import database as db
from .models import Finding, TrainingEntry

log = logging.getLogger(__name__)

_SEEDS = [
    {"instruction": "Detect IDOR", "input": "GET /api/v1/users/1042", "output": "1. Capture request.\n2. Increment ID: 1041,1043,0,-1.\n3. Different user data = IDOR.", "category": "idor", "source": "owasp"},
    {"instruction": "403 Bypass", "input": "GET /admin returns 403", "output": "curl /admin/ | curl /Admin | curl /ADMIN | curl -H 'X-Original-URL: /admin' /", "category": "403_bypass", "source": "owasp"},
    {"instruction": "Open Redirect", "input": "POST /login?next=/dashboard", "output": "curl '/login?next=https://evil.com' | Check Location header", "category": "open_redirect", "source": "owasp"},
    {"instruction": "Race Condition", "input": "POST /api/coupon/redeem", "output": "for i in {1..5}; do curl -X POST /api/coupon/redeem -d 'coupon=SAVE50' & done; wait", "category": "race", "source": "portswigger"},
    {"instruction": "Subdomain Recon", "input": "target.com", "output": "subfinder -d target.com | assetfinder --subs-only target.com | crt.sh", "category": "recon", "source": "owasp"},
    {"instruction": "WP User Enum", "input": "WordPress site", "output": "curl /wp-json/wp/v2/users", "category": "user_enum", "source": "h1"},
    {"instruction": "CORS", "input": "API endpoint", "output": "curl -H 'Origin: https://evil.com' /api | check ACAO header", "category": "cors", "source": "portswigger"},
    {"instruction": "SQLi", "input": "GET /products?id=42", "output": "curl '?id=42'' | curl '?id=42 AND 1=1' | curl '?id=42 AND 1=2'", "category": "sqli", "source": "owasp"},
    {"instruction": "Exposed .git", "input": "Web app", "output": "curl /.git/config | 200 = exposed", "category": "info_disc", "source": "owasp"},
    {"instruction": "JWT Attack", "input": "JWT auth", "output": "Decode JWT | Test alg:none | Test RS256->HS256", "category": "auth", "source": "portswigger"},
]


def seed_database():
    if db.training_count() > 0:
        return 0
    for item in _SEEDS:
        entry = TrainingEntry(
            instruction=item["instruction"],
            input=item["input"],
            output=item["output"],
            category=item.get("category"),
            source=item.get("source")
        )
        db.training_save(entry)
    return len(_SEEDS)


def record_from_finding(finding: Finding, verified: bool, false_positive: bool):
    if false_positive or not verified:
        return None
    steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(finding.reproduction_steps))
    output = f"Confirmed {finding.type}.\nReproduction:\n{steps}"
    if finding.curl_command:
        output += f"\n  curl: {finding.curl_command}"
    entry = TrainingEntry(
        instruction=f"Detect and exploit {finding.type}",
        input=f"Endpoint: {finding.url}\n{finding.description[:200]}",
        output=output,
        category=finding.type.lower(),
        source="operator_verified"
    )
    return db.training_save(entry)


def export_jsonl(output_path: Path, category: Optional[str] = None):
    entries = db.training_list(category=category)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        for entry in entries:
            f.write(json.dumps({
                "instruction": entry.instruction,
                "input": entry.input,
                "output": entry.output
            }, ensure_ascii=False) + "\n")
    return len(entries)
