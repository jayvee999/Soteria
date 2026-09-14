"""
Soteria — Compliance framework mappings.

Maps vulnerability types to security controls across:
- SOC 2 Type II
- ISO 27001:2022
- PCI-DSS 4.0
- HIPAA
- GDPR
"""

FRAMEWORK_MAPPINGS = {
    # ── INJECTION ──
    "sqli": {
        "SOC2": ["CC6.1", "CC7.1"],
        "ISO27001": ["A.8.28", "A.8.26"],
        "PCIDSS": ["6.5.1", "6.2.4"],
        "HIPAA": ["164.312(a)(1)", "164.312(c)(1)"],
        "GDPR": ["Art.32"],
        "description": "SQL Injection",
    },
    "sql_injection": {
        "SOC2": ["CC6.1", "CC7.1"],
        "ISO27001": ["A.8.28", "A.8.26"],
        "PCIDSS": ["6.5.1", "6.2.4"],
        "HIPAA": ["164.312(a)(1)", "164.312(c)(1)"],
        "GDPR": ["Art.32"],
        "description": "SQL Injection",
    },
    "nosqli": {
        "SOC2": ["CC6.1", "CC7.1"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "NoSQL Injection",
    },
    "command_injection": {
        "SOC2": ["CC6.1", "CC7.1", "CC7.2"],
        "ISO27001": ["A.8.28", "A.8.7"],
        "PCIDSS": ["6.5.1", "6.2.4"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Command Injection / RCE",
    },
    "rce": {
        "SOC2": ["CC6.1", "CC7.2"],
        "ISO27001": ["A.8.28", "A.8.7"],
        "PCIDSS": ["6.5.1", "6.2.4"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Remote Code Execution",
    },

    # ── CROSS-SITE SCRIPTING ──
    "xss": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.7"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Cross-Site Scripting",
    },
    "stored_xss": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.7"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Stored Cross-Site Scripting",
    },
    "reflected_xss": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.7"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Reflected Cross-Site Scripting",
    },

    # ── ACCESS CONTROL ──
    "idor": {
        "SOC2": ["CC6.1", "CC6.3"],
        "ISO27001": ["A.5.15", "A.8.3"],
        "PCIDSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(4)"],
        "GDPR": ["Art.32"],
        "description": "Insecure Direct Object Reference",
    },
    "auth_bypass": {
        "SOC2": ["CC6.1", "CC6.2", "CC6.3"],
        "ISO27001": ["A.5.15", "A.5.17"],
        "PCIDSS": ["7.1", "8.3"],
        "HIPAA": ["164.308(a)(4)", "164.312(d)"],
        "GDPR": ["Art.32"],
        "description": "Authentication Bypass",
    },
    "broken_access": {
        "SOC2": ["CC6.1", "CC6.3"],
        "ISO27001": ["A.5.15"],
        "PCIDSS": ["7.1"],
        "HIPAA": ["164.308(a)(4)"],
        "GDPR": ["Art.32"],
        "description": "Broken Access Control",
    },
    "privilege_escalation": {
        "SOC2": ["CC6.1", "CC6.3"],
        "ISO27001": ["A.5.15", "A.8.2"],
        "PCIDSS": ["7.1", "7.2"],
        "HIPAA": ["164.308(a)(4)"],
        "GDPR": ["Art.32"],
        "description": "Privilege Escalation",
    },

    # ── DATA EXPOSURE ──
    "env_exposure": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.24", "A.5.33"],
        "PCIDSS": ["3.5", "3.6"],
        "HIPAA": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        "GDPR": ["Art.32"],
        "description": "Environment File Exposure",
    },
    "git_exposure": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.24", "A.5.33"],
        "PCIDSS": ["6.3.1", "3.5"],
        "HIPAA": ["164.312(a)(2)(iv)"],
        "GDPR": ["Art.32"],
        "description": "Git Repository Exposure",
    },
    "backup_exposure": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.13", "A.5.33"],
        "PCIDSS": ["3.5", "9.4"],
        "HIPAA": ["164.308(a)(7)", "164.312(c)(1)"],
        "GDPR": ["Art.32"],
        "description": "Backup File Exposure",
    },
    "pii_exposure": {
        "SOC2": ["CC6.1", "CC6.6", "P4"],
        "ISO27001": ["A.5.34", "A.8.11"],
        "PCIDSS": ["3.4", "3.5"],
        "HIPAA": ["164.312(a)(1)", "164.502"],
        "GDPR": ["Art.5", "Art.32"],
        "description": "PII / Personal Data Exposure",
    },
    "credentials_exposure": {
        "SOC2": ["CC6.1", "CC6.2"],
        "ISO27001": ["A.5.17", "A.8.24"],
        "PCIDSS": ["8.3", "3.5"],
        "HIPAA": ["164.308(a)(5)", "164.312(d)"],
        "GDPR": ["Art.32"],
        "description": "Credential Exposure",
    },
    "info_disclosure": {
        "SOC2": ["CC6.6"],
        "ISO27001": ["A.5.33", "A.8.12"],
        "PCIDSS": ["6.3.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Information Disclosure",
    },
    "debug_exposure": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.31"],
        "PCIDSS": ["6.3.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Debug / Admin Interface Exposure",
    },

    # ── SERVER-SIDE ──
    "ssrf": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.28", "A.8.20"],
        "PCIDSS": ["6.5.1", "6.2.4"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Server-Side Request Forgery",
    },
    "xxe": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "XML External Entity Injection",
    },
    "ssti": {
        "SOC2": ["CC6.1", "CC7.2"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Server-Side Template Injection",
    },
    "deserialization": {
        "SOC2": ["CC6.1", "CC7.2"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Insecure Deserialization",
    },

    # ── CONFIGURATION ──
    "cors": {
        "SOC2": ["CC6.1", "CC6.6"],
        "ISO27001": ["A.8.20"],
        "PCIDSS": ["6.5.8"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "CORS Misconfiguration",
    },
    "misconfiguration": {
        "SOC2": ["CC6.1", "CC7.1"],
        "ISO27001": ["A.8.9", "A.8.20"],
        "PCIDSS": ["2.2"],
        "HIPAA": ["164.308(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Security Misconfiguration",
    },
    "open_redirect": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Open Redirect",
    },
    "csrf": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.9"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Cross-Site Request Forgery",
    },

    # ── CRYPTO / TRANSPORT ──
    "weak_tls": {
        "SOC2": ["CC6.7"],
        "ISO27001": ["A.8.24"],
        "PCIDSS": ["4.2.1"],
        "HIPAA": ["164.312(e)(1)"],
        "GDPR": ["Art.32"],
        "description": "Weak TLS Configuration",
    },
    "missing_headers": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.20"],
        "PCIDSS": ["6.4.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": [],
        "description": "Missing Security Headers",
    },

    # ── FALLBACK ──
    "unknown": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.8.28"],
        "PCIDSS": ["6.5.1"],
        "HIPAA": ["164.312(a)(1)"],
        "GDPR": ["Art.32"],
        "description": "Unclassified Finding",
    },
}


FRAMEWORK_NAMES = {
    "SOC2": "SOC 2 Type II",
    "ISO27001": "ISO 27001:2022",
    "PCIDSS": "PCI-DSS 4.0",
    "HIPAA": "HIPAA Security Rule",
    "GDPR": "GDPR",
}


def get_controls(finding_type: str) -> dict:
    """Lookup controls for a finding type. Falls back to 'unknown'."""
    key = (finding_type or "").lower().replace(" ", "_").replace("-", "_")
    mapping = FRAMEWORK_MAPPINGS.get(key) or FRAMEWORK_MAPPINGS["unknown"]
    return {
        "type": key,
        "description": mapping.get("description", ""),
        "frameworks": {
            fw: mapping[fw]
            for fw in ["SOC2", "ISO27001", "PCIDSS", "HIPAA", "GDPR"]
            if fw in mapping and mapping[fw]
        },
    }


def list_frameworks() -> list:
    """List all supported frameworks."""
    return [
        {"id": k, "name": v}
        for k, v in FRAMEWORK_NAMES.items()
    ]
