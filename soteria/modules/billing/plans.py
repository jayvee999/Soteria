"""
Soteria — Pricing plans with detailed value matrix.
"""

TRIAL_DAYS = 30


PLANS = {
    "standard": {
        "name": "Standard",
        "price_usd": 2000,
        "interval": "monthly",
        "description": "Continuous protection for growing teams",
        "target": "Series A/B startups, 50-200 employees",
        "limits": {
            "domains": 10,
            "scans_per_day": 4,
            "team_members": 5,
            "historical_data_days": 90,
        },
        "features": [
            "Up to 10 external domains",
            "Continuous scanning (4x daily)",
            "Adversarial AI validation",
            "Slack alerts for verified findings",
            "Weekly executive PDF report",
            "Monthly 30-min review call",
            "Email support (48h response)",
        ],
        "integrations": ["Slack", "Email"],
        "support": {
            "channel": "Email",
            "response_time_hours": 48,
            "review_calls": "Monthly",
        },
        "sla": {
            "uptime": "99%",
            "response_to_critical": "24h",
        },
    },
    "premium": {
        "name": "Premium",
        "price_usd": 5000,
        "interval": "monthly",
        "description": "Advanced continuous testing with priority support",
        "target": "Series B/C companies, 200-500 employees",
        "limits": {
            "domains": 25,
            "scans_per_day": 12,
            "team_members": 20,
            "historical_data_days": 365,
        },
        "features": [
            "Up to 25 external domains",
            "Continuous scanning (12x daily)",
            "Adversarial AI validation",
            "Slack + Jira alerts with auto-ticketing",
            "Weekly executive PDF report",
            "Compliance mapping (SOC 2, ISO 27001, PCI-DSS)",
            "Bi-weekly 60-min review calls",
            "Priority email + Slack support (12h response)",
            "CI/CD integration (GitHub, GitLab)",
        ],
        "integrations": ["Slack", "Jira", "GitHub", "GitLab", "Email"],
        "support": {
            "channel": "Email + Slack",
            "response_time_hours": 12,
            "review_calls": "Bi-weekly",
        },
        "sla": {
            "uptime": "99.5%",
            "response_to_critical": "4h",
        },
    },
    "enterprise": {
        "name": "Enterprise",
        "price_usd": 10000,
        "interval": "monthly",
        "description": "Custom enterprise-grade protection",
        "target": "500+ employees, regulated industries",
        "limits": {
            "domains": -1,
            "scans_per_day": -1,
            "team_members": -1,
            "historical_data_days": -1,
        },
        "features": [
            "Unlimited external domains",
            "Continuous scanning (unlimited frequency)",
            "Adversarial AI validation",
            "All integrations (Slack, Jira, Teams, PagerDuty)",
            "Custom report branding + cadence",
            "Full compliance suite (SOC 2, ISO, PCI, HIPAA, GDPR)",
            "Weekly executive + technical reports",
            "Weekly 60-min review calls",
            "Dedicated Customer Success Manager",
            "24/7 support with 1h response",
            "Custom SLA",
            "On-premise deployment option",
            "Security questionnaire support",
            "Quarterly business reviews (QBRs)",
        ],
        "integrations": ["Slack", "Jira", "Teams", "GitHub", "GitLab", "PagerDuty", "ServiceNow", "Custom API"],
        "support": {
            "channel": "Email + Slack + Phone",
            "response_time_hours": 1,
            "review_calls": "Weekly",
            "dedicated_csm": True,
        },
        "sla": {
            "uptime": "99.9%",
            "response_to_critical": "1h",
        },
    },
}


def get_plan(plan_id: str) -> dict:
    return PLANS.get(plan_id.lower())


def list_plans() -> list:
    result = []
    for plan_id, data in PLANS.items():
        result.append({"id": plan_id, **data})
    return result
