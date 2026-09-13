"""
Soteria — Slack integration.

Sends real-time alerts for validated findings to a Slack channel.
Supports webhook-based notifications with rich formatting.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

log = logging.getLogger(__name__)


SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Info": "⚪",
}

SEVERITY_COLOR = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#eab308",
    "Low": "#16a34a",
    "Info": "#6b7280",
}


class SlackNotifier:
    """Send findings to Slack via incoming webhook."""

    def __init__(self, webhook_url: str, dashboard_url: str = ""):
        self.webhook_url = webhook_url
        self.dashboard_url = dashboard_url

    def _build_payload(self, finding, scan_url: str = "") -> dict:
        """Build Slack message payload for a finding."""
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        color = SEVERITY_COLOR.get(severity, "#6b7280")

        curl = finding.curl_command or "# no reproduction"
        description = (finding.description or "")[:500]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {severity}: {finding.title}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{finding.type}"},
                    {"type": "mrkdwn", "text": f"*Endpoint:*\n`{finding.url}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Verified:*\n{'✅ Yes' if finding.verified else '⏳ Pending'}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reproduction:*\n```{curl[:1500]}```",
                },
            },
        ]

        # Add action buttons
        actions = []
        if scan_url:
            actions.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "View Report"},
                "url": scan_url,
                "style": "primary",
            })
        if self.dashboard_url:
            actions.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "Open Dashboard"},
                "url": self.dashboard_url,
            })

        if actions:
            blocks.append({"type": "actions", "elements": actions})

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Soteria • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                }
            ],
        })

        return {
            "text": f"{emoji} {severity} finding: {finding.title}",
            "attachments": [{"color": color, "blocks": blocks}],
        }

    def send(self, finding, scan_url: str = "") -> bool:
        """Send a finding to Slack. Returns True on success."""
        try:
            payload = self._build_payload(finding, scan_url)
            with httpx.Client(timeout=15) as client:
                resp = client.post(
                    self.webhook_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    log.info("Slack alert sent: %s", finding.title)
                    return True
                log.warning("Slack returned %s: %s", resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            log.warning("Slack send failed: %s", e)
            return False

    def send_summary(self, org_name: str, findings: list) -> bool:
        """Send a summary of findings (end of scan)."""
        counts = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        lines = [f"*{k}:* {v}" for k, v in counts.items()]
        summary_text = "\n".join(lines) if lines else "No findings"

        try:
            payload = {
                "text": f"Soteria scan complete for {org_name}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"✅ Scan Complete — {org_name}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Findings:*\n{summary_text}",
                        },
                    },
                ],
            }
            with httpx.Client(timeout=15) as client:
                resp = client.post(
                    self.webhook_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                return resp.status_code == 200
        except Exception as e:
            log.warning("Slack summary failed: %s", e)
            return False


def send_finding_to_slack(finding, webhook_url: str, scan_url: str = "") -> bool:
    """Convenience function for scanner integration."""
    notifier = SlackNotifier(webhook_url)
    return notifier.send(finding, scan_url)
