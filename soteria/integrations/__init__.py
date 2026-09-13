"""Soteria integrations — Slack, Teams, webhooks."""
from .slack import SlackNotifier, send_finding_to_slack

__all__ = ["SlackNotifier", "send_finding_to_slack"]
