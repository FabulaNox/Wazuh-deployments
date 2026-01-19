#!/usr/bin/env python3
#
# Wazuh Slack Integration
# Sends alert notifications to Slack via Bot API
#
# Install to: /var/ossec/integrations/custom-slack.py
#
# Configuration is read from /var/ossec/etc/slack.conf
# which can be updated dynamically via the slack-bot-listener
#

import sys
import os
import json
import requests
from datetime import datetime

CONFIG_FILE = "/var/ossec/etc/slack.conf"
CREDENTIALS_FILE = "/var/ossec/etc/slack-credentials.conf"


def load_config():
    """Load configuration from file"""
    default_config = {
        "level": 7,
        "muted": False,
        "muted_until": None
    }

    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Check mute expiration
                if config.get("muted") and config.get("muted_until"):
                    if datetime.now().timestamp() > config["muted_until"]:
                        config["muted"] = False
                return config
    except Exception:
        pass

    return default_config


def load_credentials():
    """Load credentials from file"""
    try:
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def build_slack_blocks(alert, level, severity, emoji):
    """Build Slack Block Kit message"""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    description = rule.get("description", "No description")
    rule_id = rule.get("id", "N/A")
    groups = ", ".join(rule.get("groups", [])) or "N/A"

    agent_name = agent.get("name", "N/A")
    agent_ip = agent.get("ip", data.get("srcip", "N/A"))

    timestamp = alert.get("timestamp", datetime.now().isoformat())

    # MITRE ATT&CK info
    mitre = rule.get("mitre", {})
    mitre_ids = ", ".join(mitre.get("id", [])) if mitre.get("id") else None
    mitre_tactics = ", ".join(mitre.get("tactic", [])) if mitre.get("tactic") else None

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Wazuh Alert - {severity}",
                "emoji": True
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Rule:* {rule_id} (Level {level})"},
                {"type": "mrkdwn", "text": f"*Agent:* {agent_name}"},
                {"type": "mrkdwn", "text": f"*Source IP:* {agent_ip}"},
                {"type": "mrkdwn", "text": f"*Groups:* {groups}"}
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:* {description}"}
        }
    ]

    # Add MITRE section if available
    if mitre_ids:
        mitre_text = f":shield: *MITRE ATT&CK:* {mitre_ids}"
        if mitre_tactics:
            mitre_text += f" | *Tactics:* {mitre_tactics}"
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": mitre_text}]
        })

    # Add log snippet if available
    full_log = alert.get("full_log", "")
    if full_log:
        # Truncate and escape for Slack
        log_snippet = full_log[:400].replace('`', "'")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"```{log_snippet}```"}
        })

    # Timestamp footer
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"_{timestamp}_"}]
    })

    return blocks


def send_slack_message(token, channel, blocks, text_fallback):
    """Send message to Slack channel"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "channel": channel,
        "blocks": blocks,
        "text": text_fallback  # Fallback for notifications
    }

    try:
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=headers,
            json=payload,
            timeout=10
        )

        data = response.json()
        if not data.get("ok"):
            sys.stderr.write(f"Slack API error: {data.get('error')}\n")
            return False
        return True
    except Exception as e:
        sys.stderr.write(f"Slack request error: {e}\n")
        return False


def main():
    # Load dynamic configuration
    config = load_config()

    # Check if muted
    if config.get("muted", False):
        sys.exit(0)  # Silently exit, don't send

    # Read alert from file (Wazuh passes path as first argument)
    if len(sys.argv) < 2:
        sys.exit(1)

    try:
        with open(sys.argv[1], 'r') as alert_file:
            alert_json = json.load(alert_file)
    except Exception as e:
        sys.stderr.write(f"Error reading alert file: {e}\n")
        sys.exit(1)

    # Extract alert data
    alert = alert_json.get("alert", alert_json)
    rule = alert.get("rule", {})
    level = rule.get("level", 0)

    # Check alert level against configured threshold
    config_level = config.get("level", 7)
    if level < config_level:
        sys.exit(0)  # Below threshold, don't send

    # Load credentials
    creds = load_credentials()
    bot_token = creds.get("bot_token")
    channel_id = creds.get("channel_id")

    if not bot_token or not channel_id:
        sys.stderr.write("Slack credentials not configured\n")
        sys.exit(1)

    # Determine severity
    if level >= 12:
        emoji = ":rotating_light:"
        severity = "CRITICAL"
    elif level >= 10:
        emoji = ":red_circle:"
        severity = "HIGH"
    elif level >= 7:
        emoji = ":large_orange_circle:"
        severity = "MEDIUM"
    else:
        emoji = ":large_yellow_circle:"
        severity = "LOW"

    # Build message
    blocks = build_slack_blocks(alert, level, severity, emoji)

    # Text fallback for notifications
    description = rule.get("description", "Alert")
    text_fallback = f"{emoji} Wazuh {severity}: {description}"

    # Send to Slack
    if send_slack_message(bot_token, channel_id, blocks, text_fallback):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
