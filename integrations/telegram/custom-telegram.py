#!/usr/bin/env python3
#
# Wazuh Telegram Integration
# Sends alert notifications to Telegram via Bot API
#
# Install to: /var/ossec/integrations/custom-telegram.py
#
# Configuration is read from /var/ossec/etc/telegram.conf
# which can be updated dynamically via the telegram-bot-listener
#

import sys
import os
import json
import requests
from datetime import datetime

CONFIG_FILE = "/var/ossec/etc/telegram.conf"


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


def main():
    # Load dynamic configuration
    config = load_config()

    # Read alert from file (Wazuh passes path as first argument)
    alert_file = open(sys.argv[1])
    alert_json = json.load(alert_file)
    alert_file.close()

    # Extract alert data
    alert = alert_json.get("alert", alert_json)
    rule = alert.get("rule", {})
    level = rule.get("level", 0)

    # Check if muted
    if config.get("muted", False):
        sys.exit(0)  # Silently exit, don't send

    # Check alert level against configured threshold
    # Note: Wazuh already filters by level in ossec.conf, but this allows
    # dynamic adjustment without restarting Wazuh
    config_level = config.get("level", 7)
    if level < config_level:
        sys.exit(0)  # Below threshold, don't send

    # Get Telegram settings from options (passed via ossec.conf)
    hook_url = sys.argv[3] if len(sys.argv) > 3 else None

    if not hook_url:
        sys.exit(1)

    # Parse bot token and chat ID from hook_url
    # Format: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
    # Or simple format: <TOKEN>:<CHAT_ID>
    if hook_url.startswith("https://"):
        api_url = hook_url
        chat_id = None
    else:
        # Simple format: TOKEN:CHAT_ID
        parts = hook_url.rsplit(":", 1)
        if len(parts) != 2:
            sys.exit(1)
        token, chat_id = parts
        api_url = f"https://api.telegram.org/bot{token}/sendMessage"

    # Extract remaining alert data
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    location = alert.get("location", "Unknown")

    description = rule.get("description", "No description")
    rule_id = rule.get("id", "N/A")
    groups = ", ".join(rule.get("groups", []))

    agent_name = agent.get("name", "N/A")
    agent_ip = agent.get("ip", data.get("srcip", "N/A"))

    timestamp = alert.get("timestamp", datetime.now().isoformat())

    # MITRE ATT&CK info if available
    mitre = rule.get("mitre", {})
    mitre_ids = ", ".join(mitre.get("id", [])) if mitre.get("id") else None
    mitre_tactics = ", ".join(mitre.get("tactic", [])) if mitre.get("tactic") else None

    # Determine severity emoji
    if level >= 12:
        emoji = "\U0001F6A8"  # Rotating light (critical)
        severity = "CRITICAL"
    elif level >= 10:
        emoji = "\U0001F534"  # Red circle (high)
        severity = "HIGH"
    elif level >= 7:
        emoji = "\U0001F7E0"  # Orange circle (medium)
        severity = "MEDIUM"
    else:
        emoji = "\U0001F7E1"  # Yellow circle (low)
        severity = "LOW"

    # Build message
    message_lines = [
        f"{emoji} *Wazuh Alert - {severity}*",
        "",
        f"*Rule:* {rule_id} (Level {level})",
        f"*Description:* {description}",
        f"*Agent:* {agent_name}",
        f"*Source:* {agent_ip}",
    ]

    if groups:
        message_lines.append(f"*Groups:* {groups}")

    if mitre_ids:
        message_lines.append(f"*MITRE:* {mitre_ids}")
        if mitre_tactics:
            message_lines.append(f"*Tactics:* {mitre_tactics}")

    # Add full log if available
    full_log = alert.get("full_log", "")
    if full_log and len(full_log) < 500:
        message_lines.append("")
        message_lines.append(f"```\n{full_log[:500]}\n```")

    message_lines.append("")
    message_lines.append(f"_{timestamp}_")

    message = "\n".join(message_lines)

    # Send to Telegram
    if "chat_id=" in api_url:
        # URL already has chat_id
        payload = {
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        response = requests.post(api_url, data=payload, timeout=10)
    else:
        # Need chat_id from simple format
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        response = requests.post(api_url, json=payload, timeout=10)

    if response.status_code != 200:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
