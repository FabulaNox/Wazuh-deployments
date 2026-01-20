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
# Debug logs are written to /tmp/telegram_integration.log
#

import sys
import os
import json
import traceback

DEBUG_LOG = "/tmp/telegram_integration.log"
CONFIG_FILE = "/var/ossec/etc/telegram.conf"


def debug(msg):
    """Write debug message to log file"""
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(str(msg) + "\n")
    except Exception:
        pass  # Silently fail if can't write debug log


debug("=== Invocation ===")
debug(f"CWD: {os.getcwd()}")
debug(f"Args: {sys.argv}")
debug(f"UID: {os.getuid()}, GID: {os.getgid()}")

try:
    import requests
    debug("requests imported OK")
except ImportError as e:
    debug(f"Failed to import requests: {e}")
    sys.exit(1)


def load_config():
    """Load configuration from file"""
    from datetime import datetime
    default_config = {"level": 7, "muted": False, "muted_until": None}
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Check mute expiration
                if config.get("muted") and config.get("muted_until"):
                    if datetime.now().timestamp() > config["muted_until"]:
                        config["muted"] = False
                return config
    except Exception as e:
        debug(f"Config load error: {e}")
    return default_config


def main():
    from datetime import datetime

    # Load dynamic configuration
    config = load_config()
    debug(f"Config: {config}")

    # Read alert from file (Wazuh passes path as first argument)
    alert_file = sys.argv[1]
    debug(f"Alert file: {alert_file}")

    with open(alert_file) as f:
        alert_json = json.load(f)

    # Extract alert data
    alert = alert_json.get("alert", alert_json)
    rule = alert.get("rule", {})
    level = rule.get("level", 0)
    debug(f"Alert level: {level}")

    # Check if muted
    if config.get("muted", False):
        debug("Muted, exiting")
        sys.exit(0)

    # Check alert level against configured threshold
    config_level = config.get("level", 7)
    if level < config_level:
        debug(f"Level {level} < threshold {config_level}, exiting")
        sys.exit(0)

    # Get Telegram settings from options (passed via ossec.conf)
    hook_url = sys.argv[3] if len(sys.argv) > 3 else None
    debug(f"Hook URL: {hook_url}")

    if not hook_url:
        debug("No hook_url, exiting")
        sys.exit(1)

    # Parse bot token and chat ID from hook_url
    # Format: <TOKEN>:<CHAT_ID>
    parts = hook_url.rsplit(":", 1)
    if len(parts) != 2:
        debug(f"Invalid hook_url format: {parts}")
        sys.exit(1)
    token, chat_id = parts
    api_url = f"https://api.telegram.org/bot{token}/sendMessage"
    debug(f"API URL: {api_url}, Chat ID: {chat_id}")

    # Extract remaining alert data
    agent = alert.get("agent", {})
    data = alert.get("data", {})

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

    # Add full log if available and not too long
    full_log = alert.get("full_log", "")
    if full_log and len(full_log) < 500:
        # Escape markdown special characters in log
        escaped_log = full_log[:500].replace('`', "'")
        message_lines.append("")
        message_lines.append(f"```\n{escaped_log}\n```")

    message_lines.append("")
    message_lines.append(f"_{timestamp}_")

    message = "\n".join(message_lines)

    debug("Sending message...")

    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }

    response = requests.post(api_url, json=payload, timeout=10)
    debug(f"Response: {response.status_code} - {response.text[:200]}")

    if response.status_code != 200:
        debug(f"Failed to send message: {response.text}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        debug(f"Exception: {e}")
        debug(traceback.format_exc())
        sys.exit(1)
