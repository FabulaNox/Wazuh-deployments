#!/usr/bin/env python3
#
# Wazuh Slack Bot Listener
# Listens for slash commands to configure alert settings dynamically
#
# Commands (via /wazuh in Slack):
#   /wazuh level <N>  - Set minimum alert level (1-15)
#   /wazuh level      - Show current level
#   /wazuh mute       - Mute all alerts
#   /wazuh mute <min> - Mute for N minutes
#   /wazuh unmute     - Resume alerts
#   /wazuh status     - Show current configuration
#   /wazuh help       - Show available commands
#
# Install to: /var/ossec/integrations/slack-bot-listener.py
# Run as: systemd service (wazuh-slack-bot)
#

import os
import sys
import json
import signal
import logging
import time
from datetime import datetime
from pathlib import Path

try:
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.request import SocketModeRequest
    from slack_sdk.socket_mode.response import SocketModeResponse
except ImportError:
    print("Error: slack_sdk not installed. Run: pip3 install slack_sdk")
    sys.exit(1)

CONFIG_FILE = "/var/ossec/etc/slack.conf"
CREDENTIALS_FILE = "/var/ossec/etc/slack-credentials.conf"

DEFAULT_CONFIG = {
    "level": 7,
    "muted": False,
    "muted_until": None,
    "last_updated": None,
    "updated_by": None
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wazuh-slack-bot')


class SlackBotListener:
    def __init__(self, bot_token, app_token, allowed_channels=None):
        self.bot_token = bot_token
        self.app_token = app_token
        self.allowed_channels = allowed_channels or []
        self.running = True

        self.web_client = WebClient(token=bot_token)
        self.socket_client = SocketModeClient(
            app_token=app_token,
            web_client=self.web_client
        )

        self.config = self.load_config()

        signal.signal(signal.SIGTERM, self.handle_shutdown)
        signal.signal(signal.SIGINT, self.handle_shutdown)

    def handle_shutdown(self, signum, frame):
        """Handle graceful shutdown"""
        logger.info("Shutdown signal received")
        self.running = False

    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Check mute expiration
                    if config.get("muted") and config.get("muted_until"):
                        if datetime.now().timestamp() > config["muted_until"]:
                            config["muted"] = False
                            config["muted_until"] = None
                            self.save_config(config)
                    return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")

        return DEFAULT_CONFIG.copy()

    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config

        config["last_updated"] = datetime.now().isoformat()

        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False

    def handle_command(self, subcommand, args, username):
        """Route command to handler"""
        handlers = {
            "level": self.cmd_level,
            "mute": self.cmd_mute,
            "unmute": self.cmd_unmute,
            "status": self.cmd_status,
            "help": self.cmd_help
        }

        handler = handlers.get(subcommand, self.cmd_help)

        if subcommand in ["level", "mute"]:
            return handler(args, username)
        elif subcommand == "unmute":
            return handler(username)
        else:
            return handler()

    def cmd_level(self, args, username):
        """Get or set alert level"""
        if not args:
            level = self.config.get("level", 7)
            return {
                "response_type": "ephemeral",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f":bell: Current alert level: *{level}*\n\nAlerts with level >= {level} will be sent to this channel."
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {"type": "mrkdwn", "text": "_Use `/wazuh level <1-15>` to change_"}
                        ]
                    }
                ]
            }

        try:
            new_level = int(args[0])
            if not 1 <= new_level <= 15:
                return {
                    "response_type": "ephemeral",
                    "text": ":warning: Level must be between 1 and 15"
                }

            old_level = self.config.get("level", 7)
            self.config["level"] = new_level
            self.config["updated_by"] = username

            if self.save_config():
                logger.info(f"Alert level changed from {old_level} to {new_level} by {username}")
                return {
                    "response_type": "in_channel",
                    "text": f":white_check_mark: Alert level set to *{new_level}* (was {old_level}) by <@{username}>"
                }
            return {"response_type": "ephemeral", "text": ":x: Error saving configuration"}

        except ValueError:
            return {
                "response_type": "ephemeral",
                "text": ":warning: Invalid level. Use a number between 1 and 15."
            }

    def cmd_mute(self, args, username):
        """Mute alerts"""
        self.config["muted"] = True
        self.config["updated_by"] = username

        if args:
            try:
                minutes = int(args[0])
                mute_until = datetime.now().timestamp() + (minutes * 60)
                self.config["muted_until"] = mute_until

                if self.save_config():
                    logger.info(f"Alerts muted for {minutes} minutes by {username}")
                    return {
                        "response_type": "in_channel",
                        "text": f":mute: Alerts muted for *{minutes} minutes* by <@{username}>"
                    }
            except ValueError:
                pass

        self.config["muted_until"] = None
        if self.save_config():
            logger.info(f"Alerts muted indefinitely by {username}")
            return {
                "response_type": "in_channel",
                "text": f":mute: Alerts *muted* until `/wazuh unmute` is called (by <@{username}>)"
            }
        return {"response_type": "ephemeral", "text": ":x: Error saving configuration"}

    def cmd_unmute(self, username):
        """Unmute alerts"""
        was_muted = self.config.get("muted", False)
        self.config["muted"] = False
        self.config["muted_until"] = None
        self.config["updated_by"] = username

        if self.save_config():
            logger.info(f"Alerts unmuted by {username}")
            if was_muted:
                return {
                    "response_type": "in_channel",
                    "text": f":loud_sound: Alerts *resumed* by <@{username}>"
                }
            return {
                "response_type": "ephemeral",
                "text": ":information_source: Alerts were not muted"
            }
        return {"response_type": "ephemeral", "text": ":x: Error saving configuration"}

    def cmd_status(self):
        """Show current status"""
        level = self.config.get("level", 7)
        muted = self.config.get("muted", False)
        muted_until = self.config.get("muted_until")
        last_updated = self.config.get("last_updated", "Never")
        updated_by = self.config.get("updated_by", "N/A")

        # Mute status text
        if muted:
            if muted_until:
                remaining = int((muted_until - datetime.now().timestamp()) / 60)
                mute_status = f":mute: Muted ({remaining} min remaining)"
            else:
                mute_status = ":mute: Muted (indefinitely)"
        else:
            mute_status = ":loud_sound: Active"

        # Level description
        level_desc = {
            1: "All alerts",
            3: "Info and above",
            5: "Low and above",
            7: "Medium and above (default)",
            10: "High and above",
            12: "Critical only"
        }
        level_text = level_desc.get(level, f"Level {level}+")

        return {
            "response_type": "ephemeral",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Wazuh Alert Configuration", "emoji": True}
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Alert Level:*\n{level} ({level_text})"},
                        {"type": "mrkdwn", "text": f"*Status:*\n{mute_status}"}
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Last updated: {last_updated} by {updated_by}"}
                    ]
                }
            ]
        }

    def cmd_help(self):
        """Show available commands"""
        return {
            "response_type": "ephemeral",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Wazuh Bot Commands", "emoji": True}
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*Alert Level:*\n"
                            "`/wazuh level` - Show current level\n"
                            "`/wazuh level <1-15>` - Set minimum alert level\n\n"
                            "*Mute Controls:*\n"
                            "`/wazuh mute` - Mute all alerts\n"
                            "`/wazuh mute <minutes>` - Mute for N minutes\n"
                            "`/wazuh unmute` - Resume alerts\n\n"
                            "*Information:*\n"
                            "`/wazuh status` - Show current configuration\n"
                            "`/wazuh help` - Show this help message"
                        )
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                "_Level guide: 1-3 Info, 4-6 Low, 7-9 Medium, 10-11 High, 12-15 Critical_"
                            )
                        }
                    ]
                }
            ]
        }

    def handle_slash_command(self, client, req: SocketModeRequest):
        """Handle incoming slash commands"""
        if req.type == "slash_commands":
            # Acknowledge immediately
            response = SocketModeResponse(envelope_id=req.envelope_id)
            client.send_socket_mode_response(response)

            payload = req.payload
            text = payload.get("text", "").strip()
            user_id = payload.get("user_id", "unknown")
            user_name = payload.get("user_name", "Unknown")
            channel_id = payload.get("channel_id")

            # Check allowed channels if configured
            if self.allowed_channels and channel_id not in self.allowed_channels:
                self.send_response(
                    payload.get("response_url"),
                    {"response_type": "ephemeral", "text": ":lock: This command is not available in this channel"}
                )
                return

            # Parse subcommand and args
            parts = text.split()
            subcommand = parts[0].lower() if parts else "help"
            args = parts[1:] if len(parts) > 1 else []

            logger.info(f"Command from {user_name}: /wazuh {text}")

            # Handle command
            response_data = self.handle_command(subcommand, args, user_id)

            # Send response
            self.send_response(payload.get("response_url"), response_data)

    def send_response(self, response_url, data):
        """Send response back to Slack"""
        if not response_url:
            return

        try:
            import requests
            requests.post(response_url, json=data, timeout=5)
        except Exception as e:
            logger.error(f"Error sending response: {e}")

    def run(self):
        """Start the Socket Mode connection"""
        logger.info("Wazuh Slack bot listener starting...")

        # Register slash command handler
        self.socket_client.socket_mode_request_listeners.append(
            self.handle_slash_command
        )

        # Connect to Slack
        self.socket_client.connect()

        logger.info("Connected to Slack Socket Mode")

        # Keep alive and check mute expiration
        while self.running:
            # Check mute expiration periodically
            if self.config.get("muted") and self.config.get("muted_until"):
                if datetime.now().timestamp() > self.config["muted_until"]:
                    self.config["muted"] = False
                    self.config["muted_until"] = None
                    self.save_config()
                    logger.info("Mute period expired, alerts resumed")

            time.sleep(10)

        self.socket_client.close()
        logger.info("Wazuh Slack bot listener stopped")


def main():
    # Load credentials
    if not os.path.exists(CREDENTIALS_FILE):
        logger.error(f"Credentials file not found: {CREDENTIALS_FILE}")
        sys.exit(1)

    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            creds = json.load(f)
    except Exception as e:
        logger.error(f"Error reading credentials: {e}")
        sys.exit(1)

    bot_token = creds.get("bot_token")
    app_token = creds.get("app_token")
    allowed_channels = creds.get("allowed_channels", [])

    if not bot_token:
        logger.error("Bot token not configured")
        sys.exit(1)

    if not app_token:
        logger.error("App token not configured (required for Socket Mode)")
        sys.exit(1)

    # Start listener
    listener = SlackBotListener(bot_token, app_token, allowed_channels)
    listener.run()


if __name__ == "__main__":
    main()
