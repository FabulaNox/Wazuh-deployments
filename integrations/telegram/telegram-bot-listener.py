#!/usr/bin/env python3
#
# Wazuh Telegram Bot Listener
# Listens for commands to configure alert settings dynamically
#
# Commands:
#   /level <N>  - Set minimum alert level (1-15)
#   /level      - Show current level
#   /mute       - Mute all alerts
#   /unmute     - Resume alerts
#   /status     - Show current configuration
#   /help       - Show available commands
#
# Install to: /var/ossec/integrations/telegram-bot-listener.py
# Run as: systemd service (wazuh-telegram-bot)
#

import os
import sys
import json
import time
import signal
import logging
import requests
from pathlib import Path
from datetime import datetime

# Configuration
CONFIG_FILE = "/var/ossec/etc/telegram.conf"
DEFAULT_CONFIG = {
    "level": 7,
    "muted": False,
    "muted_until": None,
    "last_updated": None,
    "updated_by": None
}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class TelegramBotListener:
    def __init__(self, token, allowed_chat_ids=None):
        self.token = token
        self.api_url = f"https://api.telegram.org/bot{token}"
        self.allowed_chat_ids = allowed_chat_ids or []
        self.running = True
        self.last_update_id = 0

        # Load or create config
        self.config = self.load_config()

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        signal.signal(signal.SIGINT, self.handle_shutdown)

    def handle_shutdown(self, signum, frame):
        logger.info("Shutdown signal received")
        self.running = False

    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults for any missing keys
                    for key, value in DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                    return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")

        # Create default config
        self.save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config

        config["last_updated"] = datetime.now().isoformat()

        try:
            # Ensure directory exists
            Path(CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)

            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)

            # Set permissions (readable by wazuh)
            os.chmod(CONFIG_FILE, 0o644)

            self.config = config
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False

    def send_message(self, chat_id, text, parse_mode="Markdown"):
        """Send a message to Telegram"""
        try:
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": parse_mode
                },
                timeout=10
            )
            return response.json().get("ok", False)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False

    def get_updates(self):
        """Get new messages from Telegram"""
        try:
            response = requests.get(
                f"{self.api_url}/getUpdates",
                params={
                    "offset": self.last_update_id + 1,
                    "timeout": 30
                },
                timeout=35
            )
            data = response.json()

            if data.get("ok"):
                return data.get("result", [])
        except requests.exceptions.Timeout:
            pass  # Normal for long polling
        except Exception as e:
            logger.error(f"Error getting updates: {e}")

        return []

    def is_authorized(self, chat_id):
        """Check if chat_id is authorized to send commands"""
        if not self.allowed_chat_ids:
            return True  # No restrictions
        return str(chat_id) in [str(c) for c in self.allowed_chat_ids]

    def handle_command(self, chat_id, command, args, username):
        """Process a command and return response"""
        command = command.lower().lstrip('/')

        if command == "help" or command == "start":
            return self.cmd_help()
        elif command == "level":
            return self.cmd_level(args, username)
        elif command == "mute":
            return self.cmd_mute(args, username)
        elif command == "unmute":
            return self.cmd_unmute(username)
        elif command == "status":
            return self.cmd_status()
        elif command == "test":
            return self.cmd_test()
        else:
            return f"Unknown command: /{command}\nUse /help for available commands."

    def cmd_help(self):
        """Show help message"""
        return """*Wazuh Telegram Bot Commands*

/level `<N>` - Set minimum alert level (1-15)
/level - Show current alert level
/mute - Mute all alerts
/mute `<minutes>` - Mute for N minutes
/unmute - Resume alerts
/status - Show current configuration
/test - Send a test message
/help - Show this message

*Alert Levels:*
`1-4` - Low (informational)
`5-6` - Medium-Low
`7-9` - Medium (default threshold)
`10-11` - High
`12+` - Critical"""

    def cmd_level(self, args, username):
        """Get or set alert level"""
        if not args:
            level = self.config.get("level", 7)
            return f"Current alert level: *{level}*\n\nAlerts with level >= {level} will be sent."

        try:
            new_level = int(args[0])
            if not 1 <= new_level <= 15:
                return "Level must be between 1 and 15"

            old_level = self.config.get("level", 7)
            self.config["level"] = new_level
            self.config["updated_by"] = username

            if self.save_config():
                return f"Alert level set to *{new_level}* (was {old_level})"
            else:
                return "Error saving configuration"
        except ValueError:
            return "Invalid level. Use a number between 1 and 15."

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
                    return f"Alerts muted for *{minutes} minutes*"
            except ValueError:
                pass

        self.config["muted_until"] = None
        if self.save_config():
            return "Alerts *muted* until /unmute is called"
        return "Error saving configuration"

    def cmd_unmute(self, username):
        """Unmute alerts"""
        was_muted = self.config.get("muted", False)
        self.config["muted"] = False
        self.config["muted_until"] = None
        self.config["updated_by"] = username

        if self.save_config():
            if was_muted:
                return "Alerts *resumed*"
            return "Alerts were not muted"
        return "Error saving configuration"

    def cmd_status(self):
        """Show current status"""
        level = self.config.get("level", 7)
        muted = self.config.get("muted", False)
        muted_until = self.config.get("muted_until")
        last_updated = self.config.get("last_updated", "Never")
        updated_by = self.config.get("updated_by", "N/A")

        status_emoji = "" if muted else ""
        mute_status = "Yes"

        if muted:
            if muted_until:
                remaining = muted_until - datetime.now().timestamp()
                if remaining > 0:
                    mins = int(remaining / 60)
                    mute_status = f"Yes (for {mins} more minutes)"
                else:
                    mute_status = "No (expired)"
                    # Auto-unmute
                    self.config["muted"] = False
                    self.config["muted_until"] = None
                    self.save_config()
        else:
            mute_status = "No"

        return f"""*Wazuh Telegram Bot Status*

{status_emoji} *Status:* {"Muted" if muted else "Active"}
*Alert Level:* >= {level}
*Muted:* {mute_status}
*Last Updated:* {last_updated}
*Updated By:* {updated_by}"""

    def cmd_test(self):
        """Send a test response"""
        return " Bot is working!\n\nThis confirms the bot listener is running and can send messages."

    def process_update(self, update):
        """Process a single update from Telegram"""
        self.last_update_id = update.get("update_id", self.last_update_id)

        message = update.get("message", {})
        if not message:
            return

        chat_id = message.get("chat", {}).get("id")
        text = message.get("text", "")
        username = message.get("from", {}).get("username", "Unknown")

        if not text or not text.startswith("/"):
            return

        # Check authorization
        if not self.is_authorized(chat_id):
            logger.warning(f"Unauthorized access attempt from chat_id: {chat_id}")
            self.send_message(chat_id, "Unauthorized. Your chat ID is not allowed.")
            return

        # Parse command
        parts = text.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        logger.info(f"Command from {username} ({chat_id}): {command} {args}")

        # Handle command
        response = self.handle_command(chat_id, command, args, username)
        self.send_message(chat_id, response)

    def run(self):
        """Main loop"""
        logger.info("Telegram bot listener started")
        logger.info(f"Config file: {CONFIG_FILE}")
        logger.info(f"Current level: {self.config.get('level', 7)}")

        while self.running:
            updates = self.get_updates()

            for update in updates:
                try:
                    self.process_update(update)
                except Exception as e:
                    logger.error(f"Error processing update: {e}")

            # Check for mute expiration
            if self.config.get("muted") and self.config.get("muted_until"):
                if datetime.now().timestamp() > self.config["muted_until"]:
                    self.config["muted"] = False
                    self.config["muted_until"] = None
                    self.save_config()
                    logger.info("Mute period expired, alerts resumed")

        logger.info("Telegram bot listener stopped")


def main():
    # Read configuration from environment or command line
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_ids = os.environ.get("TELEGRAM_CHAT_IDS", "").split(",")

    # Try to read from config file if env vars not set
    if not token:
        try:
            conf_file = "/var/ossec/etc/telegram-credentials.conf"
            if os.path.exists(conf_file):
                with open(conf_file, 'r') as f:
                    creds = json.load(f)
                    token = creds.get("bot_token")
                    chat_ids = creds.get("chat_ids", [])
        except Exception as e:
            logger.error(f"Error reading credentials: {e}")

    if not token:
        logger.error("No bot token provided. Set TELEGRAM_BOT_TOKEN or create /var/ossec/etc/telegram-credentials.conf")
        sys.exit(1)

    # Filter empty chat_ids
    chat_ids = [c.strip() for c in chat_ids if c.strip()]

    bot = TelegramBotListener(token, chat_ids)
    bot.run()


if __name__ == "__main__":
    main()
