# Telegram Integration for Wazuh

Send Wazuh alert notifications to Telegram via Bot API with dynamic control via bot commands.

## Features

- Alert notifications with severity levels and MITRE ATT&CK mapping
- **Dynamic control via Telegram commands** - change settings without restarting Wazuh
- Mute/unmute alerts temporarily or indefinitely
- Adjust alert level threshold on the fly

## Prerequisites

1. **Create a Telegram Bot**
   - Open Telegram and message [@BotFather](https://t.me/BotFather)
   - Send `/newbot` and follow the prompts
   - Save the Bot Token (looks like: `123456789:ABC-DEF...`)

2. **Get Your Chat ID**
   - For personal notifications: Message [@userinfobot](https://t.me/userinfobot)
   - For group notifications:
     1. Add your bot to the group
     2. Send a message in the group
     3. Run: `curl "https://api.telegram.org/bot<TOKEN>/getUpdates"`
     4. Find `"chat":{"id":-1001234567890}` in the response

## Quick Start

```bash
sudo ./setup-telegram-integration.sh
```

The script will prompt for:
- Bot Token
- Chat ID
- Minimum alert level (default: 7)
- Whether to install the bot command listener

## Non-Interactive Setup

```bash
# With bot listener (recommended)
sudo ./setup-telegram-integration.sh \
  -t "123456789:ABC-DEF..." \
  -c "-1001234567890" \
  -l 7

# Without bot listener
sudo ./setup-telegram-integration.sh \
  -t "123456789:ABC-DEF..." \
  -c "-1001234567890" \
  -l 7 \
  --no-listener
```

## Options

| Option | Description |
|--------|-------------|
| `-t, --token` | Telegram Bot Token |
| `-c, --chat-id` | Chat ID (user or group) |
| `-l, --level` | Minimum alert level (default: 7) |
| `--no-listener` | Don't install the bot command listener |
| `-h, --help` | Show help |

## Bot Commands

When the bot listener is enabled, you can control alert settings directly from Telegram:

| Command | Description |
|---------|-------------|
| `/level` | Show current alert level |
| `/level <N>` | Set minimum alert level (1-15) |
| `/mute` | Mute all alerts indefinitely |
| `/mute <minutes>` | Mute alerts for N minutes |
| `/unmute` | Resume alerts |
| `/status` | Show current configuration |
| `/test` | Send a test response |
| `/help` | Show available commands |

### Examples

```
/level 5      # Receive alerts level 5 and above (more alerts)
/level 10     # Only receive high/critical alerts
/mute 30      # Mute for 30 minutes during maintenance
/unmute       # Resume receiving alerts
/status       # Check current settings
```

## Alert Levels

| Level | Severity | Examples |
|-------|----------|----------|
| 12+ | Critical | System compromise, rootkit detected |
| 10-11 | High | Brute force, multiple failed logins |
| 7-9 | Medium | Config changes, firewall modifications |
| 5-6 | Low | Login events, warnings |
| 1-4 | Info | DHCP assignments, informational |

## Message Format

Notifications include:
- Severity emoji and level
- Rule ID and description
- Agent name and source IP
- MITRE ATT&CK mapping (if available)
- Truncated log entry

Example:
```
🟠 Wazuh Alert - MEDIUM

Rule: 100122 (Level 7)
Description: MikroTik: Firewall rule modified
Agent: MikroTik
Source: 192.168.88.1
Groups: firewall, config_change
MITRE: T1562

2026-01-17T10:30:00+0200
```

## Architecture

When the bot listener is enabled:

```
┌─────────────────┐     ┌──────────────────────┐
│  Wazuh Manager  │────▶│  custom-telegram.py  │────▶ Telegram
│    (alerts)     │     │  (reads config file) │
└─────────────────┘     └──────────────────────┘
                                   ▲
                                   │ reads
                                   │
                        ┌──────────────────────┐
                        │  /var/ossec/etc/     │
                        │  telegram.conf       │
                        └──────────────────────┘
                                   ▲
                                   │ writes
                                   │
┌─────────────────┐     ┌──────────────────────┐
│    Telegram     │────▶│ telegram-bot-listener│
│   (commands)    │     │    (systemd service) │
└─────────────────┘     └──────────────────────┘
```

**How it works:**
1. The bot listener runs as a systemd service, polling Telegram for commands
2. When you send `/level 5`, it updates `/var/ossec/etc/telegram.conf`
3. The integration script reads this config before sending each alert
4. No Wazuh restart needed - changes take effect immediately

## Service Management

```bash
# Check bot listener status
systemctl status wazuh-telegram-bot

# View bot listener logs
journalctl -u wazuh-telegram-bot -f

# Restart bot listener
systemctl restart wazuh-telegram-bot

# Stop bot listener
systemctl stop wazuh-telegram-bot
```

## Configuration Files

| File | Purpose |
|------|---------|
| `/var/ossec/etc/telegram.conf` | Dynamic settings (level, mute status) |
| `/var/ossec/etc/telegram-credentials.conf` | Bot token and allowed chat IDs |
| `/var/ossec/integrations/custom-telegram.py` | Alert notification script |
| `/var/ossec/integrations/telegram-bot-listener.py` | Command listener script |

## Troubleshooting

### Not receiving notifications

1. **Check integration is loaded:**
   ```bash
   grep -A5 "custom-telegram" /var/ossec/etc/ossec.conf
   ```

2. **Check integration logs:**
   ```bash
   tail -f /var/ossec/logs/integrations.log
   ```

3. **Check current config:**
   ```bash
   cat /var/ossec/etc/telegram.conf
   ```
   Verify `muted` is `false` and `level` is appropriate.

4. **Test manually:**
   ```bash
   curl -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
     -H "Content-Type: application/json" \
     -d '{"chat_id":"<CHAT_ID>","text":"Test"}'
   ```

### Bot commands not working

1. **Check listener is running:**
   ```bash
   systemctl status wazuh-telegram-bot
   ```

2. **Check listener logs:**
   ```bash
   journalctl -u wazuh-telegram-bot -f
   ```

3. **Verify credentials file:**
   ```bash
   cat /var/ossec/etc/telegram-credentials.conf
   ```

### Bot not responding at all

- Ensure you've started a conversation with the bot first (send `/start`)
- For groups, make sure the bot has permission to send messages
- Check the bot wasn't blocked
- Verify your chat ID is in the allowed list

## File Structure

```
integrations/telegram/
├── README.md                      # This file
├── setup-telegram-integration.sh  # Setup script
├── custom-telegram.py             # Wazuh integration script
├── telegram-bot-listener.py       # Bot command listener
└── wazuh-telegram-bot.service     # Systemd service file
```

## Security Notes

- Credentials are stored in `/var/ossec/etc/telegram-credentials.conf` with mode 600
- The bot listener only accepts commands from chat IDs in the allowed list
- The systemd service runs with security hardening (NoNewPrivileges, ProtectSystem, etc.)

## References

- [Wazuh Custom Integrations](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)
- [Telegram Bot API](https://core.telegram.org/bots/api)
