# Telegram Integration for Wazuh

Send Wazuh alert notifications to Telegram via Bot API.

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

## Non-Interactive Setup

```bash
sudo ./setup-telegram-integration.sh \
  -t "123456789:ABC-DEF..." \
  -c "-1001234567890" \
  -l 7
```

## Options

| Option | Description |
|--------|-------------|
| `-t, --token` | Telegram Bot Token |
| `-c, --chat-id` | Chat ID (user or group) |
| `-l, --level` | Minimum alert level (default: 7) |
| `-h, --help` | Show help |

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

3. **Test manually:**
   ```bash
   curl -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
     -H "Content-Type: application/json" \
     -d '{"chat_id":"<CHAT_ID>","text":"Test"}'
   ```

### Bot not responding

- Ensure you've started a conversation with the bot first
- For groups, make sure the bot has permission to send messages
- Check the bot wasn't blocked

## File Structure

```
integrations/telegram/
├── README.md                      # This file
├── setup-telegram-integration.sh  # Setup script
└── custom-telegram.py             # Wazuh integration script
```

## References

- [Wazuh Custom Integrations](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)
- [Telegram Bot API](https://core.telegram.org/bots/api)
