# Slack Integration for Wazuh

Send Wazuh security alerts to a Slack channel with configurable alert levels and dynamic control via slash commands.

## Features

- Real-time security alerts in Slack with rich formatting (Block Kit)
- Configurable minimum alert level (1-15)
- Dynamic control via `/wazuh` slash commands (no Wazuh restart needed)
- Mute/unmute alerts temporarily or indefinitely
- MITRE ATT&CK mapping in alert messages
- Socket Mode - no public URL or webhook required

## Prerequisites

You need to create a Slack App before running the setup script.

### Create a Slack App (using App Manifest)

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App**
3. Select **From an app manifest**
4. Choose your workspace and click **Next**
5. Select **YAML** tab and paste the contents of `app-manifest.yaml`:

```yaml
display_information:
  name: Wazuh Alerts
  description: Security alert notifications from Wazuh SIEM
  background_color: "#1a1c2c"

features:
  bot_user:
    display_name: Wazuh
    always_online: true
  slash_commands:
    - command: /wazuh
      description: Manage Wazuh alert settings
      usage_hint: "level [1-15] | mute [minutes] | unmute | status | help"
      should_escape: false

oauth_config:
  scopes:
    bot:
      - chat:write
      - commands

settings:
  socket_mode_enabled: true
```

6. Click **Next**, review the summary, then click **Create**
7. Click **Install to Workspace** and click **Allow**

### Get Your Tokens

**Bot Token (for sending messages):**
1. Go to **OAuth & Permissions** in the sidebar
2. Copy the **Bot User OAuth Token** (starts with `xoxb-`)

**App Token (for slash commands via Socket Mode):**
1. Go to **Basic Information** in the sidebar
2. Scroll to **App-Level Tokens**
3. Click **Generate Token and Scopes**
4. Name it (e.g., "wazuh-socket"), add the `connections:write` scope
5. Click **Generate**, then copy the token (starts with `xapp-`)

### Get Channel ID

1. In Slack, right-click the target channel → **View channel details**
2. Copy the **Channel ID** at the bottom (starts with `C`)
3. Invite the bot to the channel: `/invite @Wazuh`

## Quick Start

Run the setup script and follow the prompts:

```bash
sudo ./setup-slack-integration.sh
```

The script will ask for:
1. **Bot Token** - paste the `xoxb-...` token
2. **App Token** - paste the `xapp-...` token (or leave empty to skip slash commands)
3. **Channel ID** - paste the channel ID starting with `C`
4. **Alert Level** - minimum level to notify (default: 7)

The script validates your tokens, sends a test message, and configures everything automatically.

### Terraform Deployment

Add to your `terraform.tfvars`:

```hcl
slack_integration_enabled = true
slack_bot_token          = "xoxb-your-bot-token"
slack_app_token          = "xapp-your-app-token"
slack_channel_id         = "C0123456789"
slack_alert_level        = 7
```

Then run:

```bash
terraform apply
```

## Slash Commands

Once installed, use these commands in Slack:

| Command | Description |
|---------|-------------|
| `/wazuh level` | Show current alert level |
| `/wazuh level 5` | Set minimum level to 5 |
| `/wazuh mute` | Mute all alerts indefinitely |
| `/wazuh mute 30` | Mute alerts for 30 minutes |
| `/wazuh unmute` | Resume alerts |
| `/wazuh status` | Show current configuration |
| `/wazuh help` | Show all commands |

## Alert Levels

| Level | Severity | Examples |
|-------|----------|----------|
| 1-3 | Info | DHCP assignment, successful login |
| 4-6 | Low | Warnings, minor config changes |
| 7-9 | Medium | Multiple auth failures, rule changes |
| 10-11 | High | Brute force attacks, security events |
| 12-15 | Critical | Rootkit detection, privilege escalation |

**Default threshold:** Level 7 (Medium and above)

## Message Format

Alerts appear in Slack with:
- Severity indicator (emoji + label)
- Rule ID and level
- Agent name and source IP
- Alert description
- MITRE ATT&CK mapping (if available)
- Log excerpt
- Timestamp

## Architecture

```
Alert Flow:
  Wazuh Manager → ossec.conf integration → custom-slack.py → Slack API → Channel

Command Flow:
  /wazuh command → Slack Socket Mode → slack-bot-listener.py → slack.conf
```

Socket Mode uses a WebSocket connection initiated from your server, so:
- No public URL or port forwarding required
- Works behind NAT and firewalls
- No SSL certificate management

## Configuration Files

| File | Purpose | Permissions |
|------|---------|-------------|
| `/var/ossec/etc/slack.conf` | Dynamic settings (level, mute status) | 644 |
| `/var/ossec/etc/slack-credentials.conf` | Bot token, app token, channel | 640 |
| `/var/ossec/integrations/custom-slack.py` | Alert sender script | 750 |
| `/var/ossec/integrations/slack-bot-listener.py` | Command handler | 750 |

## Service Management

```bash
# Check bot listener status
systemctl status wazuh-slack-bot

# View logs
journalctl -u wazuh-slack-bot -f

# Restart listener
systemctl restart wazuh-slack-bot
```

## Testing

Generate a test alert:

```bash
logger -t security 'Authentication failure for user test'
```

Or trigger a higher-level alert:

```bash
# This may trigger brute force detection if repeated
for i in {1..5}; do logger -t sshd 'Failed password for invalid user admin'; done
```

## Troubleshooting

### Test message not received
- Verify the bot is invited to the channel: `/invite @Wazuh`
- Check the channel ID is correct (should start with `C`)
- Verify bot token with: `curl -H "Authorization: Bearer xoxb-..." https://slack.com/api/auth.test`

### Slash commands not working
- Ensure Socket Mode is enabled in your Slack App settings
- Verify app token starts with `xapp-`
- Check listener service: `systemctl status wazuh-slack-bot`
- View logs: `journalctl -u wazuh-slack-bot -f`

### Alerts not appearing
- Check Wazuh manager status: `systemctl status wazuh-manager`
- Verify integration in ossec.conf: `grep -A5 "custom-slack" /var/ossec/etc/ossec.conf`
- Check alert level threshold in `/var/ossec/etc/slack.conf`
- Look for errors: `tail -f /var/ossec/logs/ossec.log`

### Permission errors
- Credentials file should be owned by root:wazuh with mode 640
- Integration scripts should be owned by root:wazuh with mode 750

## Uninstalling

```bash
# Stop and disable the bot listener
sudo systemctl stop wazuh-slack-bot
sudo systemctl disable wazuh-slack-bot
sudo rm /etc/systemd/system/wazuh-slack-bot.service
sudo systemctl daemon-reload

# Remove integration from ossec.conf (manually edit or restore backup)
sudo vim /var/ossec/etc/ossec.conf

# Remove files
sudo rm /var/ossec/integrations/custom-slack.py
sudo rm /var/ossec/integrations/slack-bot-listener.py
sudo rm /var/ossec/etc/slack.conf
sudo rm /var/ossec/etc/slack-credentials.conf

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

## Files in This Directory

| File | Purpose |
|------|---------|
| `app-manifest.yaml` | Slack App manifest - paste into Slack to create app automatically |
| `setup-slack-integration.sh` | Automated setup script |
| `custom-slack.py` | Alert sender (installed to `/var/ossec/integrations/`) |
| `slack-bot-listener.py` | Socket Mode command handler |
| `wazuh-slack-bot.service` | Systemd service unit |
| `README.md` | This documentation |

## Security Notes

- Bot tokens and app tokens are stored in `/var/ossec/etc/slack-credentials.conf` with mode 640 (root:wazuh)
- The `allowed_channels` setting in credentials restricts which channels can use commands
- Consider creating a dedicated private channel for security alerts
- Regularly rotate your Slack tokens if needed
