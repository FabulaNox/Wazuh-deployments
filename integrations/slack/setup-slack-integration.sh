#!/bin/bash
#
# Slack Integration Setup for Wazuh
# Sends alert notifications to Slack via Bot API with Socket Mode
#
# Usage: sudo ./setup-slack-integration.sh
#
# Prerequisites:
#   1. Create a Slack App using app-manifest.yaml
#   2. Get Bot Token (xoxb-...) from OAuth & Permissions
#   3. Get App Token (xapp-...) from Basic Information -> App-Level Tokens
#   4. Get Channel ID from Slack
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
INTEGRATIONS_DIR="/var/ossec/integrations"
CONFIG_DIR="/var/ossec/etc"

log_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[X]${NC} $1"; }

show_banner() {
    echo ""
    echo -e "${CYAN}+----------------------------------------------------------+${NC}"
    echo -e "${CYAN}|     Slack Integration for Wazuh                          |${NC}"
    echo -e "${CYAN}|     Alert Notifications via Bot API + Socket Mode        |${NC}"
    echo -e "${CYAN}+----------------------------------------------------------+${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_wazuh() {
    if [[ ! -f "$OSSEC_CONF" ]]; then
        log_error "Wazuh manager not found at $OSSEC_CONF"
        exit 1
    fi
    log_success "Wazuh manager detected"
}

prompt_config() {
    echo -e "${YELLOW}Slack App Setup${NC}"
    echo "-------------------------------------------------------------"
    echo ""
    echo "Before continuing, create a Slack App:"
    echo "  1. Go to https://api.slack.com/apps"
    echo "  2. Create New App -> From an app manifest"
    echo "  3. Paste contents of app-manifest.yaml"
    echo "  4. Install to Workspace"
    echo ""
    echo "See README.md for detailed instructions."
    echo ""
    echo "-------------------------------------------------------------"
    echo ""

    # Bot Token
    echo -e "${CYAN}Bot Token${NC} (OAuth & Permissions -> Bot User OAuth Token)"
    read -p "  xoxb-: " BOT_TOKEN_INPUT
    if [[ -z "$BOT_TOKEN_INPUT" ]]; then
        log_error "Bot token is required"
        exit 1
    fi
    # Add prefix if not included
    if [[ "$BOT_TOKEN_INPUT" == xoxb-* ]]; then
        BOT_TOKEN="$BOT_TOKEN_INPUT"
    else
        BOT_TOKEN="xoxb-$BOT_TOKEN_INPUT"
    fi

    echo ""

    # App Token
    echo -e "${CYAN}App Token${NC} (Basic Information -> App-Level Tokens)"
    echo "  (Leave empty to skip slash commands)"
    read -p "  xapp-: " APP_TOKEN_INPUT
    if [[ -z "$APP_TOKEN_INPUT" ]]; then
        log_warn "No app token - slash commands will be disabled"
        APP_TOKEN=""
        INSTALL_LISTENER=false
    else
        if [[ "$APP_TOKEN_INPUT" == xapp-* ]]; then
            APP_TOKEN="$APP_TOKEN_INPUT"
        else
            APP_TOKEN="xapp-$APP_TOKEN_INPUT"
        fi
        INSTALL_LISTENER=true
    fi

    echo ""

    # Channel ID
    echo -e "${CYAN}Channel ID${NC} (Right-click channel -> View details -> copy ID)"
    read -p "  C: " CHANNEL_INPUT
    if [[ -z "$CHANNEL_INPUT" ]]; then
        log_error "Channel ID is required"
        exit 1
    fi
    # Add prefix if not included
    if [[ "$CHANNEL_INPUT" == C* ]] || [[ "$CHANNEL_INPUT" == \#* ]]; then
        CHANNEL_ID="$CHANNEL_INPUT"
    else
        CHANNEL_ID="C$CHANNEL_INPUT"
    fi

    echo ""

    # Alert Level
    echo -e "${CYAN}Minimum Alert Level${NC} (1-15, default: 7)"
    echo "  1-3: Info  |  4-6: Low  |  7-9: Medium  |  10-11: High  |  12-15: Critical"
    read -p "  Level [7]: " ALERT_LEVEL_INPUT
    ALERT_LEVEL=${ALERT_LEVEL_INPUT:-7}

    echo ""
}

validate_bot_token() {
    log_info "Validating bot token..."

    local response=$(curl -s -H "Authorization: Bearer ${BOT_TOKEN}" \
        "https://slack.com/api/auth.test")

    if echo "$response" | grep -q '"ok":true'; then
        local team=$(echo "$response" | grep -o '"team":"[^"]*"' | cut -d'"' -f4)
        local bot_name=$(echo "$response" | grep -o '"user":"[^"]*"' | cut -d'"' -f4)
        log_success "Bot token valid - workspace: $team, bot: $bot_name"
        return 0
    else
        local error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log_error "Bot token validation failed: $error"
        return 1
    fi
}

validate_app_token() {
    if [[ -z "$APP_TOKEN" ]]; then
        return 0
    fi

    log_info "Validating app token (Socket Mode)..."

    local response=$(curl -s -X POST \
        -H "Authorization: Bearer ${APP_TOKEN}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "https://slack.com/api/apps.connections.open")

    if echo "$response" | grep -q '"ok":true'; then
        log_success "App token valid for Socket Mode"
        return 0
    else
        local error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log_error "App token validation failed: $error"
        log_warn "Slash commands will not work without a valid app token"
        INSTALL_LISTENER=false
        return 0
    fi
}

test_slack() {
    log_info "Sending test message to Slack..."

    local listener_status="Disabled"
    if $INSTALL_LISTENER; then
        listener_status="Enabled (/wazuh commands)"
    fi

    local payload=$(cat << EOF
{
    "channel": "${CHANNEL_ID}",
    "text": "Wazuh Integration Test",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":white_check_mark: Wazuh Integration Test",
                "emoji": true
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Slack notifications configured successfully!\n\n*Alert level:* ${ALERT_LEVEL}+\n*Bot commands:* ${listener_status}"
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "_Wazuh will send security alerts to this channel_"
                }
            ]
        }
    ]
}
EOF
)

    local response=$(curl -s -X POST \
        -H "Authorization: Bearer ${BOT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "https://slack.com/api/chat.postMessage")

    if echo "$response" | grep -q '"ok":true'; then
        log_success "Test message sent successfully!"
        return 0
    else
        local error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log_error "Failed to send test message: $error"

        if [[ "$error" == "channel_not_found" ]]; then
            log_warn "Make sure the bot is invited to the channel: /invite @Wazuh"
        fi
        return 1
    fi
}

install_dependencies() {
    log_info "Checking Python dependencies..."

    # Check for requests
    if ! python3 -c "import requests" 2>/dev/null; then
        log_info "Installing requests..."
        pip3 install requests -q 2>/dev/null || apt-get install -y python3-requests -qq 2>/dev/null || true
    fi

    # Check for slack_sdk if listener is enabled
    if $INSTALL_LISTENER; then
        if ! python3 -c "import slack_sdk" 2>/dev/null; then
            log_info "Installing slack_sdk..."
            pip3 install slack_sdk -q 2>/dev/null || {
                log_warn "Could not install slack_sdk via pip"
                log_warn "Try: pip3 install slack_sdk"
            }
        fi
    fi

    log_success "Dependencies checked"
}

install_integration() {
    log_info "Installing Slack integration script..."

    # Copy the Python script
    if [[ -f "$SCRIPT_DIR/custom-slack.py" ]]; then
        cp "$SCRIPT_DIR/custom-slack.py" "$INTEGRATIONS_DIR/custom-slack.py"
        chmod 750 "$INTEGRATIONS_DIR/custom-slack.py"
        chown root:wazuh "$INTEGRATIONS_DIR/custom-slack.py"
        log_success "Integration script installed"
    else
        log_error "Integration script not found: $SCRIPT_DIR/custom-slack.py"
        exit 1
    fi
}

install_bot_listener() {
    if ! $INSTALL_LISTENER; then
        return 0
    fi

    log_info "Installing bot command listener..."

    # Copy the listener script
    if [[ -f "$SCRIPT_DIR/slack-bot-listener.py" ]]; then
        cp "$SCRIPT_DIR/slack-bot-listener.py" "$INTEGRATIONS_DIR/slack-bot-listener.py"
        chmod 750 "$INTEGRATIONS_DIR/slack-bot-listener.py"
        chown root:root "$INTEGRATIONS_DIR/slack-bot-listener.py"
        log_success "Bot listener script installed"
    else
        log_warn "Bot listener script not found, skipping"
        return 0
    fi

    # Install systemd service
    if [[ -f "$SCRIPT_DIR/wazuh-slack-bot.service" ]]; then
        log_info "Installing systemd service..."
        cp "$SCRIPT_DIR/wazuh-slack-bot.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable wazuh-slack-bot
        systemctl start wazuh-slack-bot

        sleep 2
        if systemctl is-active --quiet wazuh-slack-bot; then
            log_success "Bot listener service started"
        else
            log_warn "Bot listener service failed to start"
            log_warn "Check: journalctl -u wazuh-slack-bot"
        fi
    else
        log_warn "Service file not found, skipping systemd setup"
    fi
}

create_config_files() {
    log_info "Creating configuration files..."

    # Create credentials config file (restricted permissions)
    cat > "$CONFIG_DIR/slack-credentials.conf" << EOF
{
  "bot_token": "${BOT_TOKEN}",
  "app_token": "${APP_TOKEN}",
  "channel_id": "${CHANNEL_ID}",
  "allowed_channels": ["${CHANNEL_ID}"]
}
EOF
    chown root:wazuh "$CONFIG_DIR/slack-credentials.conf"
    chmod 640 "$CONFIG_DIR/slack-credentials.conf"
    log_success "Credentials saved to $CONFIG_DIR/slack-credentials.conf"

    # Create dynamic config file
    cat > "$CONFIG_DIR/slack.conf" << EOF
{
  "level": ${ALERT_LEVEL},
  "muted": false,
  "muted_until": null,
  "last_updated": "$(date -Iseconds)",
  "updated_by": "setup-script"
}
EOF
    chmod 644 "$CONFIG_DIR/slack.conf"
    log_success "Dynamic config saved to $CONFIG_DIR/slack.conf"
}

configure_ossec() {
    log_info "Configuring ossec.conf..."

    # Use level 1 in ossec.conf to let the script handle filtering
    local ossec_level=1
    if ! $INSTALL_LISTENER; then
        ossec_level=$ALERT_LEVEL
    fi

    # Check if integration already exists
    if grep -q "custom-slack" "$OSSEC_CONF" 2>/dev/null; then
        log_warn "Slack integration already configured"
        read -p "Replace existing configuration? [y/N]: " replace
        if [[ "${replace,,}" != "y" ]]; then
            return 0
        fi
        # Remove existing config
        python3 << PYEOF
import re
with open('$OSSEC_CONF', 'r') as f:
    content = f.read()

pattern = r'\s*<!--\s*Slack[^>]*-->\s*<integration>.*?custom-slack.*?</integration>'
content = re.sub(pattern, '', content, flags=re.DOTALL)

with open('$OSSEC_CONF', 'w') as f:
    f.write(content)
PYEOF
    fi

    # Backup config
    cp "$OSSEC_CONF" "${OSSEC_CONF}.backup.$(date +%Y%m%d%H%M%S)"

    # Add integration config
    local integration_config="
  <!-- Slack Alert Notifications -->
  <integration>
    <name>custom-slack.py</name>
    <hook_url>slack</hook_url>
    <level>${ossec_level}</level>
    <alert_format>json</alert_format>
  </integration>"

    # Insert before closing tag
    python3 << PYEOF
import re
with open('$OSSEC_CONF', 'r') as f:
    content = f.read()

insert_text = '''$integration_config'''
content = re.sub(r'(</ossec_config>)\s*$', insert_text + r'\n\1', content)

with open('$OSSEC_CONF', 'w') as f:
    f.write(content)
PYEOF

    log_success "Integration configured in ossec.conf"
}

restart_wazuh() {
    log_info "Restarting Wazuh manager..."

    if ! /var/ossec/bin/wazuh-analysisd -t > /dev/null 2>&1; then
        log_error "Configuration validation failed!"
        /var/ossec/bin/wazuh-analysisd -t
        exit 1
    fi

    systemctl restart wazuh-manager
    sleep 3

    if systemctl is-active --quiet wazuh-manager; then
        log_success "Wazuh manager restarted"
    else
        log_error "Wazuh manager failed to start"
        exit 1
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  Slack Integration Complete!${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "Alerts level $ALERT_LEVEL and above will be sent to Slack."
    echo ""

    if $INSTALL_LISTENER; then
        echo -e "${YELLOW}Slash Commands:${NC}"
        echo "  /wazuh level <N>  - Set alert level (1-15)"
        echo "  /wazuh mute       - Mute alerts"
        echo "  /wazuh unmute     - Resume alerts"
        echo "  /wazuh status     - Show config"
        echo ""
        echo "Service: systemctl status wazuh-slack-bot"
        echo ""
    fi

    echo "Test with: logger -t security 'Authentication failure'"
    echo ""
}

# Main
show_banner
check_root
check_wazuh
prompt_config

echo -e "${YELLOW}Summary${NC}"
echo "-------------------------------------------------------------"
echo -e "  Bot Token:   ${GREEN}${BOT_TOKEN:0:20}...${NC}"
if [[ -n "$APP_TOKEN" ]]; then
    echo -e "  App Token:   ${GREEN}${APP_TOKEN:0:20}...${NC}"
else
    echo -e "  App Token:   ${YELLOW}Not provided${NC}"
fi
echo -e "  Channel:     ${GREEN}$CHANNEL_ID${NC}"
echo -e "  Level:       ${GREEN}$ALERT_LEVEL+${NC}"
echo -e "  Commands:    ${GREEN}$(if $INSTALL_LISTENER; then echo 'Yes'; else echo 'No'; fi)${NC}"
echo ""

read -p "Proceed? [Y/n]: " confirm
if [[ "${confirm,,}" == "n" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
validate_bot_token || exit 1
validate_app_token

echo ""
test_slack || exit 1

echo ""
install_dependencies
install_integration
create_config_files
install_bot_listener
configure_ossec
restart_wazuh

print_summary
