#!/bin/bash
#
# Telegram Integration Setup for Wazuh
# Sends alert notifications to Telegram via Bot API
#
# Usage: sudo ./setup-telegram-integration.sh
#
# Prerequisites:
#   1. Create a Telegram bot via @BotFather
#   2. Get your Chat ID (message @userinfobot or @getidsbot)
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

# Default values
BOT_TOKEN=""
CHAT_ID=""
ALERT_LEVEL=7
INSTALL_LISTENER=true

log_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Telegram Integration for Wazuh                       ║${NC}"
    echo -e "${CYAN}║     Alert Notifications via Bot API                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    cat << EOF
Usage: sudo $(basename "$0") [OPTIONS]

Configure Wazuh to send alert notifications to Telegram.

OPTIONS:
  -t, --token TOKEN     Telegram Bot Token (from @BotFather)
  -c, --chat-id ID      Telegram Chat ID (user or group)
  -l, --level LEVEL     Minimum alert level to notify (default: 7)
  --no-listener         Don't install the bot command listener
  -h, --help            Show this help message

EXAMPLES:
  # Interactive setup
  sudo $(basename "$0")

  # Non-interactive setup
  sudo $(basename "$0") -t "123456:ABC-DEF" -c "-1001234567890" -l 7

HOW TO GET CREDENTIALS:
  1. Bot Token: Message @BotFather on Telegram, send /newbot
  2. Chat ID: Message @userinfobot or @getidsbot to get your ID
     For groups: Add bot to group, send a message, then use:
     curl "https://api.telegram.org/bot<TOKEN>/getUpdates"

BOT COMMANDS (when listener is enabled):
  /level <N>  - Set minimum alert level (1-15)
  /level      - Show current level
  /mute       - Mute all alerts
  /mute <min> - Mute for N minutes
  /unmute     - Resume alerts
  /status     - Show current configuration
  /help       - Show available commands

EOF
    exit 0
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
    echo -e "${YELLOW}Telegram Configuration${NC}"
    echo "─────────────────────────────────────────────────────────"
    echo ""
    echo "To get your Bot Token:"
    echo "  1. Open Telegram and message @BotFather"
    echo "  2. Send /newbot and follow the prompts"
    echo "  3. Copy the token (looks like: 123456789:ABC-DEF...)"
    echo ""

    if [[ -z "$BOT_TOKEN" ]]; then
        read -p "Bot Token: " BOT_TOKEN
        if [[ -z "$BOT_TOKEN" ]]; then
            log_error "Bot token is required"
            exit 1
        fi
    fi

    echo ""
    echo "To get your Chat ID:"
    echo "  - For personal: Message @userinfobot"
    echo "  - For groups: Add bot to group, then check getUpdates API"
    echo ""

    if [[ -z "$CHAT_ID" ]]; then
        read -p "Chat ID: " CHAT_ID
        if [[ -z "$CHAT_ID" ]]; then
            log_error "Chat ID is required"
            exit 1
        fi
    fi

    echo ""
    read -p "Minimum alert level to notify [$ALERT_LEVEL]: " input_level
    ALERT_LEVEL=${input_level:-$ALERT_LEVEL}

    echo ""
    echo "The bot listener allows you to change settings via Telegram commands"
    echo "(e.g., /level 5, /mute, /unmute) without restarting Wazuh."
    echo ""
    read -p "Install bot command listener? [Y/n]: " install_listener
    if [[ "${install_listener,,}" == "n" ]]; then
        INSTALL_LISTENER=false
    fi

    echo ""
}

test_telegram() {
    log_info "Testing Telegram connection..."

    local response=$(curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{
            \"chat_id\": \"${CHAT_ID}\",
            \"text\": \"✅ *Wazuh Integration Test*\n\nTelegram notifications configured successfully!\n\nAlert level: ${ALERT_LEVEL}+\n\nBot commands: $(if $INSTALL_LISTENER; then echo 'Enabled'; else echo 'Disabled'; fi)\",
            \"parse_mode\": \"Markdown\"
        }" 2>&1)

    if echo "$response" | grep -q '"ok":true'; then
        log_success "Test message sent successfully!"
        return 0
    else
        log_error "Failed to send test message"
        log_error "Response: $response"
        return 1
    fi
}

install_integration() {
    log_info "Installing Telegram integration script..."

    # Copy the Python script
    if [[ -f "$SCRIPT_DIR/custom-telegram.py" ]]; then
        cp "$SCRIPT_DIR/custom-telegram.py" "$INTEGRATIONS_DIR/custom-telegram.py"
        chmod 750 "$INTEGRATIONS_DIR/custom-telegram.py"
        chown root:wazuh "$INTEGRATIONS_DIR/custom-telegram.py"
        log_success "Integration script installed"
    else
        log_error "Integration script not found: $SCRIPT_DIR/custom-telegram.py"
        exit 1
    fi

    # Ensure requests module is available
    if ! python3 -c "import requests" 2>/dev/null; then
        log_info "Installing Python requests module..."
        pip3 install requests -q || apt-get install -y python3-requests -qq
    fi
}

install_bot_listener() {
    if ! $INSTALL_LISTENER; then
        return 0
    fi

    log_info "Installing bot command listener..."

    # Copy the listener script
    if [[ -f "$SCRIPT_DIR/telegram-bot-listener.py" ]]; then
        cp "$SCRIPT_DIR/telegram-bot-listener.py" "$INTEGRATIONS_DIR/telegram-bot-listener.py"
        chmod 750 "$INTEGRATIONS_DIR/telegram-bot-listener.py"
        chown root:root "$INTEGRATIONS_DIR/telegram-bot-listener.py"
        log_success "Bot listener script installed"
    else
        log_warn "Bot listener script not found, skipping"
        return 0
    fi

    # Create credentials config file
    log_info "Creating credentials configuration..."
    cat > "$CONFIG_DIR/telegram-credentials.conf" << EOF
{
  "bot_token": "${BOT_TOKEN}",
  "chat_ids": ["${CHAT_ID}"]
}
EOF
    chmod 600 "$CONFIG_DIR/telegram-credentials.conf"
    log_success "Credentials saved to $CONFIG_DIR/telegram-credentials.conf"

    # Create initial telegram.conf with default settings
    log_info "Creating dynamic configuration..."
    cat > "$CONFIG_DIR/telegram.conf" << EOF
{
  "level": ${ALERT_LEVEL},
  "muted": false,
  "muted_until": null,
  "last_updated": "$(date -Iseconds)",
  "updated_by": "setup-script"
}
EOF
    chmod 644 "$CONFIG_DIR/telegram.conf"
    log_success "Dynamic config saved to $CONFIG_DIR/telegram.conf"

    # Install systemd service
    if [[ -f "$SCRIPT_DIR/wazuh-telegram-bot.service" ]]; then
        log_info "Installing systemd service..."
        cp "$SCRIPT_DIR/wazuh-telegram-bot.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable wazuh-telegram-bot
        systemctl start wazuh-telegram-bot

        sleep 2
        if systemctl is-active --quiet wazuh-telegram-bot; then
            log_success "Bot listener service started"
        else
            log_warn "Bot listener service failed to start"
            log_warn "Check: journalctl -u wazuh-telegram-bot"
        fi
    else
        log_warn "Service file not found, skipping systemd setup"
    fi
}

configure_ossec() {
    log_info "Configuring ossec.conf..."

    # Use level 1 in ossec.conf to let the script handle filtering
    # This allows dynamic level changes without restarting Wazuh
    local ossec_level=1
    if ! $INSTALL_LISTENER; then
        # If no listener, use the actual level in ossec.conf
        ossec_level=$ALERT_LEVEL
    fi

    # Check if integration already exists
    if grep -q "custom-telegram" "$OSSEC_CONF" 2>/dev/null; then
        log_warn "Telegram integration already configured"
        read -p "Replace existing configuration? [y/N]: " replace
        if [[ "${replace,,}" != "y" ]]; then
            return 0
        fi
        # Remove existing config
        python3 << PYEOF
import re
with open('$OSSEC_CONF', 'r') as f:
    content = f.read()

# Remove existing telegram integration block
pattern = r'\s*<integration>.*?custom-telegram.*?</integration>'
content = re.sub(pattern, '', content, flags=re.DOTALL)

with open('$OSSEC_CONF', 'w') as f:
    f.write(content)
PYEOF
    fi

    # Backup config
    cp "$OSSEC_CONF" "${OSSEC_CONF}.backup.$(date +%Y%m%d%H%M%S)"

    # Add integration config
    local integration_config="
  <!-- Telegram Alert Notifications -->
  <integration>
    <name>custom-telegram.py</name>
    <hook_url>${BOT_TOKEN}:${CHAT_ID}</hook_url>
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
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Telegram Integration Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "You will receive Telegram notifications for alerts level $ALERT_LEVEL and above."
    echo ""

    if $INSTALL_LISTENER; then
        echo -e "${YELLOW}Bot Commands Available:${NC}"
        echo "  /level <N>  - Set minimum alert level (1-15)"
        echo "  /level      - Show current level"
        echo "  /mute       - Mute all alerts"
        echo "  /mute <min> - Mute for N minutes"
        echo "  /unmute     - Resume alerts"
        echo "  /status     - Show current configuration"
        echo "  /help       - Show all commands"
        echo ""
        echo "Service status: systemctl status wazuh-telegram-bot"
        echo ""
    fi

    echo "Test by generating an alert:"
    echo "  logger -t security 'Authentication failure for user test'"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--token)       BOT_TOKEN="$2"; shift 2 ;;
        -c|--chat-id)     CHAT_ID="$2"; shift 2 ;;
        -l|--level)       ALERT_LEVEL="$2"; shift 2 ;;
        --no-listener)    INSTALL_LISTENER=false; shift ;;
        -h|--help)        show_help ;;
        *)                shift ;;
    esac
done

# Main
show_banner
check_root
check_wazuh

# Get configuration
if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
    prompt_config
fi

echo ""
echo -e "${YELLOW}Configuration Summary${NC}"
echo "─────────────────────────────────────────────────────────"
echo -e "  Bot Token:     ${GREEN}${BOT_TOKEN:0:10}...${NC}"
echo -e "  Chat ID:       ${GREEN}$CHAT_ID${NC}"
echo -e "  Alert Level:   ${GREEN}$ALERT_LEVEL+${NC}"
echo -e "  Bot Listener:  ${GREEN}$(if $INSTALL_LISTENER; then echo 'Yes'; else echo 'No'; fi)${NC}"
echo ""

read -p "Proceed with installation? [Y/n]: " confirm
if [[ "${confirm,,}" == "n" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
test_telegram || exit 1

echo ""
install_integration
install_bot_listener
configure_ossec
restart_wazuh

print_summary
