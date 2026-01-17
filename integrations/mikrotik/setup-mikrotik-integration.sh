#!/bin/bash
#
# MikroTik RouterOS Integration Setup for Wazuh
# Automatically configures both Wazuh and MikroTik router
#
# Usage: sudo ./setup-mikrotik-integration.sh
#
# Supports:
#   - Automatic Wazuh configuration (decoders, rules, syslog)
#   - MikroTik REST API auto-configuration (RouterOS 7.1+)
#   - Manual command output for older RouterOS versions
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
DECODERS_DIR="/var/ossec/etc/decoders"
RULES_DIR="/var/ossec/etc/rules"

# Default values
ROUTER_IP=""
WAZUH_IP=""
ROUTER_USER="admin"
ROUTER_PASS=""
USE_API=false

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     MikroTik RouterOS Integration for Wazuh              ║${NC}"
    echo -e "${CYAN}║     Automated Setup Script                               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    cat << EOF
Usage: sudo $(basename "$0") [OPTIONS]

Automatically configure Wazuh to receive logs from MikroTik routers.

OPTIONS:
  -r, --router IP       MikroTik router IP address (required)
  -w, --wazuh IP        Wazuh server IP address (auto-detected if not specified)
  -u, --user USER       MikroTik admin username (default: admin)
  -p, --password PASS   MikroTik admin password (for API config)
  -a, --api             Use MikroTik REST API to auto-configure router
  -m, --manual          Only show manual commands (no API config)
  -h, --help            Show this help message

EXAMPLES:
  # Interactive setup
  sudo $(basename "$0")

  # Auto-configure with API
  sudo $(basename "$0") -r 192.168.88.1 -u admin -p MyPassword -a

  # Manual setup (just configure Wazuh, print router commands)
  sudo $(basename "$0") -r 192.168.88.1 -m

EOF
    exit 0
}

detect_wazuh_ip() {
    # Skip if already set via command line
    if [[ -n "$WAZUH_IP" ]]; then
        return 0
    fi

    # Method 1: Check if Wazuh manager is running and get IP from ossec.conf
    if [[ -f "$OSSEC_CONF" ]]; then
        # Try to extract local_ip from existing remote config
        local conf_ip=$(grep -oP '(?<=<local_ip>)[^<]+' "$OSSEC_CONF" 2>/dev/null | head -1)
        if [[ -n "$conf_ip" && "$conf_ip" != "0.0.0.0" ]]; then
            WAZUH_IP="$conf_ip"
            log_info "Detected Wazuh IP from ossec.conf: $WAZUH_IP"
            return 0
        fi
    fi

    # Method 2: Get IP on same subnet as router (for local network setups)
    if [[ -n "$ROUTER_IP" ]]; then
        local router_subnet=$(echo "$ROUTER_IP" | cut -d'.' -f1-3)
        local subnet_ip=$(ip -4 addr show | grep -oP "(?<=inet )${router_subnet}\.\d+" | head -1)
        if [[ -n "$subnet_ip" ]]; then
            WAZUH_IP="$subnet_ip"
            log_info "Detected Wazuh IP from network interface: $WAZUH_IP"
            return 0
        fi
    fi

    # Method 3: Get IP of interface with default route
    local default_ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP '(?<=src )\d+\.\d+\.\d+\.\d+' | head -1)
    if [[ -n "$default_ip" ]]; then
        WAZUH_IP="$default_ip"
        log_info "Detected Wazuh IP from default route: $WAZUH_IP"
        return 0
    fi

    # Method 4: Fallback to primary IP from hostname
    WAZUH_IP=$(hostname -I | awk '{print $1}')
    if [[ -n "$WAZUH_IP" ]]; then
        log_info "Detected Wazuh IP from hostname: $WAZUH_IP"
    fi
}

prompt_config() {
    echo -e "${YELLOW}Configuration${NC}"
    echo "─────────────────────────────────────────────────────────"

    # Router IP
    if [[ -z "$ROUTER_IP" ]]; then
        read -p "MikroTik router IP [192.168.88.1]: " ROUTER_IP
        ROUTER_IP=${ROUTER_IP:-192.168.88.1}
    fi

    # Wazuh IP
    detect_wazuh_ip
    read -p "Wazuh server IP [$WAZUH_IP]: " input_wazuh
    WAZUH_IP=${input_wazuh:-$WAZUH_IP}

    # Configuration method
    echo ""
    echo "How should the router be configured?"
    echo "  1) API - Automatically via MikroTik REST API (RouterOS 7.1+)"
    echo "  2) Manual - Show commands to paste into router"
    read -p "Choice [1]: " config_method

    if [[ "$config_method" != "2" ]]; then
        USE_API=true
        echo ""
        echo -e "${YELLOW}MikroTik Credentials${NC}"
        read -p "Username [admin]: " input_user
        ROUTER_USER=${input_user:-admin}
        read -s -p "Password for '$ROUTER_USER': " ROUTER_PASS
        echo ""

        if [[ -z "$ROUTER_PASS" ]]; then
            log_error "Password is required for API configuration"
            exit 1
        fi
    fi

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

install_decoders() {
    log_info "Installing MikroTik decoders..."

    if [[ -f "$SCRIPT_DIR/decoders/mikrotik_decoders.xml" ]]; then
        cp "$SCRIPT_DIR/decoders/mikrotik_decoders.xml" "$DECODERS_DIR/"
        chown wazuh:wazuh "$DECODERS_DIR/mikrotik_decoders.xml"
        chmod 640 "$DECODERS_DIR/mikrotik_decoders.xml"
        log_success "Decoders installed"
    else
        log_error "Decoder file not found: $SCRIPT_DIR/decoders/mikrotik_decoders.xml"
        exit 1
    fi
}

install_rules() {
    log_info "Installing MikroTik rules..."

    if [[ -f "$SCRIPT_DIR/rules/mikrotik_rules.xml" ]]; then
        cp "$SCRIPT_DIR/rules/mikrotik_rules.xml" "$RULES_DIR/"
        chown wazuh:wazuh "$RULES_DIR/mikrotik_rules.xml"
        chmod 640 "$RULES_DIR/mikrotik_rules.xml"
        log_success "Rules installed"
    else
        log_error "Rules file not found: $SCRIPT_DIR/rules/mikrotik_rules.xml"
        exit 1
    fi
}

configure_syslog() {
    log_info "Configuring syslog reception..."

    # Check if already configured
    if grep -q "allowed-ips>$ROUTER_IP<" "$OSSEC_CONF" 2>/dev/null; then
        log_warn "Syslog already configured for $ROUTER_IP"
        return 0
    fi

    # Backup config
    cp "$OSSEC_CONF" "${OSSEC_CONF}.backup.$(date +%Y%m%d%H%M%S)"

    # Create syslog config
    local syslog_config="
  <!-- MikroTik Syslog Reception - Added by setup script -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>$ROUTER_IP</allowed-ips>
    <local_ip>$WAZUH_IP</local_ip>
  </remote>"

    # Insert before closing tag using Python (more reliable than sed)
    python3 << PYEOF
import re
with open('$OSSEC_CONF', 'r') as f:
    content = f.read()

# Insert before last </ossec_config>
insert_text = '''$syslog_config'''
content = re.sub(r'(</ossec_config>)\s*$', insert_text + r'\n\1', content)

with open('$OSSEC_CONF', 'w') as f:
    f.write(content)
PYEOF

    log_success "Syslog configuration added"
}

enable_archives() {
    log_info "Enabling log archives..."

    if grep -q "<logall>no</logall>" "$OSSEC_CONF"; then
        sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' "$OSSEC_CONF"
        log_success "Archives enabled"
    else
        log_warn "Archives already enabled or not found"
    fi
}

configure_firewall() {
    log_info "Configuring firewall..."

    if command -v ufw &> /dev/null; then
        if ! ufw status | grep -q "514/udp.*ALLOW"; then
            ufw allow 514/udp comment "Wazuh Syslog from MikroTik" > /dev/null 2>&1
            log_success "UFW: Port 514/UDP allowed"
        else
            log_warn "UFW: Port 514/UDP already allowed"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=514/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log_success "firewalld: Port 514/UDP allowed"
    else
        log_warn "No firewall detected - ensure port 514/UDP is open"
    fi
}

restart_wazuh() {
    log_info "Restarting Wazuh manager..."

    # Validate config first
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
        journalctl -u wazuh-manager --no-pager | tail -10
        exit 1
    fi
}

configure_mikrotik_api() {
    log_info "Configuring MikroTik via REST API..."

    local api_url="https://$ROUTER_IP/rest"
    local auth="$ROUTER_USER:$ROUTER_PASS"

    # Test API connection
    local test_response=$(curl -s -k -u "$auth" "$api_url/system/identity" 2>&1)

    if echo "$test_response" | grep -q "error\|401\|403"; then
        log_error "Failed to connect to MikroTik API"
        log_error "Response: $test_response"
        log_warn "Falling back to manual configuration..."
        print_manual_commands
        return 1
    fi

    local router_name=$(echo "$test_response" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
    log_success "Connected to router: $router_name"

    # Check if logging action already exists
    local existing=$(curl -s -k -u "$auth" "$api_url/system/logging/action" | grep -o '"name":"wazuh"')

    if [[ -n "$existing" ]]; then
        log_warn "Logging action 'wazuh' already exists"
    else
        # Create logging action
        log_info "Creating logging action..."
        curl -s -k -u "$auth" -X POST "$api_url/system/logging/action" \
            -H "Content-Type: application/json" \
            -d "{
                \"name\": \"wazuh\",
                \"target\": \"remote\",
                \"remote\": \"$WAZUH_IP\",
                \"remote-port\": \"514\",
                \"src-address\": \"$ROUTER_IP\"
            }" > /dev/null
        log_success "Logging action created"
    fi

    # Add logging rules for each topic
    local topics=("critical" "error" "warning" "system" "firewall" "interface" "ppp" "pppoe" "dhcp" "wireless" "account" "ovpn")

    log_info "Adding logging rules..."
    for topic in "${topics[@]}"; do
        # Check if rule exists
        local exists=$(curl -s -k -u "$auth" "$api_url/system/logging" | grep -o "\"topics\":\"$topic\".*\"action\":\"wazuh\"")

        if [[ -z "$exists" ]]; then
            curl -s -k -u "$auth" -X POST "$api_url/system/logging" \
                -H "Content-Type: application/json" \
                -d "{\"action\": \"wazuh\", \"topics\": \"$topic\"}" > /dev/null 2>&1
        fi
    done
    log_success "Logging rules configured for ${#topics[@]} topics"

    return 0
}

print_manual_commands() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  MikroTik Router Configuration Commands${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Paste these commands into your MikroTik terminal (Winbox or SSH):"
    echo ""
    echo -e "${GREEN}# Create logging action for Wazuh${NC}"
    echo "/system logging action add name=wazuh target=remote \\"
    echo "    remote=$WAZUH_IP remote-port=514 src-address=$ROUTER_IP"
    echo ""
    echo -e "${GREEN}# Add logging rules${NC}"
    echo "/system logging add action=wazuh topics=critical"
    echo "/system logging add action=wazuh topics=error"
    echo "/system logging add action=wazuh topics=warning"
    echo "/system logging add action=wazuh topics=system"
    echo "/system logging add action=wazuh topics=firewall"
    echo "/system logging add action=wazuh topics=interface"
    echo "/system logging add action=wazuh topics=ppp"
    echo "/system logging add action=wazuh topics=pppoe"
    echo "/system logging add action=wazuh topics=dhcp"
    echo "/system logging add action=wazuh topics=wireless"
    echo "/system logging add action=wazuh topics=account"
    echo "/system logging add action=wazuh topics=ovpn"
    echo ""
}

verify_setup() {
    echo ""
    log_info "Verifying setup..."

    # Check syslog port
    if ss -ulnp | grep -q ":514"; then
        log_success "Syslog port 514/UDP is listening"
    else
        log_error "Syslog port 514/UDP not listening"
    fi

    # Check decoders
    if [[ -f "$DECODERS_DIR/mikrotik_decoders.xml" ]]; then
        log_success "MikroTik decoders installed"
    else
        log_error "MikroTik decoders missing"
    fi

    # Check rules
    if [[ -f "$RULES_DIR/mikrotik_rules.xml" ]]; then
        log_success "MikroTik rules installed"
    else
        log_error "MikroTik rules missing"
    fi
}

print_test_instructions() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Setup Complete!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Test the integration:${NC}"
    echo ""
    echo "1. Generate a test log on MikroTik:"
    echo "   /log warning message=\"Wazuh integration test\""
    echo ""
    echo "2. Watch for logs on Wazuh:"
    echo "   tail -f /var/ossec/logs/archives/archives.log | grep $ROUTER_IP"
    echo ""
    echo "3. Check alerts:"
    echo "   tail -f /var/ossec/logs/alerts/alerts.log"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--router)    ROUTER_IP="$2"; shift 2 ;;
        -w|--wazuh)     WAZUH_IP="$2"; shift 2 ;;
        -u|--user)      ROUTER_USER="$2"; shift 2 ;;
        -p|--password)  ROUTER_PASS="$2"; shift 2 ;;
        -a|--api)       USE_API=true; shift ;;
        -m|--manual)    USE_API=false; shift ;;
        -h|--help)      show_help ;;
        *)              log_error "Unknown option: $1"; show_help ;;
    esac
done

# Main
show_banner
check_root
check_wazuh

# Get configuration if not provided via args
if [[ -z "$ROUTER_IP" ]]; then
    prompt_config
else
    detect_wazuh_ip
fi

echo ""
echo -e "${YELLOW}Configuration Summary${NC}"
echo "─────────────────────────────────────────────────────────"
echo -e "  Router IP:  ${GREEN}$ROUTER_IP${NC}"
echo -e "  Wazuh IP:   ${GREEN}$WAZUH_IP${NC}"
echo -e "  Config:     ${GREEN}$(if $USE_API; then echo "REST API"; else echo "Manual"; fi)${NC}"
echo ""

read -p "Proceed with installation? [Y/n]: " confirm
if [[ "${confirm,,}" == "n" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo -e "${YELLOW}Configuring Wazuh...${NC}"
echo "─────────────────────────────────────────────────────────"
install_decoders
install_rules
configure_syslog
enable_archives
configure_firewall
restart_wazuh

if $USE_API && [[ -n "$ROUTER_PASS" ]]; then
    echo ""
    echo -e "${YELLOW}Configuring MikroTik...${NC}"
    echo "─────────────────────────────────────────────────────────"
    configure_mikrotik_api || true
else
    print_manual_commands
fi

verify_setup
print_test_instructions
