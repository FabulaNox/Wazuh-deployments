#!/bin/bash
#
# Wazuh Active Response Setup
# Configures automatic blocking of malicious IPs
#
# Features:
#   - Block IPs after brute force attempts
#   - Block port scanners
#   - Block after multiple authentication failures
#   - Configurable block duration
#
# Usage: sudo ./setup-active-response.sh [BLOCK_MINUTES]
#        Default: 60 minutes
#

set -e

BLOCK_TIME=${1:-60}
OSSEC_CONF="/var/ossec/etc/ossec.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Wazuh Active Response Setup                          ║${NC}"
    echo -e "${CYAN}║     Automatic Threat Blocking                            ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
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
        log_error "Wazuh manager not found"
        exit 1
    fi
    log_success "Wazuh manager detected"
}

backup_config() {
    cp "$OSSEC_CONF" "${OSSEC_CONF}.backup.$(date +%Y%m%d%H%M%S)"
    log_success "Configuration backed up"
}

# ============================================
# Configure Active Response
# ============================================
configure_active_response() {
    log_info "Configuring Active Response..."

    # Check if already configured
    if grep -q "active-response" "$OSSEC_CONF" && grep -q "firewall-drop" "$OSSEC_CONF"; then
        log_warn "Active Response appears to be configured"
        read -p "Overwrite existing configuration? [y/N]: " overwrite
        if [[ "${overwrite,,}" != "y" ]]; then
            return 0
        fi
        # Remove existing active-response blocks
        python3 << 'PYEOF'
import re
with open('/var/ossec/etc/ossec.conf', 'r') as f:
    content = f.read()
# Remove existing active-response and command blocks for our commands
content = re.sub(r'\s*<!-- Active Response Configuration -->.*?<!-- End Active Response -->', '', content, flags=re.DOTALL)
content = re.sub(r'\n{3,}', '\n\n', content)
with open('/var/ossec/etc/ossec.conf', 'w') as f:
    f.write(content)
PYEOF
    fi

    # Active Response configuration
    local ar_config="
  <!-- Active Response Configuration -->

  <!-- Command: Block IP using firewall -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Command: Block IP using iptables directly -->
  <command>
    <name>iptables-drop</name>
    <executable>iptables-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Response: Block after SSH brute force (Rule 5712) -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712</rules_id>
    <timeout>${BLOCK_TIME}</timeout>
  </active-response>

  <!-- Response: Block after multiple auth failures (Rule 5503) -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5503</rules_id>
    <timeout>${BLOCK_TIME}</timeout>
  </active-response>

  <!-- Response: Block after web brute force (Rule 31164) -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>31164</rules_id>
    <timeout>${BLOCK_TIME}</timeout>
  </active-response>

  <!-- Response: Block MikroTik brute force (custom rule 100104) -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100104</rules_id>
    <timeout>${BLOCK_TIME}</timeout>
  </active-response>

  <!-- Response: Block after port scan detection (Rule 581) -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>581</rules_id>
    <timeout>${BLOCK_TIME}</timeout>
  </active-response>

  <!-- Response: Block MikroTik port scan (custom rule 100121) -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100121</rules_id>
    <timeout>${BLOCK_TIME}</timeout>
  </active-response>

  <!-- End Active Response -->"

    # Insert before closing tag
    python3 << PYEOF
import re
with open('$OSSEC_CONF', 'r') as f:
    content = f.read()

insert_text = '''$ar_config'''
content = re.sub(r'(</ossec_config>)\s*$', insert_text + r'\n\1', content)

with open('$OSSEC_CONF', 'w') as f:
    f.write(content)
PYEOF

    log_success "Active Response rules configured"
}

# ============================================
# Configure Whitelist
# ============================================
configure_whitelist() {
    log_info "Configuring whitelist..."

    # Get local network
    local local_net=$(ip route | grep -E "^192\.168\.|^10\.|^172\." | head -1 | awk '{print $1}')

    echo ""
    echo -e "${YELLOW}Important: Add trusted IPs to whitelist to prevent lockout${NC}"
    echo ""
    echo "Current network detected: ${local_net:-none}"
    echo ""

    # Check if white_list exists
    if grep -q "<white_list>" "$OSSEC_CONF"; then
        log_info "Whitelist section exists"
        echo "Current whitelist entries:"
        grep "<white_list>" "$OSSEC_CONF" | head -5
    fi

    echo ""
    read -p "Add your current IP to whitelist? [Y/n]: " add_ip
    if [[ "${add_ip,,}" != "n" ]]; then
        # Get user's IP
        local my_ip=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()' || echo "")
        if [[ -z "$my_ip" ]]; then
            read -p "Enter your IP address to whitelist: " my_ip
        fi

        if [[ -n "$my_ip" ]]; then
            # Add to whitelist if not exists
            if ! grep -q "<white_list>$my_ip</white_list>" "$OSSEC_CONF"; then
                sed -i "/<white_list>127.0.0.1<\/white_list>/a\\    <white_list>$my_ip</white_list>" "$OSSEC_CONF"
                log_success "Added $my_ip to whitelist"
            else
                log_warn "$my_ip already in whitelist"
            fi
        fi
    fi
}

# ============================================
# Verify firewall-drop script
# ============================================
verify_scripts() {
    log_info "Verifying Active Response scripts..."

    local ar_dir="/var/ossec/active-response/bin"

    if [[ -x "$ar_dir/firewall-drop" ]]; then
        log_success "firewall-drop script found and executable"
    else
        log_error "firewall-drop script not found or not executable"
        log_info "Path: $ar_dir/firewall-drop"
    fi

    # Check which firewall is available
    if command -v ufw &> /dev/null; then
        log_success "UFW detected - firewall-drop will use UFW"
    elif command -v iptables &> /dev/null; then
        log_success "iptables detected - firewall-drop will use iptables"
    elif command -v nft &> /dev/null; then
        log_success "nftables detected"
    else
        log_warn "No supported firewall detected"
    fi
}

# ============================================
# Test Configuration
# ============================================
test_config() {
    log_info "Validating configuration..."

    if /var/ossec/bin/wazuh-analysisd -t > /dev/null 2>&1; then
        log_success "Configuration is valid"
    else
        log_error "Configuration validation failed!"
        /var/ossec/bin/wazuh-analysisd -t
        exit 1
    fi
}

# ============================================
# Restart Wazuh
# ============================================
restart_wazuh() {
    log_info "Restarting Wazuh manager..."

    systemctl restart wazuh-manager
    sleep 3

    if systemctl is-active --quiet wazuh-manager; then
        log_success "Wazuh manager restarted"
    else
        log_error "Wazuh manager failed to start"
        exit 1
    fi
}

# ============================================
# Summary
# ============================================
show_summary() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Active Response Configured!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Auto-blocking enabled for:"
    echo "  • SSH brute force (Rule 5712)"
    echo "  • Multiple auth failures (Rule 5503)"
    echo "  • Web brute force (Rule 31164)"
    echo "  • Port scans (Rule 581)"
    echo "  • MikroTik brute force (Rule 100104)"
    echo "  • MikroTik port scan (Rule 100121)"
    echo ""
    echo "Block duration: ${BLOCK_TIME} minutes"
    echo ""
    echo "View blocked IPs:"
    echo "  sudo cat /var/ossec/logs/active-responses.log"
    echo ""
    echo "Manually unblock an IP:"
    echo "  sudo /var/ossec/active-response/bin/firewall-drop delete - <IP>"
    echo ""
    echo -e "${YELLOW}WARNING: Ensure your IP is whitelisted to prevent lockout!${NC}"
    echo ""
}

# Main
show_banner
check_root
check_wazuh
backup_config
configure_active_response
configure_whitelist
verify_scripts
test_config
restart_wazuh
show_summary
