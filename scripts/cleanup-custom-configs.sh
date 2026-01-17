#!/bin/bash
#
# Cleanup script for custom Wazuh configurations
# Removes all custom rules, decoders, and integrations added by this repository
#
# Usage: sudo ./cleanup-custom-configs.sh [--keep-wazuh]
#
# Options:
#   --keep-wazuh    Only remove custom configs, don't uninstall Wazuh itself
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

KEEP_WAZUH=false

log_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Wazuh Custom Configuration Cleanup                   ║${NC}"
    echo -e "${CYAN}║     Removes integrations and custom rules                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-wazuh) KEEP_WAZUH=true; shift ;;
        *) shift ;;
    esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

show_banner

# ============================================
# Remove MikroTik Integration
# ============================================
log_info "Removing MikroTik integration..."

# Remove decoder
if [[ -f "/var/ossec/etc/decoders/mikrotik_decoders.xml" ]]; then
    rm -f "/var/ossec/etc/decoders/mikrotik_decoders.xml"
    log_success "Removed MikroTik decoders"
else
    log_warn "MikroTik decoders not found (skipped)"
fi

# Remove rules
if [[ -f "/var/ossec/etc/rules/mikrotik_rules.xml" ]]; then
    rm -f "/var/ossec/etc/rules/mikrotik_rules.xml"
    log_success "Removed MikroTik rules"
else
    log_warn "MikroTik rules not found (skipped)"
fi

# Remove MikroTik syslog config from ossec.conf
if [[ -f "/var/ossec/etc/ossec.conf" ]]; then
    if grep -q "MikroTik Syslog Reception" "/var/ossec/etc/ossec.conf"; then
        log_info "Removing MikroTik syslog config from ossec.conf..."
        # Use Python for reliable multi-line removal
        python3 << 'PYEOF'
import re

conf_path = '/var/ossec/etc/ossec.conf'
with open(conf_path, 'r') as f:
    content = f.read()

# Remove MikroTik remote block (including comment)
pattern = r'\s*<!-- MikroTik Syslog Reception[^>]*-->.*?<remote>.*?</remote>'
content = re.sub(pattern, '', content, flags=re.DOTALL)

# Clean up extra blank lines
content = re.sub(r'\n{3,}', '\n\n', content)

with open(conf_path, 'w') as f:
    f.write(content)
PYEOF
        log_success "Removed MikroTik syslog config"
    fi
fi

# ============================================
# Remove User Management Security Rules
# ============================================
log_info "Removing user management security rules..."

# Remove local_rules.xml if it only contains our custom rules
if [[ -f "/var/ossec/etc/rules/local_rules.xml" ]]; then
    if grep -q "wazuh-user-management" "/var/ossec/etc/rules/local_rules.xml"; then
        # Check if file has other rules besides ours (IDs 100001-100004)
        other_rules=$(grep -c '<rule id="' "/var/ossec/etc/rules/local_rules.xml" 2>/dev/null || echo 0)
        our_rules=$(grep -cE '<rule id="10000[1-4]"' "/var/ossec/etc/rules/local_rules.xml" 2>/dev/null || echo 0)

        if [[ "$other_rules" -eq "$our_rules" ]]; then
            rm -f "/var/ossec/etc/rules/local_rules.xml"
            log_success "Removed local_rules.xml (only contained our rules)"
        else
            log_warn "local_rules.xml contains other rules - manual cleanup needed"
        fi
    else
        log_warn "local_rules.xml doesn't contain our rules (skipped)"
    fi
else
    log_warn "local_rules.xml not found (skipped)"
fi

# Remove custom log file
if [[ -f "/var/log/wazuh-user-management.log" ]]; then
    rm -f "/var/log/wazuh-user-management.log"
    log_success "Removed user management log file"
fi

# Remove localfile monitoring from ossec.conf
if [[ -f "/var/ossec/etc/ossec.conf" ]]; then
    if grep -q "wazuh-user-management.log" "/var/ossec/etc/ossec.conf"; then
        log_info "Removing user management log monitoring from ossec.conf..."
        python3 << 'PYEOF'
import re

conf_path = '/var/ossec/etc/ossec.conf'
with open(conf_path, 'r') as f:
    content = f.read()

# Remove localfile block for user management
pattern = r'\s*<!-- Custom log for user management[^>]*-->.*?<localfile>.*?wazuh-user-management\.log.*?</localfile>'
content = re.sub(pattern, '', content, flags=re.DOTALL)

# Clean up extra blank lines
content = re.sub(r'\n{3,}', '\n\n', content)

with open(conf_path, 'w') as f:
    f.write(content)
PYEOF
        log_success "Removed user management log monitoring"
    fi
fi

# ============================================
# Remove Telegram Integration
# ============================================
log_info "Removing Telegram integration..."

# Remove integration script
if [[ -f "/var/ossec/integrations/custom-telegram.py" ]]; then
    rm -f "/var/ossec/integrations/custom-telegram.py"
    log_success "Removed Telegram integration script"
else
    log_warn "Telegram integration script not found (skipped)"
fi

# Remove Telegram config from ossec.conf
if [[ -f "/var/ossec/etc/ossec.conf" ]]; then
    if grep -q "custom-telegram" "/var/ossec/etc/ossec.conf"; then
        log_info "Removing Telegram config from ossec.conf..."
        python3 << 'PYEOF'
import re

conf_path = '/var/ossec/etc/ossec.conf'
with open(conf_path, 'r') as f:
    content = f.read()

# Remove Telegram integration block
pattern = r'\s*<!-- Telegram Alert Notifications -->.*?<integration>.*?custom-telegram.*?</integration>'
content = re.sub(pattern, '', content, flags=re.DOTALL)

# Clean up extra blank lines
content = re.sub(r'\n{3,}', '\n\n', content)

with open(conf_path, 'w') as f:
    f.write(content)
PYEOF
        log_success "Removed Telegram config"
    fi
fi

# ============================================
# Remove ossec.conf backups
# ============================================
log_info "Removing ossec.conf backups..."
backup_count=$(ls -1 /var/ossec/etc/ossec.conf.backup.* 2>/dev/null | wc -l || echo 0)
if [[ "$backup_count" -gt 0 ]]; then
    rm -f /var/ossec/etc/ossec.conf.backup.*
    log_success "Removed $backup_count ossec.conf backup(s)"
else
    log_warn "No ossec.conf backups found"
fi

# ============================================
# Remove Firewall Rules
# ============================================
log_info "Removing firewall rules..."

if command -v ufw &> /dev/null; then
    # Get list of Wazuh-related UFW rules
    ufw_rules=$(ufw status numbered 2>/dev/null | grep -E "Wazuh|MikroTik" || true)

    if [[ -n "$ufw_rules" ]]; then
        # Delete rules by comment (safer than by number)
        ufw delete allow 443/tcp 2>/dev/null || true
        ufw delete allow 1514/tcp 2>/dev/null || true
        ufw delete allow 1515/tcp 2>/dev/null || true
        ufw delete allow 514/udp 2>/dev/null || true
        log_success "Removed UFW rules for Wazuh"
    else
        log_warn "No Wazuh UFW rules found"
    fi
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --remove-port=443/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=1514/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=1515/tcp 2>/dev/null || true
    firewall-cmd --permanent --remove-port=514/udp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log_success "Removed firewalld rules for Wazuh"
fi

# ============================================
# Uninstall Wazuh (unless --keep-wazuh)
# ============================================
if [[ "$KEEP_WAZUH" == "false" ]]; then
    echo ""
    log_info "Uninstalling Wazuh..."

    # Download and run official uninstall
    cd /tmp
    curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
    chmod +x wazuh-install.sh
    bash wazuh-install.sh --uninstall 2>/dev/null || true
    rm -f wazuh-install.sh

    log_success "Wazuh uninstalled"

    # Clean up any remaining directories
    rm -rf /var/ossec 2>/dev/null || true
    rm -rf /etc/wazuh-* 2>/dev/null || true
    rm -rf /var/log/wazuh-* 2>/dev/null || true

    log_success "Cleaned up remaining Wazuh directories"
else
    echo ""
    log_warn "Keeping Wazuh installed (--keep-wazuh specified)"
    log_info "Restarting Wazuh manager to apply config changes..."
    systemctl restart wazuh-manager 2>/dev/null || true
fi

# ============================================
# Summary
# ============================================
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Removed:"
echo "  • MikroTik integration (decoders, rules, syslog config)"
echo "  • Telegram integration (script, ossec.conf config)"
echo "  • User management security rules"
echo "  • Firewall rules (UFW/firewalld)"
echo "  • Configuration backups"
if [[ "$KEEP_WAZUH" == "false" ]]; then
    echo "  • Wazuh installation"
fi
echo ""
