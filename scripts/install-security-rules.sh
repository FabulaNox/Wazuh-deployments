#!/bin/bash
#
# Install custom Wazuh rules for user management security alerts
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_SRC="$SCRIPT_DIR/wazuh-rules/local_rules.xml"
RULES_DST="/var/ossec/etc/rules/local_rules.xml"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
CUSTOM_LOG="/var/log/wazuh-user-management.log"

echo -e "${YELLOW}Installing Wazuh security rules for user management...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Create custom log file
echo -e "[1/4] Creating custom log file..."
touch "$CUSTOM_LOG"
chmod 640 "$CUSTOM_LOG"
chown root:wazuh "$CUSTOM_LOG" 2>/dev/null || true
echo -e "${GREEN}✓ Created $CUSTOM_LOG${NC}"

# Backup existing local_rules.xml if it exists
if [[ -f "$RULES_DST" ]]; then
    echo -e "[2/4] Backing up existing rules..."
    cp "$RULES_DST" "${RULES_DST}.backup.$(date +%Y%m%d%H%M%S)"
    echo -e "${GREEN}✓ Backup created${NC}"

    # Append new rules (avoiding duplicates)
    if ! grep -q "id=\"100001\"" "$RULES_DST"; then
        echo -e "[3/4] Appending custom rules..."
        # Remove closing group tag, append new rules
        sed -i '/<\/group>/d' "$RULES_DST" 2>/dev/null || true
        cat "$RULES_SRC" >> "$RULES_DST"
        echo -e "${GREEN}✓ Rules appended${NC}"
    else
        echo -e "${YELLOW}⚠ Rules already installed, skipping${NC}"
    fi
else
    echo -e "[2/4] No existing rules file..."
    echo -e "[3/4] Installing custom rules..."
    cp "$RULES_SRC" "$RULES_DST"
    chown wazuh:wazuh "$RULES_DST"
    chmod 640 "$RULES_DST"
    echo -e "${GREEN}✓ Rules installed${NC}"
fi

# Add log monitoring to ossec.conf if not present
echo -e "[4/4] Configuring log monitoring..."
if ! grep -q "wazuh-user-management.log" "$OSSEC_CONF"; then
    # Add localfile block before closing ossec_config tag
    sed -i '/<\/ossec_config>/i \
  <!-- Custom log for user management security alerts -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/wazuh-user-management.log</location>\
  </localfile>' "$OSSEC_CONF"
    echo -e "${GREEN}✓ Log monitoring configured${NC}"
else
    echo -e "${YELLOW}⚠ Log monitoring already configured${NC}"
fi

# Restart Wazuh manager
echo ""
echo -e "${YELLOW}Restarting Wazuh manager...${NC}"
systemctl restart wazuh-manager

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo "Custom rules installed for:"
echo "  • Rule 100002: Multiple failed auth attempts (Level 15)"
echo "  • Rule 100003: Privilege escalation attempt (Level 15)"
echo ""
echo "Test with: /var/ossec/bin/wazuh-logtest"
echo ""
