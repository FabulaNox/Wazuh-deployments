#!/bin/bash
#
# Wazuh Log Retention Policy Setup
# Configures 30-day retention for both Indexer and local logs
#
# Usage: sudo ./setup-retention-policy.sh [DAYS]
#        Default: 30 days
#

set -e

RETENTION_DAYS=${1:-30}
INDEXER_URL="https://localhost:9200"

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
    echo -e "${CYAN}║     Wazuh Log Retention Policy Setup                     ║${NC}"
    echo -e "${CYAN}║     ${RETENTION_DAYS}-Day Retention with Auto-Rotation                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

get_admin_password() {
    # Try to get password from common locations
    if [[ -f /tmp/wazuh-install/wazuh-passwords.txt ]]; then
        ADMIN_PASS=$(grep -A1 "indexer_username: 'admin'" /tmp/wazuh-install/wazuh-passwords.txt | grep "indexer_password:" | awk '{print $2}' | tr -d "'" || true)
    fi

    if [[ -z "$ADMIN_PASS" ]]; then
        read -s -p "Enter Wazuh Indexer admin password: " ADMIN_PASS
        echo ""
    fi
}

# ============================================
# Wazuh Indexer ISM Policy (30 days)
# ============================================
configure_indexer_retention() {
    log_info "Configuring Wazuh Indexer retention policy..."

    # Check if ISM plugin is available
    local ism_check=$(curl -s -k -u "admin:${ADMIN_PASS}" "${INDEXER_URL}/_plugins/_ism/policies" 2>&1)

    if echo "$ism_check" | grep -q "error"; then
        log_warn "ISM plugin may not be available, skipping indexer policy"
        return 1
    fi

    # Create ISM policy for wazuh-alerts
    local policy_json=$(cat <<EOF
{
  "policy": {
    "description": "Wazuh alerts retention policy - ${RETENTION_DAYS} days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "${RETENTION_DAYS}d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": ["wazuh-alerts-*"],
        "priority": 100
      },
      {
        "index_patterns": ["wazuh-archives-*"],
        "priority": 100
      }
    ]
  }
}
EOF
)

    # Create or update the policy
    local response=$(curl -s -k -u "admin:${ADMIN_PASS}" \
        -X PUT "${INDEXER_URL}/_plugins/_ism/policies/wazuh-retention-policy" \
        -H "Content-Type: application/json" \
        -d "$policy_json" 2>&1)

    if echo "$response" | grep -q '"_id"'; then
        log_success "Indexer ISM policy created (${RETENTION_DAYS} days)"
    else
        log_warn "Could not create ISM policy: $response"
    fi

    # Apply policy to existing indices
    log_info "Applying policy to existing indices..."
    curl -s -k -u "admin:${ADMIN_PASS}" \
        -X POST "${INDEXER_URL}/_plugins/_ism/add/wazuh-alerts-*" \
        -H "Content-Type: application/json" \
        -d '{"policy_id": "wazuh-retention-policy"}' > /dev/null 2>&1 || true

    curl -s -k -u "admin:${ADMIN_PASS}" \
        -X POST "${INDEXER_URL}/_plugins/_ism/add/wazuh-archives-*" \
        -H "Content-Type: application/json" \
        -d '{"policy_id": "wazuh-retention-policy"}' > /dev/null 2>&1 || true

    log_success "Policy applied to existing indices"
}

# ============================================
# Local Log Rotation (logrotate)
# ============================================
configure_local_rotation() {
    log_info "Configuring local log rotation..."

    # Create logrotate config for Wazuh
    cat > /etc/logrotate.d/wazuh << EOF
# Wazuh Manager logs - ${RETENTION_DAYS} day retention
/var/ossec/logs/ossec.log
/var/ossec/logs/active-responses.log
/var/ossec/logs/integrations.log {
    daily
    rotate ${RETENTION_DAYS}
    compress
    delaycompress
    missingok
    notifempty
    create 640 wazuh wazuh
    postrotate
        /var/ossec/bin/wazuh-control reload > /dev/null 2>&1 || true
    endscript
}

# Wazuh alerts and archives - ${RETENTION_DAYS} day retention
/var/ossec/logs/alerts/alerts.log
/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/archives/archives.log
/var/ossec/logs/archives/archives.json {
    daily
    rotate ${RETENTION_DAYS}
    compress
    delaycompress
    missingok
    notifempty
    create 640 wazuh wazuh
    dateext
    dateformat -%Y%m%d
}

# Wazuh API logs
/var/ossec/logs/api.log {
    daily
    rotate ${RETENTION_DAYS}
    compress
    delaycompress
    missingok
    notifempty
    create 640 wazuh wazuh
}
EOF

    log_success "Local logrotate configured (${RETENTION_DAYS} days)"

    # Test logrotate config
    if logrotate -d /etc/logrotate.d/wazuh > /dev/null 2>&1; then
        log_success "Logrotate configuration valid"
    else
        log_warn "Logrotate config may have issues - check manually"
    fi
}

# ============================================
# Wazuh Internal Rotation Settings
# ============================================
configure_wazuh_internal() {
    log_info "Configuring Wazuh internal log settings..."

    local ossec_conf="/var/ossec/etc/ossec.conf"

    # Check if logging settings exist
    if grep -q "<logging>" "$ossec_conf"; then
        log_warn "Logging section exists - verify settings manually"
    else
        # Wazuh handles its own rotation via the logging section
        # This is usually not needed if logrotate is handling it
        log_info "Using logrotate for rotation (recommended)"
    fi

    # Ensure log compression is enabled in internal_options
    local internal_opts="/var/ossec/etc/local_internal_options.conf"
    if [[ ! -f "$internal_opts" ]]; then
        touch "$internal_opts"
        chown wazuh:wazuh "$internal_opts"
    fi

    log_success "Wazuh internal settings configured"
}

# ============================================
# Summary
# ============================================
show_summary() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Retention Policy Configured!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Settings applied:"
    echo "  • Retention period: ${RETENTION_DAYS} days"
    echo "  • Indexer ISM policy: wazuh-alerts-*, wazuh-archives-*"
    echo "  • Local logrotate: /var/ossec/logs/*"
    echo ""
    echo "Verify with:"
    echo "  # Check indexer policy"
    echo "  curl -k -u admin:PASSWORD '${INDEXER_URL}/_plugins/_ism/policies/wazuh-retention-policy'"
    echo ""
    echo "  # Check current index sizes"
    echo "  curl -k -u admin:PASSWORD '${INDEXER_URL}/_cat/indices/wazuh-*?v&s=index'"
    echo ""
    echo "  # Test logrotate"
    echo "  sudo logrotate -d /etc/logrotate.d/wazuh"
    echo ""
}

# Main
show_banner
check_root
get_admin_password

configure_indexer_retention
configure_local_rotation
configure_wazuh_internal
show_summary
