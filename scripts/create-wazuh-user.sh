#!/bin/bash
#
# Create users in Wazuh with different access levels
# Supports: admin, soc-l1 (read-only), soc-l2 (read + actions)
#
# Usage: ./create-wazuh-user.sh -u <username> -r <role> [-p <password>]
#
# Roles:
#   admin   - Full administrative access
#   soc-l1  - Read-only access (monitoring, viewing alerts)
#   soc-l2  - Read + limited actions (restart agents, run scans)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Wazuh endpoints
INDEXER_URL="https://localhost:9200"
API_URL="https://localhost:55000"

# Default admin credentials location
PASSWORD_FILE="/tmp/wazuh-install/wazuh-passwords.txt"

show_help() {
    cat << EOF
Usage: $(basename "$0") -u <username> -r <role> [-p <password>] [-a <admin_password>]

Create a Wazuh user with specified access level.

Options:
  -u, --username      Username for the new account (required)
  -r, --role          Access role: admin, soc-l1, soc-l2 (required)
  -p, --password      Password for new user (will prompt if not provided)
  -a, --admin-pass    Admin password (auto-detected from install if not provided)
  -h, --help          Show this help message

Roles:
  admin    Full administrative access (all_access)
  soc-l1   Read-only SOC analyst (view alerts, agents, vulnerabilities)
  soc-l2   SOC analyst with actions (L1 + restart agents, run scans)

Examples:
  $(basename "$0") -u john.doe -r soc-l1
  $(basename "$0") -u jane.smith -r soc-l2 -p 'SecurePass123!'
  $(basename "$0") -u admin2 -r admin

EOF
    exit 0
}

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

get_admin_password() {
    if [[ -f "$PASSWORD_FILE" ]]; then
        grep -A1 "indexer_username: 'admin'" "$PASSWORD_FILE" 2>/dev/null | \
            grep "indexer_password:" | awk -F"'" '{print $2}'
    fi
}

#######################################
# Security: Generate Wazuh Alert
#######################################
generate_security_alert() {
    local alert_level=$1
    local description=$2
    local src_user=$3

    # Write to syslog (Wazuh monitors this)
    logger -p auth.alert -t "wazuh-user-script" \
        "SECURITY ALERT: Level $alert_level - $description - Source user: $src_user - Source IP: $(hostname -I | awk '{print $1}') - Hostname: $(hostname)"

    # Also write to Wazuh active responses log for guaranteed pickup
    local alert_log="/var/ossec/logs/active-responses.log"
    if [[ -w "$alert_log" ]] || [[ -w "$(dirname "$alert_log")" ]]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-user-script: CRITICAL - $description - User: $src_user" | \
            sudo tee -a "$alert_log" > /dev/null 2>&1
    fi

    # Create custom alert file for Wazuh to pick up
    local custom_log="/var/log/wazuh-user-management.log"
    echo "$(date -Iseconds) level=$alert_level type=authentication_failure description=\"$description\" src_user=\"$src_user\" src_ip=\"$(hostname -I | awk '{print $1}')\" hostname=\"$(hostname)\"" | \
        sudo tee -a "$custom_log" > /dev/null 2>&1
}

#######################################
# Security: Verify Admin Credentials
#######################################
verify_admin_credentials() {
    local admin_user=$1
    local admin_pass=$2
    local max_attempts=3
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        ((attempt++))

        # Prompt for credentials if not provided or previous attempt failed
        if [[ -z "$admin_user" ]] || [[ $attempt -gt 1 ]]; then
            echo -n "Enter admin username [admin]: "
            read admin_user
            admin_user=${admin_user:-admin}
        fi

        if [[ -z "$admin_pass" ]] || [[ $attempt -gt 1 ]]; then
            echo -n "Enter password for '$admin_user': "
            read -s admin_pass
            echo
        fi

        log_info "Verifying admin credentials (attempt $attempt/$max_attempts)..."

        # Check if credentials are valid
        local auth_response
        auth_response=$(curl -s -k -u "$admin_user:$admin_pass" \
            "$INDEXER_URL/_plugins/_security/api/account" 2>/dev/null)

        if ! echo "$auth_response" | grep -q '"user_name"'; then
            log_error "Authentication failed"

            if [[ $attempt -ge $max_attempts ]]; then
                log_error "Maximum authentication attempts exceeded!"
                log_error "Security alert generated."

                # Generate level 15 alert
                generate_security_alert 15 \
                    "Multiple failed admin authentication attempts on Wazuh user management script" \
                    "$(whoami)"

                echo ""
                echo -e "${RED}════════════════════════════════════════════════════════${NC}"
                echo -e "${RED}  SECURITY ALERT GENERATED${NC}"
                echo -e "${RED}  Too many failed authentication attempts.${NC}"
                echo -e "${RED}  This incident has been logged.${NC}"
                echo -e "${RED}════════════════════════════════════════════════════════${NC}"
                echo ""

                exit 1
            fi

            log_warn "Please try again..."
            admin_pass=""  # Clear password for retry
            continue
        fi

        # Check if user has admin role (all_access)
        local user_roles
        user_roles=$(echo "$auth_response" | grep -o '"roles":\[[^]]*\]' | tr ',' '\n')

        if ! echo "$user_roles" | grep -qE '"all_access"|"admin"'; then
            log_error "User '$admin_user' does not have admin privileges"

            if [[ $attempt -ge $max_attempts ]]; then
                log_error "Maximum attempts exceeded with non-admin user!"

                # Generate level 15 alert - potential privilege escalation attempt
                generate_security_alert 15 \
                    "Attempted use of non-admin account for user management - possible privilege escalation" \
                    "$admin_user"

                echo ""
                echo -e "${RED}════════════════════════════════════════════════════════${NC}"
                echo -e "${RED}  SECURITY ALERT GENERATED${NC}"
                echo -e "${RED}  Non-admin user attempted to create accounts.${NC}"
                echo -e "${RED}  This incident has been logged.${NC}"
                echo -e "${RED}════════════════════════════════════════════════════════${NC}"
                echo ""

                exit 1
            fi

            log_warn "Please use an account with admin privileges..."
            admin_user=""
            admin_pass=""
            continue
        fi

        # Success
        log_success "Admin credentials verified (user: $admin_user)"
        ADMIN_USER="$admin_user"
        ADMIN_PASSWORD="$admin_pass"
        return 0
    done
}

# Global admin credentials
ADMIN_USER="admin"

# Parse arguments
USERNAME=""
ROLE=""
PASSWORD=""
ADMIN_PASSWORD=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--username)  USERNAME="$2"; shift 2 ;;
        -r|--role)      ROLE="$2"; shift 2 ;;
        -p|--password)  PASSWORD="$2"; shift 2 ;;
        -a|--admin-pass) ADMIN_PASSWORD="$2"; shift 2 ;;
        -h|--help)      show_help ;;
        *)              log_error "Unknown option: $1"; show_help ;;
    esac
done

# Validate inputs
if [[ -z "$USERNAME" ]]; then
    log_error "Username is required"
    show_help
fi

if [[ -z "$ROLE" ]]; then
    log_error "Role is required"
    show_help
fi

if [[ ! "$ROLE" =~ ^(admin|soc-l1|soc-l2)$ ]]; then
    log_error "Invalid role: $ROLE (must be: admin, soc-l1, soc-l2)"
    exit 1
fi

# Try to auto-detect admin password from install
if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD=$(get_admin_password)
fi

#######################################
# Admin Authentication (with security)
#######################################
echo ""
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}  Admin Authentication Required${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

verify_admin_credentials "$ADMIN_USER" "$ADMIN_PASSWORD"

# Get new user password
echo ""
if [[ -z "$PASSWORD" ]]; then
    echo -n "Enter password for new user '$USERNAME': "
    read -s PASSWORD
    echo
    echo -n "Confirm password: "
    read -s PASSWORD_CONFIRM
    echo
    if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
        log_error "Passwords do not match"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}  Creating user: $USERNAME${NC}"
echo -e "${BLUE}  Role: $ROLE${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

#######################################
# Create Indexer Roles (if needed)
#######################################

create_indexer_role() {
    local role_name=$1
    local role_definition=$2

    log_info "Creating indexer role: $role_name"

    RESPONSE=$(curl -s -k -u "$ADMIN_USER:$ADMIN_PASSWORD" \
        -X PUT "$INDEXER_URL/_plugins/_security/api/roles/$role_name" \
        -H "Content-Type: application/json" \
        -d "$role_definition")

    if echo "$RESPONSE" | grep -qE '"status":"(CREATED|OK)"'; then
        log_success "Role '$role_name' created/updated"
    else
        log_warn "Role response: $RESPONSE"
    fi
}

# SOC L1 Role - Read Only
SOC_L1_ROLE='{
  "cluster_permissions": [
    "cluster_composite_ops_ro"
  ],
  "index_permissions": [
    {
      "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"],
      "allowed_actions": ["read", "search"]
    }
  ],
  "tenant_permissions": [
    {
      "tenant_patterns": ["global_tenant"],
      "allowed_actions": ["kibana_all_read"]
    }
  ]
}'

# SOC L2 Role - Read + Actions
SOC_L2_ROLE='{
  "cluster_permissions": [
    "cluster_composite_ops_ro",
    "cluster_monitor"
  ],
  "index_permissions": [
    {
      "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"],
      "allowed_actions": ["read", "search"]
    }
  ],
  "tenant_permissions": [
    {
      "tenant_patterns": ["global_tenant"],
      "allowed_actions": ["kibana_all_write"]
    }
  ]
}'

# Create roles based on selected role
case $ROLE in
    soc-l1)
        create_indexer_role "soc_l1_role" "$SOC_L1_ROLE"
        BACKEND_ROLES='["soc_l1"]'
        INDEXER_ROLE="soc_l1_role"
        ;;
    soc-l2)
        create_indexer_role "soc_l2_role" "$SOC_L2_ROLE"
        BACKEND_ROLES='["soc_l2"]'
        INDEXER_ROLE="soc_l2_role"
        ;;
    admin)
        BACKEND_ROLES='["admin"]'
        INDEXER_ROLE="all_access"
        ;;
esac

#######################################
# Create Role Mapping (if needed)
#######################################

create_role_mapping() {
    local role_name=$1
    local backend_role=$2

    log_info "Creating role mapping for: $role_name"

    RESPONSE=$(curl -s -k -u "$ADMIN_USER:$ADMIN_PASSWORD" \
        -X PUT "$INDEXER_URL/_plugins/_security/api/rolesmapping/$role_name" \
        -H "Content-Type: application/json" \
        -d "{
            \"backend_roles\": [\"$backend_role\"],
            \"hosts\": [],
            \"users\": []
        }")

    if echo "$RESPONSE" | grep -qE '"status":"(CREATED|OK)"'; then
        log_success "Role mapping created"
    elif echo "$RESPONSE" | grep -q "reserved"; then
        log_info "Using existing reserved role mapping"
    else
        log_warn "Role mapping response: $RESPONSE"
    fi
}

case $ROLE in
    soc-l1)
        create_role_mapping "soc_l1_role" "soc_l1"
        ;;
    soc-l2)
        create_role_mapping "soc_l2_role" "soc_l2"
        ;;
esac

#######################################
# Create Internal User
#######################################

log_info "Creating internal user: $USERNAME"

RESPONSE=$(curl -s -k -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -X PUT "$INDEXER_URL/_plugins/_security/api/internalusers/$USERNAME" \
    -H "Content-Type: application/json" \
    -d "{
        \"password\": \"$PASSWORD\",
        \"backend_roles\": $BACKEND_ROLES,
        \"attributes\": {
            \"full_name\": \"$USERNAME\",
            \"role\": \"$ROLE\"
        }
    }")

if echo "$RESPONSE" | grep -qE '"status":"(CREATED|OK)"'; then
    log_success "User '$USERNAME' created"
else
    log_error "Failed to create user: $RESPONSE"
    exit 1
fi

#######################################
# Configure Wazuh API RBAC
#######################################

log_info "Configuring Wazuh API access..."

# Get API token
API_TOKEN=$(curl -s -k -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -X POST "$API_URL/security/user/authenticate" 2>/dev/null | \
    grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [[ -n "$API_TOKEN" ]]; then

    # Define policies based on role
    case $ROLE in
        admin)
            POLICY_NAME="${USERNAME}_admin_policy"
            POLICY_ACTIONS='["*:*"]'
            POLICY_RESOURCES='["*:*:*"]'
            API_ROLE_ID=1  # Administrator
            ;;
        soc-l1)
            POLICY_NAME="${USERNAME}_readonly_policy"
            POLICY_ACTIONS='["agent:read", "group:read", "vulnerability:read", "syscheck:read", "rootcheck:read", "syscollector:read", "rules:read", "decoders:read", "lists:read", "mitre:read", "cluster:read", "cluster:status"]'
            POLICY_RESOURCES='["agent:id:*", "agent:group:*", "group:id:*", "node:id:*", "*:*:*"]'
            API_ROLE_ID=4  # readonly
            ;;
        soc-l2)
            POLICY_NAME="${USERNAME}_analyst_policy"
            POLICY_ACTIONS='["agent:read", "agent:restart", "agent:reconnect", "group:read", "vulnerability:read", "syscheck:read", "syscheck:run", "rootcheck:read", "rootcheck:run", "syscollector:read", "rules:read", "decoders:read", "lists:read", "mitre:read", "active-response:command", "cluster:read", "cluster:status", "logtest:run"]'
            POLICY_RESOURCES='["agent:id:*", "agent:group:*", "group:id:*", "node:id:*", "*:*:*"]'
            API_ROLE_ID=3  # agents_admin (closest to L2)
            ;;
    esac

    # Create security rule for user
    RULE_RESPONSE=$(curl -s -k \
        -H "Authorization: Bearer $API_TOKEN" \
        -X POST "$API_URL/security/rules" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"${USERNAME}_rule\",
            \"rule\": {
                \"FIND\": {
                    \"user_name\": \"$USERNAME\"
                }
            }
        }" 2>/dev/null)

    RULE_ID=$(echo "$RULE_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

    if [[ -n "$RULE_ID" ]]; then
        # Map rule to role
        curl -s -k \
            -H "Authorization: Bearer $API_TOKEN" \
            -X POST "$API_URL/security/roles/$API_ROLE_ID/rules?rule_ids=$RULE_ID" > /dev/null 2>&1
        log_success "Wazuh API role configured"
    else
        log_warn "Could not create API rule (can configure manually in dashboard)"
    fi
else
    log_warn "Could not authenticate to Wazuh API (can configure manually)"
fi

#######################################
# Summary
#######################################

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  User created successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BLUE}Username:${NC}  $USERNAME"
echo -e "  ${BLUE}Role:${NC}      $ROLE"
echo -e "  ${BLUE}Dashboard:${NC} https://localhost:443"
echo ""

case $ROLE in
    admin)
        echo -e "  ${YELLOW}Permissions:${NC}"
        echo "    • Full administrative access"
        echo "    • All indexer and API operations"
        ;;
    soc-l1)
        echo -e "  ${YELLOW}Permissions:${NC}"
        echo "    • View agents, alerts, vulnerabilities"
        echo "    • Read rules, decoders, MITRE data"
        echo "    • Monitor cluster status"
        echo "    • NO action capabilities"
        ;;
    soc-l2)
        echo -e "  ${YELLOW}Permissions:${NC}"
        echo "    • All L1 permissions plus:"
        echo "    • Restart/reconnect agents"
        echo "    • Run FIM and rootcheck scans"
        echo "    • Execute active responses"
        echo "    • Test rules with logtest"
        ;;
esac

echo ""
echo -e "${YELLOW}Note: Log out and back in for all permissions to take effect.${NC}"
echo ""
