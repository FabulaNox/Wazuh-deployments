# MikroTik RouterOS Integration for Wazuh

Collect and analyze logs from MikroTik routers in your Wazuh SIEM.

## Overview

This integration enables:
- Syslog forwarding from MikroTik RouterOS to Wazuh
- Custom decoders for parsing MikroTik log formats
- Security detection rules for common threats and events
- **Automated setup via MikroTik REST API** (RouterOS 7.1+)

## Detected Events

| Category | Events | Alert Level |
|----------|--------|-------------|
| **Authentication** | Login success/failure, logout | 3-10 |
| **Brute Force** | Multiple failed logins | 10 |
| **ISP Connection** | PPPoE connect/disconnect, link up/down | 3-10 |
| **Firewall** | Blocked connections, rule changes | 3-8 |
| **Port Scanning** | Multiple firewall drops from same source | 8 |
| **NAT/Port Forward** | Rule added/modified/removed | 8-10 |
| **Configuration** | System changes, user modifications | 5-8 |
| **DHCP** | New device, IP change, lease assigned | 3-7 |
| **Wireless** | Client connect/disconnect | 3 |
| **OpenVPN** | Connection, disconnection, auth failure | 4-8 |
| **System** | Critical errors, warnings, reboots | 4-12 |

## Quick Start

### Option 1: Interactive Setup

```bash
sudo ./setup-mikrotik-integration.sh
```

The script will prompt for:
- Router IP address
- Wazuh server IP
- Configuration method (API or manual)
- Router credentials (for API method)

### Option 2: Automated with API (Recommended)

```bash
sudo ./setup-mikrotik-integration.sh -r 192.168.88.1 -u admin -p YourPassword -a
```

This automatically:
1. Configures Wazuh (decoders, rules, syslog)
2. Connects to MikroTik via REST API
3. Creates logging action and rules on the router

### Option 3: Manual Router Config

```bash
sudo ./setup-mikrotik-integration.sh -r 192.168.88.1 -m
```

Configures Wazuh and prints commands to paste into your router.

### Script Options

| Option | Description |
|--------|-------------|
| `-r, --router IP` | MikroTik router IP address |
| `-w, --wazuh IP` | Wazuh server IP (auto-detected) |
| `-u, --user USER` | MikroTik username (default: admin) |
| `-p, --password PASS` | MikroTik password (for API) |
| `-a, --api` | Use MikroTik REST API |
| `-m, --manual` | Print manual commands only |
| `-h, --help` | Show help |

### 2. Configure MikroTik Router

Via SSH/Terminal:
```routeros
# Create logging action
/system logging action add name=wazuh target=remote \
    remote=<WAZUH_SERVER_IP> remote-port=514 \
    src-address=192.168.88.1

# Add logging rules
/system logging add action=wazuh topics=critical
/system logging add action=wazuh topics=error
/system logging add action=wazuh topics=warning
/system logging add action=wazuh topics=system
/system logging add action=wazuh topics=firewall
/system logging add action=wazuh topics=interface
/system logging add action=wazuh topics=ppp
/system logging add action=wazuh topics=pppoe
/system logging add action=wazuh topics=dhcp
/system logging add action=wazuh topics=dns
/system logging add action=wazuh topics=wireless
/system logging add action=wazuh topics=account
```

### 3. Verify Integration

```bash
# Watch for incoming logs
tail -f /var/ossec/logs/archives/archives.log | grep 192.168.88.1

# Generate test event on MikroTik
/log warning "Wazuh integration test"
```

## Manual Installation

If you prefer manual setup:

### Install Decoders

```bash
sudo cp decoders/mikrotik_decoders.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/mikrotik_decoders.xml
```

### Install Rules

```bash
sudo cp rules/mikrotik_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/mikrotik_rules.xml
```

### Configure Syslog Reception

Add to `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.88.1</allowed-ips>
  <local_ip><WAZUH_SERVER_IP></local_ip>
</remote>
```

### Restart Wazuh

```bash
sudo systemctl restart wazuh-manager
```

## File Structure

```
integrations/mikrotik/
├── README.md                        # This file
├── setup-mikrotik-integration.sh    # Automated setup script
├── decoders/
│   └── mikrotik_decoders.xml       # Log parsing decoders
└── rules/
    └── mikrotik_rules.xml          # Detection rules
```

## Rule IDs

| ID Range | Category |
|----------|----------|
| 100100 | Base MikroTik event |
| 100101-100105 | Authentication |
| 100110-100115 | ISP/WAN connectivity |
| 100120-100122 | Firewall |
| 100130-100133 | Configuration changes |
| 100140-100141 | DHCP |
| 100150-100151 | Wireless |
| 100160-100163 | System errors/warnings |
| 100170-100171 | Scripts |

## Troubleshooting

### No logs received

1. **Check Wazuh is listening:**
   ```bash
   ss -ulnp | grep 514
   ```

2. **Check firewall:**
   ```bash
   sudo ufw status
   sudo ufw allow 514/udp comment "Wazuh Syslog"
   ```

3. **Verify MikroTik config:**
   ```routeros
   /system logging action print
   /system logging print
   ```

4. **Test connectivity from router:**
   ```routeros
   /tool ping <WAZUH_SERVER_IP>
   ```

### Logs received but no alerts

1. **Check decoder is working:**
   ```bash
   /var/ossec/bin/wazuh-logtest
   ```
   Paste a sample MikroTik log line.

2. **Check archives:**
   ```bash
   grep mikrotik /var/ossec/logs/archives/archives.log
   ```

### High volume of DHCP alerts

If DHCP events are too noisy, disable them:

```bash
# Edit rules file
sudo nano /var/ossec/etc/rules/mikrotik_rules.xml
# Change level="2" to level="0" for rules 100140-100141
sudo systemctl restart wazuh-manager
```

## MITRE ATT&CK Mapping

| Technique | Rule ID | Description |
|-----------|---------|-------------|
| T1110 | 100103, 100104 | Brute Force |
| T1046 | 100121 | Network Service Discovery (Port Scan) |
| T1562 | 100122 | Impair Defenses (Firewall modification) |
| T1136 | 100131 | Create Account |
| T1053 | 100171 | Scheduled Task |

## References

- [Wazuh Syslog Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
- [MikroTik Logging Documentation](https://help.mikrotik.com/docs/display/ROS/Log)
- [Wazuh MikroTik Blog Post](https://wazuh.com/blog/monitoring-network-devices/)
