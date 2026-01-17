# Wazuh Configurations

Storage-conscious security configurations for Wazuh.

## Log Retention (30 Days)

Configure automatic log rotation and deletion.

```bash
cd configurations/retention
sudo ./setup-retention-policy.sh 30
```

**What it configures:**
- Wazuh Indexer ISM policy (auto-delete indices after 30 days)
- Local logrotate for `/var/ossec/logs/` (compress and rotate)

**Storage management:**
```bash
# Check current index sizes
curl -k -u admin:PASSWORD 'https://localhost:9200/_cat/indices/wazuh-*?v&s=index'

# Check local log sizes
sudo du -sh /var/ossec/logs/*
```

## Active Response (Auto-Blocking)

Automatically block malicious IPs after attacks.

```bash
cd configurations/active-response
sudo ./setup-active-response.sh 60  # Block for 60 minutes
```

**Triggers:**

| Rule ID | Description | Action |
|---------|-------------|--------|
| 5712 | SSH brute force | Block IP |
| 5503 | Multiple auth failures | Block IP |
| 31164 | Web brute force | Block IP |
| 581 | Port scan detected | Block IP |
| 100104 | MikroTik brute force | Block IP |
| 100121 | MikroTik port scan | Block IP |

**Manage blocked IPs:**
```bash
# View blocked IPs
sudo cat /var/ossec/logs/active-responses.log

# Manually unblock
sudo /var/ossec/active-response/bin/firewall-drop delete - 192.168.1.100

# View current firewall blocks
sudo ufw status
# or
sudo iptables -L -n
```

**Important:** Always whitelist your own IP to prevent lockout!

## Future Additions

| Component | Purpose | Storage Impact |
|-----------|---------|----------------|
| auditd rules | Targeted syscall monitoring | Low (selective rules) |
| Suricata | Network IDS | Separate system recommended |
| YARA rules | Malware scanning | Minimal |
| Threat intel feeds | CDB lists | Minimal |

## File Structure

```
configurations/
├── README.md
├── retention/
│   └── setup-retention-policy.sh
└── active-response/
    └── setup-active-response.sh
```
