# Wazuh Home Lab Deployments

> **TESTING IN PROGRESS, PLEASE HOLD WHILE THE OPERATOR IS COOKING IN THE BACKGROUND**

A collection of deployment methods for running [Wazuh](https://wazuh.com/) in a home lab environment. This repository provides Infrastructure as Code (IaC) solutions for deploying and managing Wazuh, a free and open-source security monitoring platform.

---

## Table of Contents

- [About This Project](#about-this-project)
- [Why Wazuh?](#why-wazuh)
- [Architecture Decisions](#architecture-decisions)
  - [Manager Host Visibility](#manager-host-visibility-important)
- [Prerequisites](#prerequisites)
- [Deployment Methods](#deployment-methods)
  - [Terraform (Local)](#terraform-local)
- [User Management](#user-management)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## About This Project

### Purpose

This repository serves a dual purpose:

1. **Learning & Training** - Hands-on experience with security monitoring, SIEM concepts, and incident response in a controlled environment
2. **Active Home Network Security** - Real-time monitoring and protection of home lab infrastructure

### Scope

Designed for home lab environments with:

- **10-50 monitored endpoints** (physical machines, VMs, containers, IoT devices)
- **All-in-one deployment** - Single server running Wazuh Manager, Indexer, and Dashboard
- **Medium storage requirements** - Approximately 50-100GB for 90 days of alert retention

### Target Audience

This repository is shared with the community to help others:

- Set up their own Wazuh home labs
- Learn security monitoring concepts
- Understand Infrastructure as Code practices
- Build SOC (Security Operations Center) skills

---

## Why Wazuh?

Wazuh was chosen for this home lab because:

| Feature | Benefit |
|---------|---------|
| **Open Source** | Free to use, no licensing costs for home labs |
| **All-in-One Solution** | SIEM, XDR, and compliance in a single platform |
| **Active Community** | Regular updates, good documentation, community support |
| **Agent-Based** | Lightweight agents for endpoints, central management |
| **MITRE ATT&CK Integration** | Maps alerts to known attack techniques |
| **Scalable** | Grows from home lab to enterprise if needed |

---

## Architecture Decisions

### Why Terraform First?

Terraform was chosen as the initial deployment method for several reasons:

1. **Infrastructure as Code (IaC)**
   - Deployments are version-controlled and reproducible
   - Changes are tracked in git history
   - Easy to destroy and recreate environments

2. **Future Cloud Expansion**
   - Same Terraform patterns extend to AWS, Azure, GCP
   - Skills transfer directly to cloud deployments
   - Modular structure allows adding cloud providers later

3. **Declarative Approach**
   - Define desired state, not procedural steps
   - Terraform handles dependency ordering
   - Built-in destroy capabilities for clean teardown

### Why All-in-One Deployment?

For a home lab with 10 to 50 endpoints (as the home lab expands), a distributed architecture is unnecessary:

- **Simplified Management** - One server to maintain
- **Resource Efficient** - No overhead of cluster coordination
- **Sufficient Performance** - Handles home lab scale easily
- **Lower Hardware Requirements** - Can run on a single machine with 8GB+ RAM

### Why Custom User Management Scripts?

The included scripts provide:

- **Role-Based Access Control** - Predefined SOC L1/L2 analyst roles
- **Security Monitoring** - Failed login attempts generate alerts
- **Automation** - Consistent user creation across deployments
- **Learning Tool** - Understand Wazuh RBAC by examining the code
- **Ease of Access** - I will want to explore role permissions and creations in further depth

### Manager Host Visibility (Important!)

When running Wazuh all-in-one, the **manager server monitors itself** through a built-in agent with **ID 000**. This has important implications:

#### What You Should Know

| Aspect | Details |
|--------|---------|
| **Built-in Agent** | The manager includes an internal agent (ID: 000) - no separate agent installation needed |
| **Never Install Agent on Manager** | Installing an agent on the manager will **remove the manager and API components** |
| **Dashboard Visibility** | Manager events appear under `agent.id: 000` in the Discover dashboard |
| **Vulnerability Detection** | Disabled for manager by default - must be enabled manually |

#### Enabling Vulnerability Detection on Manager

By default, the Vulnerability Detection module does **not** scan the manager host. To enable it:

```bash
# Edit internal options
sudo nano /var/ossec/etc/internal_options.conf

# Find and change this line from 1 to 0:
vulnerability-detection.disable_scan_manager=0

# Restart the manager
sudo systemctl restart wazuh-manager
```

#### Viewing Manager Events

To see security events from the Wazuh server itself:

1. Go to **Discover** in the Wazuh dashboard
2. Add a filter: `agent.id: 000`
3. All events from the manager host will be displayed

#### Why This Matters

When you start adding agents to monitor other endpoints, the dashboard naturally focuses on those agents. The manager (ID: 000) can get "lost" among many agents. Remember to:

- Include `agent.id: 000` when reviewing overall security posture
- Enable vulnerability scanning on the manager (see above)
- Monitor the manager's own logs at `/var/ossec/logs/ossec.log`

> **Reference**: [Wazuh Manager Documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-manager.html), [Vulnerability Detection Configuration](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Storage | 50 GB | 100+ GB |
| Network | 1 Gbps | 1 Gbps |

### Software Requirements

- **Operating System**: Ubuntu 22.04 LTS (Tested), Debian 11+ (Tested on 12 Bullseye), or CentOS 8+
- **Terraform**: v1.0.0 or higher
- **curl**: For API interactions
- **sudo access**: Required for installation

### Network Requirements

The following ports must be available:

| Port | Service | Direction |
|------|---------|-----------|
| 443 | Wazuh Dashboard (HTTPS) | Inbound |
| 1514 | Agent communication | Inbound |
| 1515 | Agent registration | Inbound |
| 9200 | Wazuh Indexer API | Local only |
| 55000 | Wazuh Server API | Local only |

---

## Deployment Methods

### Terraform (Local)

Deploy Wazuh on a local machine using Terraform with the official installation script.

#### Quick Start

```bash
# Clone the repository
git clone https://github.com/FabulaNox/Wazuh-deployments.git
cd Wazuh-deployments/terraform/local

# Configure variables (optional)
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars if needed

# Initialize and deploy
terraform init
terraform apply
```

#### What It Does

1. Downloads the official Wazuh installation script
2. Runs all-in-one installation (`wazuh-install.sh -a`)
3. Configures firewall rules (UFW) automatically
4. Extracts credentials for dashboard access

#### Configuration Options

Edit `terraform.tfvars` to customize:

```hcl
# Wazuh version to install
wazuh_version = "4.14"

# Where to store installation artifacts
installation_path = "/tmp/wazuh-install"
```

#### Outputs

After deployment, Terraform displays:

- Dashboard URL: `https://localhost:443`
- Credentials file location
- Service status commands

#### Destroying the Deployment

```bash
terraform destroy
```

This runs the official Wazuh uninstall script, cleanly removing all components.

#### File Structure

```
terraform/local/
├── main.tf                    # Main deployment logic
├── variables.tf               # Input variables
├── outputs.tf                 # Output values
├── versions.tf                # Terraform version constraints
└── terraform.tfvars.example   # Example configuration
```

---

## User Management

### Creating Users

Use the provided script to create users with predefined roles:

```bash
./scripts/create-wazuh-user.sh -u <username> -r <role>
```

#### Available Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Full administrative access | All operations on indexer and API |
| `soc-l1` | SOC Tier 1 Analyst (Read-Only) | View alerts, agents, vulnerabilities, rules |
| `soc-l2` | SOC Tier 2 Analyst (Read + Actions) | L1 permissions + restart agents, run scans, active response |

#### Examples

```bash
# Create an admin user
./scripts/create-wazuh-user.sh -u john.admin -r admin

# Create a read-only analyst
./scripts/create-wazuh-user.sh -u jane.analyst -r soc-l1

# Create an analyst with action permissions
./scripts/create-wazuh-user.sh -u bob.responder -r soc-l2

# Provide password via argument (for automation)
./scripts/create-wazuh-user.sh -u auto.user -r soc-l1 -p 'SecurePassword123!'
```

#### Role Details

**SOC L1 (Read-Only)**
- View agents, alerts, and vulnerabilities
- Read rules, decoders, and MITRE ATT&CK data
- Monitor cluster status
- Cannot perform any actions

**SOC L2 (Read + Actions)**
- All L1 permissions, plus:
- Restart and reconnect agents
- Run file integrity monitoring (FIM) scans
- Run rootcheck scans
- Execute active responses
- Test rules with logtest

---

## Security Features

### Authentication Security

The user management script includes built-in security measures:

#### Admin Credential Verification

- Requires valid admin credentials to create users
- Verifies the authenticating user has admin-level privileges
- Maximum 3 authentication attempts

#### Security Alerts

Failed authentication attempts generate **Level 15 alerts** (critical severity):

| Scenario | Alert | MITRE ATT&CK |
|----------|-------|--------------|
| 3 failed login attempts | Multiple failed admin authentication | T1110 (Brute Force) |
| Non-admin user attempts to create accounts | Privilege escalation attempt | T1548 (Abuse Elevation) |

#### Installing Security Rules

To enable alert detection for the user management script:

```bash
sudo ./scripts/install-security-rules.sh
```

This installs:
- Custom Wazuh rules (IDs 100001-100004)
- Log monitoring for `/var/log/wazuh-user-management.log`
- Automatic Wazuh manager restart

---

## Troubleshooting

### Installation Issues

#### "sudo: a terminal is required to read the password"

**Problem**: Terraform cannot prompt for sudo password.

**Solution**: Either:
1. Run terraform with sudo: `sudo terraform apply`
2. Configure passwordless sudo for the installation
3. Run the installation commands manually

#### "Wazuh services fail to start"

**Problem**: Services don't start after installation.

**Solutions**:
```bash
# Check service status
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Check logs
tail -f /var/ossec/logs/ossec.log
tail -f /var/log/wazuh-indexer/wazuh-indexer.log

# Restart services
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard
```

#### "Port 443 already in use"

**Problem**: Another service is using port 443.

**Solution**:
```bash
# Find what's using the port
sudo lsof -i :443

# Stop the conflicting service or change Wazuh dashboard port
```

### Dashboard Access Issues

#### "Cannot connect to dashboard"

**Checklist**:
1. Verify services are running: `systemctl status wazuh-dashboard`
2. Check firewall: `sudo ufw status`
3. Try accessing via IP: `https://<server-ip>:443`
4. Check for certificate warnings (self-signed cert is normal)

#### "Invalid credentials"

**Solutions**:
```bash
# Retrieve admin password from installation
cat /tmp/wazuh-install/wazuh-passwords.txt | grep -A1 "admin"

# Or extract from tar archive
sudo tar -xvf /tmp/wazuh-install/wazuh-install-files.tar -C /tmp ./wazuh-passwords.txt
```

### User Management Issues

#### "Authentication failed" in user script

**Problem**: Cannot authenticate to create users.

**Solutions**:
1. Verify admin credentials work in dashboard first
2. Check Wazuh indexer is running: `systemctl status wazuh-indexer`
3. Test API manually:
```bash
curl -k -u admin:PASSWORD https://localhost:9200/_cluster/health
```

#### "User created but cannot log in"

**Problem**: New user exists but login fails.

**Solutions**:
1. Clear browser cache and cookies
2. Try incognito/private window
3. Wait 30 seconds for permission propagation
4. Verify user was created:
```bash
curl -k -u admin:PASSWORD https://localhost:9200/_plugins/_security/api/internalusers/USERNAME
```

### Performance Issues

#### "Dashboard is slow"

**Solutions**:
1. Check system resources: `htop` or `top`
2. Increase heap size for Wazuh indexer (if RAM allows):
```bash
sudo vi /etc/wazuh-indexer/jvm.options
# Adjust -Xms and -Xmx values
```
3. Reduce index retention period
4. Add more RAM to the server

#### "High CPU usage"

**Common causes**:
1. Vulnerability detection running (normal, temporary)
2. Too many agents reporting simultaneously
3. Complex rules triggering frequently

**Solutions**:
```bash
# Check what's consuming resources
sudo /var/ossec/bin/wazuh-control status
top -c -p $(pgrep -d',' -f wazuh)
```

### Agent Connection Issues

#### "Agent not appearing in dashboard"

**Checklist**:
1. Agent service running: `sudo systemctl status wazuh-agent`
2. Firewall allows 1514/1515: `sudo ufw status`
3. Agent configured with correct manager IP
4. Check agent logs: `tail -f /var/ossec/logs/ossec.log`

---

## Roadmap

The following deployment methods are planned (in order of priority):

### 1. Docker Compose
- Containerized all-in-one deployment
- Easy local development and testing
- Simplified cleanup and recreation

### 2. Kubernetes (Helm Charts)
- Scalable container orchestration
- High availability options
- Cloud-native deployment patterns

### 3. Ansible
- Configuration management
- Multi-node deployments
- Automated agent enrollment

---

## Repository Structure

```
Wazuh-deployments/
├── README.md                 # This documentation
├── LICENSE.md                # License information
├── .gitignore                # Git ignore patterns
├── terraform/
│   └── local/                # Local Terraform deployment
│       ├── main.tf
│       ├── variables.tf
│       ├── outputs.tf
│       ├── versions.tf
│       └── terraform.tfvars.example
├── scripts/
│   ├── create-wazuh-user.sh       # User management script
│   ├── install-security-rules.sh  # Install custom Wazuh rules
│   └── wazuh-rules/
│       └── local_rules.xml        # Custom alert rules
├── docker/                   # (Coming soon)
├── kubernetes/               # (Coming soon)
└── ansible/                  # (Coming soon)
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## License

See [LICENSE.md](LICENSE.md) for details.

---

## Acknowledgments

- [Wazuh](https://wazuh.com/) - For the excellent open-source security platform
- [Wazuh Documentation](https://documentation.wazuh.com/) - Comprehensive official docs

---

## Support

For issues specific to this repository, please open a GitHub issue.

For Wazuh-specific questions, refer to:
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh Community Slack](https://wazuh.com/community/join-us-on-slack/)
