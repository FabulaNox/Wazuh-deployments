output "dashboard_url" {
  description = "URL to access Wazuh dashboard"
  value       = "https://localhost:443"
}

output "indexer_url" {
  description = "URL for Wazuh indexer API"
  value       = "https://localhost:9200"
}

output "api_url" {
  description = "URL for Wazuh server API"
  value       = "https://localhost:55000"
}

output "credentials_file" {
  description = "Path to the credentials file"
  value       = "${var.installation_path}/wazuh-passwords.txt"
}

output "wazuh_version" {
  description = "Installed Wazuh version"
  value       = var.wazuh_version
}

output "mikrotik_integration" {
  description = "MikroTik integration status"
  value = {
    enabled   = var.mikrotik_integration_enabled
    router_ip = var.mikrotik_integration_enabled ? var.mikrotik_router_ip : null
    api_mode  = var.mikrotik_integration_enabled ? var.mikrotik_use_api : null
  }
}

output "installation_notes" {
  description = "Post-installation notes"
  value = <<-EOT

    Wazuh ${var.wazuh_version} has been installed successfully!

    Dashboard: https://localhost:443
    Credentials: ${var.installation_path}/wazuh-passwords.txt

    To retrieve the admin password:
      cat ${var.installation_path}/wazuh-passwords.txt | grep -A1 "admin"

    Services:
      systemctl status wazuh-manager
      systemctl status wazuh-indexer
      systemctl status wazuh-dashboard
${var.mikrotik_integration_enabled ? <<-MIKROTIK

    MikroTik Integration:
      Router: ${var.mikrotik_router_ip}
      Mode: ${var.mikrotik_use_api ? "API (automatic)" : "Manual"}
      ${var.mikrotik_use_api ? "" : "Run these commands on your MikroTik router:"}
      ${var.mikrotik_use_api ? "" : "  /system logging action add name=wazuh target=remote remote=<WAZUH_IP> remote-port=514"}
      ${var.mikrotik_use_api ? "" : "  /system logging add action=wazuh topics=critical,error,warning,system,firewall"}

    Test MikroTik logs:
      tail -f /var/ossec/logs/archives/archives.log | grep ${var.mikrotik_router_ip}
MIKROTIK
: ""}
  EOT
}
