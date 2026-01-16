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

output "installation_notes" {
  description = "Post-installation notes"
  value       = <<-EOT

    Wazuh ${var.wazuh_version} has been installed successfully!

    Dashboard: https://localhost:443
    Credentials: ${var.installation_path}/wazuh-passwords.txt

    To retrieve the admin password:
      cat ${var.installation_path}/wazuh-passwords.txt | grep -A1 "admin"

    Services:
      systemctl status wazuh-manager
      systemctl status wazuh-indexer
      systemctl status wazuh-dashboard

  EOT
}
