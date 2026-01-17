locals {
  wazuh_install_url = "https://packages.wazuh.com/${var.wazuh_version}/wazuh-install.sh"
  install_dir       = var.installation_path
}

resource "null_resource" "wazuh_all_in_one" {
  triggers = {
    version = var.wazuh_version
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${local.install_dir}
      cd ${local.install_dir}

      # Download installation script
      curl -sO ${local.wazuh_install_url}
      chmod +x wazuh-install.sh

      # Run all-in-one installation
      sudo bash wazuh-install.sh -a

      # Extract credentials for reference
      sudo tar -xvf wazuh-install-files.tar -C ${local.install_dir} ./wazuh-passwords.txt 2>/dev/null || true
      sudo chown $(whoami):$(whoami) ${local.install_dir}/wazuh-passwords.txt 2>/dev/null || true
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      CLEANUP_SCRIPT="${path.module}/../../scripts/cleanup-custom-configs.sh"

      if [[ -f "$CLEANUP_SCRIPT" ]]; then
        echo "Running custom cleanup script..."
        sudo bash "$CLEANUP_SCRIPT"
      else
        echo "Cleanup script not found, running standard uninstall..."
        curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
        sudo bash wazuh-install.sh --uninstall 2>/dev/null || true
        rm -f wazuh-install.sh
      fi
    EOT
  }
}

resource "null_resource" "firewall_rules" {
  depends_on = [null_resource.wazuh_all_in_one]

  provisioner "local-exec" {
    command = <<-EOT
      if command -v ufw &> /dev/null; then
        sudo ufw allow 443/tcp comment "Wazuh Dashboard" 2>/dev/null || true
        sudo ufw allow 1514/tcp comment "Wazuh Agent" 2>/dev/null || true
        sudo ufw allow 1515/tcp comment "Wazuh Agent Registration" 2>/dev/null || true
      fi
    EOT
  }
}

# MikroTik Integration (optional)
resource "null_resource" "mikrotik_integration" {
  count      = var.mikrotik_integration_enabled ? 1 : 0
  depends_on = [null_resource.wazuh_all_in_one, null_resource.firewall_rules]

  triggers = {
    router_ip = var.mikrotik_router_ip
    use_api   = var.mikrotik_use_api
  }

  # Open syslog port for MikroTik
  provisioner "local-exec" {
    command = <<-EOT
      if command -v ufw &> /dev/null; then
        sudo ufw allow from ${var.mikrotik_router_ip} to any port 514 proto udp comment "Wazuh Syslog from MikroTik" 2>/dev/null || true
      elif command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="${var.mikrotik_router_ip}" port port="514" protocol="udp" accept' 2>/dev/null || true
        sudo firewall-cmd --reload 2>/dev/null || true
      fi
    EOT
  }

  # Run MikroTik integration setup script
  provisioner "local-exec" {
    command = <<-EOT
      SCRIPT_PATH="${path.module}/../../integrations/mikrotik/setup-mikrotik-integration.sh"

      if [[ ! -f "$SCRIPT_PATH" ]]; then
        echo "ERROR: MikroTik integration script not found at $SCRIPT_PATH"
        exit 1
      fi

      chmod +x "$SCRIPT_PATH"

      if [[ "${var.mikrotik_use_api}" == "true" && -n "${var.mikrotik_password}" ]]; then
        # Use API for automatic router configuration
        sudo bash "$SCRIPT_PATH" \
          --router "${var.mikrotik_router_ip}" \
          --user "${var.mikrotik_username}" \
          --password "${var.mikrotik_password}" \
          --api <<< "Y"
      else
        # Manual mode - just configure Wazuh side
        sudo bash "$SCRIPT_PATH" \
          --router "${var.mikrotik_router_ip}" \
          --manual <<< "Y"
      fi
    EOT
  }
}
