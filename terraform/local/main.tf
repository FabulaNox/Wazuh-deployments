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
      curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
      sudo bash wazuh-install.sh --uninstall 2>/dev/null || true
      rm -f wazuh-install.sh
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
