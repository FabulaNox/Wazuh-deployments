locals {
  wazuh_install_url = "https://packages.wazuh.com/${var.wazuh_version}/wazuh-install.sh"
  install_dir       = var.installation_path
  timestamp         = formatdate("YYYYMMDD-hhmmss", timestamp())
}

resource "null_resource" "wazuh_prerequisites" {
  triggers = {
    always_run = local.timestamp
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${local.install_dir}
      cd ${local.install_dir}

      # Download installation script
      curl -sO ${local.wazuh_install_url}
      chmod +x wazuh-install.sh

      # Generate configuration files
      sudo bash wazuh-install.sh --generate-config-files
    EOT
  }
}

resource "null_resource" "wazuh_indexer" {
  depends_on = [null_resource.wazuh_prerequisites]

  triggers = {
    version   = var.wazuh_version
    node_name = var.indexer_node_name
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${local.install_dir}
      sudo bash wazuh-install.sh --wazuh-indexer ${var.indexer_node_name}
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "sudo apt-get remove --purge wazuh-indexer -y 2>/dev/null || true"
  }
}

resource "null_resource" "wazuh_indexer_cluster" {
  depends_on = [null_resource.wazuh_indexer]

  triggers = {
    indexer_id = null_resource.wazuh_indexer.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${local.install_dir}
      sudo bash wazuh-install.sh --start-cluster
    EOT
  }
}

resource "null_resource" "wazuh_server" {
  depends_on = [null_resource.wazuh_indexer_cluster]

  triggers = {
    version   = var.wazuh_version
    node_name = var.server_node_name
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${local.install_dir}
      sudo bash wazuh-install.sh --wazuh-server ${var.server_node_name}
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "sudo apt-get remove --purge wazuh-manager filebeat -y 2>/dev/null || true"
  }
}

resource "null_resource" "wazuh_dashboard" {
  depends_on = [null_resource.wazuh_server]

  triggers = {
    version   = var.wazuh_version
    node_name = var.dashboard_node_name
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${local.install_dir}
      sudo bash wazuh-install.sh --wazuh-dashboard ${var.dashboard_node_name}
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "sudo apt-get remove --purge wazuh-dashboard -y 2>/dev/null || true"
  }
}

resource "null_resource" "extract_credentials" {
  depends_on = [null_resource.wazuh_dashboard]

  triggers = {
    dashboard_id = null_resource.wazuh_dashboard.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${local.install_dir}
      sudo tar -xvf wazuh-install-files.tar -C ${local.install_dir} ./wazuh-passwords.txt 2>/dev/null || true
    EOT
  }
}

data "local_file" "wazuh_passwords" {
  depends_on = [null_resource.extract_credentials]
  filename   = "${local.install_dir}/wazuh-passwords.txt"
}
