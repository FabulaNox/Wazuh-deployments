variable "wazuh_version" {
  description = "Wazuh version to install"
  type        = string
  default     = "4.14"
}

variable "install_all_in_one" {
  description = "Install all components on single node"
  type        = bool
  default     = true
}

variable "components" {
  description = "Components to install when not using all-in-one"
  type = object({
    indexer   = bool
    server    = bool
    dashboard = bool
  })
  default = {
    indexer   = true
    server    = true
    dashboard = true
  }
}

variable "admin_password" {
  description = "Admin password for Wazuh dashboard (leave empty for auto-generated)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "indexer_node_name" {
  description = "Name for the indexer node"
  type        = string
  default     = "node-1"
}

variable "server_node_name" {
  description = "Name for the Wazuh server node"
  type        = string
  default     = "wazuh-1"
}

variable "dashboard_node_name" {
  description = "Name for the dashboard node"
  type        = string
  default     = "dashboard"
}

variable "installation_path" {
  description = "Path to store installation artifacts"
  type        = string
  default     = "/tmp/wazuh-install"
}
