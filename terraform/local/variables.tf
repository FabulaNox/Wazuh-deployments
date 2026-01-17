variable "wazuh_version" {
  description = "Wazuh version to install"
  type        = string
  default     = "4.14"
}

variable "installation_path" {
  description = "Path to store installation artifacts"
  type        = string
  default     = "/tmp/wazuh-install"
}

# MikroTik Integration Variables
variable "mikrotik_integration_enabled" {
  description = "Enable MikroTik RouterOS log integration"
  type        = bool
  default     = false
}

variable "mikrotik_router_ip" {
  description = "MikroTik router IP address"
  type        = string
  default     = "192.168.88.1"
}

variable "mikrotik_use_api" {
  description = "Use MikroTik REST API for automatic router configuration (RouterOS 7.1+)"
  type        = bool
  default     = false
}

variable "mikrotik_username" {
  description = "MikroTik admin username (required if mikrotik_use_api is true)"
  type        = string
  default     = "admin"
}

variable "mikrotik_password" {
  description = "MikroTik admin password (required if mikrotik_use_api is true)"
  type        = string
  default     = ""
  sensitive   = true
}
