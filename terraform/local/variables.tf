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
