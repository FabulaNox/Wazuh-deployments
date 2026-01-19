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

# Telegram Integration Variables
variable "telegram_integration_enabled" {
  description = "Enable Telegram alert notifications"
  type        = bool
  default     = false
}

variable "telegram_bot_token" {
  description = "Telegram Bot Token (from @BotFather)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "telegram_chat_id" {
  description = "Telegram Chat ID (user or group)"
  type        = string
  default     = ""
}

variable "telegram_alert_level" {
  description = "Minimum alert level to send to Telegram (1-15)"
  type        = number
  default     = 7
}

# Slack Integration Variables
variable "slack_integration_enabled" {
  description = "Enable Slack alert notifications"
  type        = bool
  default     = false
}

variable "slack_bot_token" {
  description = "Slack Bot User OAuth Token (xoxb-...)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_app_token" {
  description = "Slack App-Level Token for Socket Mode (xapp-...)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_channel_id" {
  description = "Slack Channel ID (C...) or channel name"
  type        = string
  default     = ""
}

variable "slack_alert_level" {
  description = "Minimum alert level to send to Slack (1-15)"
  type        = number
  default     = 7
}
