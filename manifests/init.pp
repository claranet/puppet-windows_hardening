# == Class: windows_hardening
#
# Configuring local policies and registry settings to meet security hardening specifications
#
# === Authors
#
# Liam Bennett <liam.bennett@claranet.uk>
#
# === Copyright
#
# Copyright 2017 Claranet
#
class windows_hardening {
  include windows_hardening::access_config
  include windows_hardening::account_lockout
  include windows_hardening::audit_log_config
  include windows_hardening::ie_config
  include windows_hardening::password_policy
  include windows_hardening::powershell
  include windows_hardening::privacy
  include windows_hardening::rdp_config
  include windows_hardening::security_options
  include windows_hardening::user_rights
}
