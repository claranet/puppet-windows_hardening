# == Class: windows_hardening::user_rights
#
# Configures user access local polocies
#
class windows_hardening::user_rights {

  # Set Access Credential Manager as a trusted caller to No One
  # cis-access-cred-manager-2.2.1
  local_security_policy { 'Access Credential Manager as a trusted caller':
    ensure       => present,
    policy_value => 'NOBODY'
  }

  # Set Act as part of the operating system to No One
  # cis-act-as-os-2.2.3
  local_security_policy { 'Act as part of the operating system':
    ensure       => present,
    policy_value => 'NOBODY'
  }

  # Set Add workstations to domain to Administrators
  # cis-add-workstations-2.2.4
  local_security_policy { 'Add workstations to domain':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS'
  }

}
