#
#
#
class windows_hardening::security_options {
  
  # cis-admin-account-status-2.3.1.1
  # TODO:

  # cis-accounts-block-microsoft-2.3.1.2
  local_security_policy { 'Accounts: Block Microsoft accounts':
    ensure       => present,
    policy_value => '3',
  }

  # cis-accounts-guest-account-status-2.3.1.3
  # TODO:

  # cis-accounts-local-account-blank-passwords-2.3.1.4
  local_security_policy { 'Accounts: Limit local account use of blank passwords to console logon only':
    ensure       => present,
    policy_value => '1',
  }

  # cis-rename-administrator-account-2.3.1.5
  # TODO:
}
