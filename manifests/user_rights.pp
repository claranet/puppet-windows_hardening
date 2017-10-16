# == Class: windows_hardening::user_rights
#
# Configures user access local polocies
#
class windows_hardening::user_rights {

  # Set Access Credential Manager as a trusted caller to No One
  # cis-access-cred-manager-2.2.1
  local_security_policy { 'Access Credential Manager as a trusted caller':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  #
  # Set Access this computer from the network
  # cis-access-from-network-2.2.2
  # local_security_policy { 'Access this computer from the network':
  #  ensure       => present,
  #  policy_value => 'NOBODY',
  # }

  # Set Act as part of the operating system to No One
  # cis-act-as-os-2.2.3
  local_security_policy { 'Act as part of the operating system':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  # Set Add workstations to domain to Administrators
  # cis-add-workstations-2.2.4
  local_security_policy { 'Add workstations to domain':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-adjust-memory-quotas-2.2.5
  local_security_policy { 'Adjust memory quotas for a process':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','LOCAL SERVICE','NETWORK SERVICE'],
  }

  # cis-allow-login-locally-2.2.6
  local_security_policy { 'Allow log on locally':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-allow-login-rds-2.2.7
  local_security_policy { 'Allow log on through Remote Desktop Services':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','REMOTE_DESKTOP'],
  }

  # cis-ensure-backup-files-2.2.8
  local_security_policy { 'Back up files and directories':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }
  
  # cis-ensure-change-system-time-2.2.9
  local_security_policy { 'Change the system time':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','LOCAL_SERVICE'],
  }

  # cis-ensure-change-time-zone-2.2.10
  local_security_policy { 'Change the time zone':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','LOCAL_SERVICE'],
  }

  # cis-allow-create-pagefile-2.2.11
  local_security_policy { 'Create a pagefile':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-allow-create-token-object-2.2.12
  local_security_policy { 'Create a token object':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  # cis-allow-create-global-objects-2.2.13
  local_security_policy { 'Create global objects':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','SERVICE','LOCAL_SERVICE','NETWORK_SERVICE'],
  }

  # cis-allow-create-shared-objects-2.2.14
  local_security_policy { 'Create permanent shared objects':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  # cis-allow-create-symbolic-links-2.2.15
  local_security_policy { 'Create symbolic links':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-allow-debug-programs-2.2.16
  local_security_policy { 'Debug programs':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-deny-access-from-network-2.2.17
  # local_security_policy { 'Deny access to this computer from the network':
  #  ensure       => present,
  #  policy_value => 'BUILTIN_ADMINISTRATORS',
  # }

  # cis-deny-logon-as-batch-job-guests-2.2.18
  local_security_policy { 'Deny log on as a batch job':
    ensure       => present,
    policy_value => 'Guests',
  }

  # cis-deny-logon-as-service-guests-2.2.19
  local_security_policy { 'Deny log on as a service':
    ensure       => present,
    policy_value => 'Guests',
  }

  # cis-deny-logon-locally-guests-2.2.20
  local_security_policy { 'Deny log on locally':
    ensure       => present,
    policy_value => 'Guests',
  }

  # cis-deny-logon-RDS-2.2.21
  local_security_policy { 'Deny log on through Remote Desktop Services':
    ensure       => present,
    policy_value => ['Guests','LOCAL'],
  }

  # cis-enable-accounts-trusted-for-delegation-2.2.22
  local_security_policy { 'Enable computer and user accounts to be trusted for delegation':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  # cis-allow-force-shutdown-2.2.23
  local_security_policy { 'Force shutdown from a remote system':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-allow-generate-security-audits-2.2.24
  local_security_policy { 'Generate security audits':
    ensure       => present,
    policy_value => ['LOCAL_SERVICE','NETWORK_SERVICE'],
  }

  # cis-configure-impersonate-client-2.2.25
  local_security_policy { 'Impersonate a client after authentication':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','LOCAL_SERVICE','NETWORK_SERVICE','SERVICE'],
  }

  # cis-increase-scheduling-priority-2.2.26
  local_security_policy { 'Increase scheduling priority':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-load-unload-device-drivers-2.2.27
  # TODO:

  # cis-lock-pages-in-memory-noone-2.2.28
  local_security_policy { 'Lock pages in memory':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  # cis-logon-as-batch-job-2.2.29
  # TODO: 

  # cis-manage-auditing-security-log-2.2.30
  local_security_policy { 'Manage auditing and security log':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-manage-object-label-noone-2.2.31
  local_security_policy { 'Modify an object label':
    ensure       => present,
    policy_value => 'NOBODY',
  }

  # cis-modify-fireware-environment-2.2.32
  local_security_policy { 'Modify firmware environment values':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-perform-volume-maintaince-2.2.33
  local_security_policy { 'Perform volume maintenance tasks':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-profile-single-process-2.2.34
  local_security_policy { 'Profile single process':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-profile-system-performance-2.2.35
  local_security_policy { 'Profile system performance':
    ensure       => present,
    policy_value => ['BUILTIN_ADMINISTRATORS','S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'],
  }

  # cis-replace-progress-level-token-2.2.36
  local_security_policy { 'Replace a process level token':
    ensure       => present,
    policy_value => ['LOCAL_SERVICE','NETWORK_SERVICE'],
  }

  # cis-restore-files-and-directories-2.2.37
  local_security_policy { 'Restore files and directories':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-shutdown-the-system-2.2.38
  local_security_policy { 'Shut down the system':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }

  # cis-synchronize-dc-data-2.2.39
  # TODO:

  # cis-take-ownership-of-files-2.2.40
  local_security_policy { 'Take ownership of files or other objects':
    ensure       => present,
    policy_value => 'BUILTIN_ADMINISTRATORS',
  }
}
