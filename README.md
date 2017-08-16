# windows-hardening (Puppet Module)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with windows_hardening](#setup)
    * [What windows_hardening affects](#what-windows_hardening-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with windows_hardening](#beginning-with-windows_hardening)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Overview

This module provides classes for ensuring that a Windows system is compliant with the [DevSec Windows Baseline](https://github.com/dev-sec/windows-baseline).

## Setup

### What windows_hardening affects

* Registry settings
* Local group policy settings

## Usage

While each class here can be used in isolation is it assumed that in the general case this module will be applied in it's entirity using ```include windows_hardening``` in an existing profile.

## Reference

### Classes

* `access_config`: Configures authentication and access settings
* `account_lockout`: Configures account lockout thresholds and durations
* `audit_log_config`: Configures event auditing settings
* `ie_config`: Configures IE security settings
* `password_policy`: Configures password polocies
* `powershell`:  Configures powershell security setttings
* `privacy`: Configures windows privacy settings
* `rdp_config`: Configures Remote Desktop security settings
* `user_rights`: Configures user access local polocies

## Limitations

This module has been tested on:

* Windows Server 2012 R2