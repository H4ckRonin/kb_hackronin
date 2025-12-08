# Network Security - eCPPTv2

## Overview
Network security concepts including information gathering, vulnerability assessment, exploitation, post-exploitation, anonymity, and social engineering.

**Sources**: 
- [johnermac.github.io](https://johnermac.github.io/notes/ecppt/networksecurity/)
- [dev-angelist/eCPPTv2-PTP-Notes](https://github.com/dev-angelist/eCPPTv2-PTP-Notes)

## Information Gathering

### Business vs Infrastructure
- **Business**: Collecting information regarding the type of business, its stakeholders, assets, products, services, employees and generally non-technical information
- **Infrastructure**: Networks, systems, domains, IP addresses, etc

### Passive or Active

**Passive or OSINT**:
- Web presence, partners, financial info, physical plants, infrastructure related information etc
- Get information without exposing our presence
- Using publicly available resources (accessible by anyone)

**Active**:
- Gather information about ports, services, running systems, net blocks etc
- Active techniques can reveal the investigation to the organization through IDS or server logs
- Caution should be taken to prevent detection

### Mind Mapping Technology
- FreeMind: http://freemind.sourceforge.net/wiki/index.php/Main_Page
- Xmind: https://www.xmind.net/

### Keep Track of Networks/Vulns Scans
- Dradis: http://dradisframework.org/
- Faraday: https://github.com/infobyte/faraday
- Magitree: http://www.gremwell.com/what_is_magictree

### Search Engine

#### Web Presence
- What they do
- What is their business purpose
- Physical and logical locations
- Employees and departments
- Email and contact information
- Alternative web sites and sub-domains
- Press releases, news, comments, opinions
- Start with the company name and company website
- Analyze information that is publicly available

#### Google Dorks
- https://www.exploit-db.com/google-hacking-database/
- http://pdf.textfiles.com/security/googlehackers.pdf
- http://www.googleguide.com/advanced_operators_reference.html

## Vulnerability Assessment

### Low Hanging Fruits (LHF)
- Default credentials
- Missing patches
- Misconfigurations
- Exposed services

### Exploitation
- Exploit development
- Payload creation
- Shellcode development

## Post Exploitation

### Privilege Escalation and Maintaining Access
- Local privilege escalation techniques
- Persistence mechanisms
- Backdoors

### Data Harvesting (aka Pillaging)
- Credential extraction
- File system enumeration
- Registry access
- Database access

### Mapping the Internal Network
- Network discovery
- Service enumeration
- Host identification

### Exploitation through Pivoting

Pivoting allows you to use a compromised system to access networks that are not directly accessible from your attacking machine.

#### Port Forwarding
```bash
# Local port forwarding (SSH)
ssh -L <local_port>:<remote_host>:<remote_port> user@<jump_host>

# Example: Forward local 3389 to remote 3389
ssh -L 3389:192.168.1.100:3389 user@compromised_host

# Remote port forwarding (SSH)
ssh -R <remote_port>:<local_host>:<local_port> user@<jump_host>

# Dynamic port forwarding (SOCKS proxy)
ssh -D <local_port> user@<jump_host>
```

#### Metasploit Port Forwarding
```bash
# Add route
route add <subnet> <netmask> <session_id>

# Port forward
portfwd add -l <local_port> -p <remote_port> -r <remote_host>

# Example
portfwd add -l 3389 -p 3389 -r 192.168.1.100
```

#### Proxychains
```bash
# Configure /etc/proxychains.conf
# Add: socks4 127.0.0.1 1080

# Use proxychains
proxychains nmap -sT <target>
proxychains ssh user@<target>
proxychains rdesktop <target>
```

#### Chisel
```bash
# Server (on compromised host)
chisel server -p 8000 --reverse

# Client (on attacker)
chisel client <server>:8000 R:1080:socks

# Then use proxychains
```

#### SSHuttle
```bash
# VPN-like tunneling
sshuttle -r user@<jump_host> <subnet>

# Example
sshuttle -r user@compromised_host 192.168.1.0/24
```

#### Plink (Windows)
```bash
# Port forwarding
plink.exe -ssh -L <local_port>:<remote_host>:<remote_port> user@<jump_host>

# SOCKS proxy
plink.exe -ssh -D <local_port> user@<jump_host>
```

### Regular Payload
- Meterpreter
- Bind shells
- Reverse shells

## Anonymity

### Browsing Anonymously
- Proxy chains
- VPN
- Tor

### Tunneling for Anonymity
- SSH tunnels
- VPN tunnels
- Proxy tunnels

### Using Tor
```bash
# Start Tor service
service tor start

# Use with proxychains
# Configure /etc/proxychains.conf to use Tor
# Then: proxychains <command>
```

### VPN Tunneling
```bash
# OpenVPN
openvpn --config config.ovpn

# WireGuard
wg-quick up wg0
```

## Social Engineering

### Types of Social Engineering
- Phishing
- Pretexting
- Baiting
- Quid pro quo
- Tailgating

### Samples of Social Engineering Attacks
- Email phishing
- Phone phishing
- Physical access
- USB drops

### Tools
- SET (Social Engineering Toolkit)
- Gophish
- King Phisher

### Social Engineering Linux Targets
- Custom payloads
- Linux-specific techniques

## Metasploit

### Database Setup
```bash
service postgresql start
msfdb init
msfdb start
msfdb status
```

### Pivoting in Metasploit
```bash
# Get session
sessions -i <session_id>

# Add route
route add <subnet> <netmask> <session_id>
route print

# Port forward
portfwd add -l <local_port> -p <remote_port> -r <remote_host>
portfwd list
portfwd delete <local_port>

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run

# Then use proxychains
```

### Lab Scenarios
- Client Side attacks
- DNS & SMB Relay
- Various exploitation scenarios
- Pivoting through networks
- Lateral movement

## Network Enumeration

### Nmap Advanced Scanning
```bash
# Stealth scan
nmap -sS -T2 <target>

# UDP scan
nmap -sU <target>

# Service version detection
nmap -sV <target>

# OS detection
nmap -O <target>

# Aggressive scan
nmap -A <target>

# Scan specific ports
nmap -p 80,443,8080 <target>

# Scan all ports
nmap -p- <target>

# Save output
nmap -oN output.txt <target>
nmap -oX output.xml <target>
nmap -oG output.gnmap <target>
```

### SMB Enumeration
```bash
# List shares
smbclient -L //<target> -N
smbclient -L //<target> -U ""

# Connect to share
smbclient //<target>/share -N

# Enum4linux
enum4linux -a <target>
enum4linux -U <target>
enum4linux -S <target>

# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users <target>
nmap --script smb-vuln-* <target>
```

### SNMP Enumeration
```bash
# SNMP walk
snmpwalk -c public -v 2c <target>
snmpwalk -c private -v 2c <target>

# SNMP check
onesixtyone -c community.txt <target>
```

### DNS Enumeration
```bash
# Zone transfer
dig axfr @<target> <domain>
host -l <domain> <target>

# DNS enumeration
dnsrecon -d <domain>
dnsenum <domain>
```

## Tools
- **Nmap** - Network scanning
- **Metasploit** - Exploitation framework
- **Burp Suite** - Web application security
- **Wireshark** - Network protocol analyzer
- **Dradis** - Reporting framework
- **Faraday** - Collaborative penetration testing
- **Proxychains** - Proxy chains
- **Chisel** - Fast TCP/UDP tunnel
- **SSHuttle** - VPN over SSH
- **Plink** - Windows SSH client
- **Enum4linux** - SMB enumeration
- **CrackMapExec** - Network exploitation

## Resources
- **Metasploit Unleashed**: https://www.offensive-security.com/metasploit-unleashed/
- **Nmap Documentation**: https://nmap.org/docs.html

## Last Updated
January 2025

