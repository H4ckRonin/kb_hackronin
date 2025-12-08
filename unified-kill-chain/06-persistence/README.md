# Phase 6: Persistence

## Overview
Persistence involves maintaining access to compromised systems after initial exploitation. This phase ensures that attackers can regain access even if the initial entry point is closed.

## Objectives
- Establish backdoors
- Create multiple persistence mechanisms
- Ensure access survives reboots
- Maintain access across system changes
- Hide persistence mechanisms

## Techniques

### Boot or Logon Autostart Execution
- Registry run keys
- Startup folders
- Scheduled tasks
- Services

### Scheduled Task/Job
- Windows Task Scheduler
- Linux cron jobs
- Systemd timers

### Create Account
- Local accounts
- Domain accounts
- Service accounts

### Registry Run Keys
- Run, RunOnce keys
- User-specific keys

### Windows Service
- Service installation
- Service modification

## Tools
- PowerUp
- WinPEAS
- Metasploit persistence modules
- Custom scripts

## Defensive Measures
- Monitor for new accounts
- Review scheduled tasks
- Monitor registry changes
- Service monitoring
- Behavioral analysis

## Related Phases
- **Previous**: Exploitation (Phase 5)
- **Next**: Defense Evasion (Phase 7)

## References
- MITRE ATT&CK: Persistence

## Last Updated
[Date]

