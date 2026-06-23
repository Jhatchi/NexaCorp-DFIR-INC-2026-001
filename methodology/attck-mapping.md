# MITRE ATT&CK Mapping: INC-2026-001

Mapping of the INC-2026-001 findings to MITRE ATT&CK Enterprise techniques (v15). NexaCorp is a fictitious BeCode lab scenario.

| Finding | Tactic | Technique ID | Technique Name | Observed evidence |
|---|---|---|---|---|
| I1, I3 | Initial Access | T1190 | Exploit Public-Facing Application | CVE-2011-2523 backdoor in vsftpd 2.3.4 |
| I3 | Initial Access | T1133 | External Remote Services | FTP backdoor exposing a remote shell |
| I4 | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | root bind shell on TCP/6200 |
| I4 | Discovery | T1033 | System Owner/User Discovery | id, whoami |
| I4 | Discovery | T1082 | System Information Discovery | uname -a, hostname |
| I4 | Discovery | T1087.001 | Account Discovery: Local Account | cat /etc/passwd |
| I4 | Discovery | T1083 | File and Directory Discovery | ls /home |
| I4 | Discovery | T1016 | System Network Configuration Discovery | ifconfig |
| I4, I6 | Discovery | T1049 | System Network Connections Discovery | netstat -an |
| I5 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Caldera beacon to 10.40.0.200:8888 |
| I5 | Command and Control | T1102 | Web Service | Caldera C2 over HTTP |
| I5 | Persistence | T1543.002 | Create or Modify System Process: Systemd Service (suspected) | Sandcat daemonised as root (PID 4749, PPID 1) |
| I2 | Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | low-and-slow FTP probing |
| I2 | Reconnaissance | T1589 | Gather Victim Identity Information | FTP username enumeration |
| I6 | Reconnaissance | T1592.002 | Gather Victim Host Information: Software | multi-protocol banner grabbing |
| I6 | Discovery | T1046 | Network Service Discovery | service enumeration (HTTP/SSH/SMTP/Telnet/MySQL) |
| I7 | Credential Access | T1110 / T1110.001 | Brute Force / Password Guessing | SSH and PAM brute-force attempts (Wazuh) |
| I8 | Privilege Escalation | T1548.003 | Sudo and Sudo Caching (suspected) | anomalous first-time-sudo events (Wazuh) |

Framework version : MITRE ATT&CK Enterprise v15. Finding references (I1-I10) correspond to the sections of the findings report.
