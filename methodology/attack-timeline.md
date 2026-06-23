# Attack Timeline: INC-2026-001

Chronology of the NexaCorp Linux infrastructure compromise. Timestamps are UTC. Sources: [P] = PCAP, [W] = Wazuh SIEM, [H] = host logs. NexaCorp is a fictitious BeCode lab scenario.

| Time (UTC) | Source | Event |
|---|---|---|
| 09 May 07:48 | [W] | First FTP connection from 172.16.50.10 (start of reconnaissance, ~15h before exploitation) |
| 09 May 13:23 - 19:05 | [W] | Continued low-and-slow FTP reconnaissance (one connection every 20-90 minutes) |
| 09 May 20:08:30 | [P] | PCAP capture starts. The MITRE Caldera Sandcat agent is already beaconing to 10.40.0.200:8888 (pre-existing implant, initial compromise not captured) |
| 09 May 20:10:48 | [P] | First HTTP reconnaissance from 172.16.50.10 (GET /) |
| 09 May 20:12:36 | [P] | FTP server banner exposes vsFTPd 2.3.4 |
| 09 May 20:30 - 22:00 | [P] | Username enumeration and multi-protocol banner grabbing (HTTP, SSH, SMTP, Telnet, MySQL) |
| 09 May 22:53:31 | [P] | EXPLOIT: `USER baduser:)` sent, CVE-2011-2523 backdoor triggered |
| 09 May 22:53:35 | [P] | Unauthenticated root bind shell opened on TCP/6200; attacker connects |
| 09 May 22:53:36 - 22:53:54 | [P] | 8 root enumeration commands (id, whoami, uname -a, hostname, cat /etc/passwd, ls /home, ifconfig, netstat) |
| 09 May ~22:53:55 | [P] | Bind shell closes (~20-second session); no persistence or exfiltration in this session |
| 10 May 01:39 | [P] | End of PCAP capture |
| 10 May 06:37 | [H] | First post-incident host log entry (host logs do not cover the incident window) |

The Caldera implant predates the entire captured window, indicating the initial compromise that installed it occurred before 09 May 20:08 UTC and is not represented in the evidence. The FTP exploitation and the C2 implant involve different external endpoints (172.16.50.10 vs 10.40.0.200) and are likely distinct threat actors.
