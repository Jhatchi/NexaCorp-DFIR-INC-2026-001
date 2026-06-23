# Indicators of Compromise: INC-2026-001

Indicators observed during the investigation of the NexaCorp Linux infrastructure compromise (Liege services server, 9-10 May 2026). NexaCorp is a fictitious BeCode lab scenario on isolated infrastructure; these indicators are not real-world threat intelligence. The `Source` column records where each indicator was observed.

## Network indicators

| Type | Value | Source |
|---|---|---|
| Attacker source IP | 172.16.50.10 | pcap, Wazuh |
| C2 endpoint (pre-existing implant) | 10.40.0.200:8888 (Caldera Sandcat) | pcap |
| C2 beacon endpoint | POST /beacon (Go-http-client/1.1 user agent) | pcap |
| Exploit transport | FTP control channel, TCP/21 | pcap |
| Backdoor listener | TCP/6200 (unauthenticated root bind shell) | pcap |

## Host and application indicators

| Type | Value | Source |
|---|---|---|
| Target host | 192.168.10.10 (Metasploitable 2, hostname metasploitable) | pcap |
| Vulnerable service | vsftpd 2.3.4 (CVE-2011-2523 backdoor) | pcap (FTP banner) |
| Exploit trigger | FTP USER argument ending in the smiley sequence (`USER baduser:)`) | pcap |
| Implant on disk | /opt/caldera/sandcat (daemonised as root, PID 4749) | beacon payload |
| OpenSSH version exposed | OpenSSH 4.7p1 Debian-8ubuntu1 | pcap (banner) |

## Behavioral indicators

| Type | Value | Source |
|---|---|---|
| Low-and-slow reconnaissance | FTP connections every 20-90 minutes over ~15 hours before exploitation | Wazuh, pcap |
| Username enumeration | USER attempts with placeholder password `wrongpassword` | pcap |
| Post-exploit session | ~20-second root shell on TCP/6200, 8 enumeration commands, then clean disengagement | pcap |
| C2 cadence | beacon to 10.40.0.200:8888 every 37-53 seconds | pcap |

## Account indicators

| Type | Value | Source |
|---|---|---|
| Exploit username artifact | `baduser:)` (CVE-2011-2523 trigger, not a real account) | pcap |
| Implant identity | runs as root (uid=0), agent paw `mesdec` | beacon payload |

> No credentials were exfiltrated through the captured FTP exploit (reconnaissance only). The Caldera implant predates the capture and indicates a separate, earlier compromise. Raw evidence is BeCode lab property and is not redistributed.
