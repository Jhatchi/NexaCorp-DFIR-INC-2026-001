# INC-2026-001 - NexaCorp Intrusion Investigation
## Investigation Journal - Phase 1 Complete

---

**Analyst:** Johan-Emmanuel Hatchi (blue11)
**Organization:** BeCode Corp
**Client:** NexaCorp
**Engagement:** INC-2026-001
**Investigation start:** 2026-05-11 09:55 UTC
**Phase 1 completion:** 2026-05-11 ~12:00 UTC
**Report deadline:** 2026-05-15 (Friday) 18:00 local
**Classification:** Internal - Not for distribution

---

## 1. Lab Context

### 1.1 SOC infrastructure (BeCode Corp)

| Component | Value |
|---|---|
| SOC workstation | `10.30.0.191` (Ubuntu 22.04 LTS, hostname `blue11`) |
| Monitoring interface | `ens19` (MTU 1450) |
| Suricata version | 6.0.4 RELEASE |
| SIEM / Wazuh dashboard | `https://10.40.0.210` (manager.name: wazuh) |
| Lab access | Tailscale tunnel |

### 1.2 Wazuh agent under investigation

| Field | Value |
|---|---|
| Agent ID | `020` |
| Agent name | `blue11` |
| Reported IP (Wazuh) | `192.168.100.60` |
| **Target IP (PCAP)** | **`192.168.10.10`** |
| Hostname (PCAP shell) | `metasploitable` |
| OS (Wazuh) | Ubuntu 22.04.5 LTS |
| OS (PCAP shell) | Linux 2.6.24-16-server (Metasploitable 2) |

**IP/OS mismatch resolved per lab design:** Wazuh agent runs on a separate monitoring host that ingests logs from the Metasploitable target. Confirmed by coach.

### 1.3 Subnets

| Subnet | Purpose |
|---|---|
| `192.168.10.0/24` | NexaCorp target subnet |
| `172.16.50.0/24` | Attacker origin subnet |
| `10.30.0.0/24` | BeCode SOC workstations |
| `10.40.0.0/24` | BeCode SIEM + ancillary infra |

---

## 2. Incident Framing

### 2.1 Client narrative (per Sarah Chen briefing, 10 May 20:33)

NexaCorp's IT team observed **unexpected outbound connections from one of their internal servers**. Their **firewall flagged some traffic but generated no actionable alert**.

**Business stakes:** NexaCorp's board awaits the analyst's report before deciding on disclosure / regulatory notification.

### 2.2 Reported window

- **PCAP coverage:** May 9 20:08 UTC → May 10 01:39 UTC (5h30m)
- **Wazuh logs coverage:** broader - earliest log events back to May 9 07:48 UTC

---

## 3. Evidence Inventory

### 3.1 Files

| File | Size | Notes |
|---|---|---|
| `attack.pcap` | 943 KB | 5194 packets, 5h30 window |
| `wazuh-alerts.json` | 50 B | **INVALID** (HTTP 404 stored) |
| `logs/auth.log` | 3.3 KB | Starts May 10 06:47 UTC (post-incident) |
| `logs/syslog` | 22 KB | Starts May 10 06:37 UTC (`syslogd restart`) |
| `events-2026-05-11T12_05_44_977Z.csv` | 30 KB | **Wazuh export (397 events)** - analyzed in §9 |
| `README.txt` | 967 B | Client framing |

### 3.2 Evidence package limitations

1. **PCAP starts mid-incident** - Sandcat C2 beacon already active at frame 1
2. **Host logs ~7h post-incident** - first entry is `syslogd restart` (likely VM reboot)
3. **`wazuh-alerts.json` is invalid** (HTTP 404 stored as JSON)
4. **Wazuh log ingestion was temporarily unavailable** until 2026-05-11 11:39 UTC (confirmed by coach Thomas B. (BeCode lab coach)) - once restored, 397 events were retrievable via the dashboard

---

## 4. Investigation Plan - Status

| Step | Description | Status |
|---|---|---|
| A | High-level PCAP triage | ✅ Done |
| B | Reconnaissance detection (FTP/HTTP/multi-protocol) | ✅ Done |
| C | Service identification | ✅ Done |
| D | Exploit confirmation | ✅ Done |
| E | Post-exploit shell analysis | ✅ Done |
| F | C2 channel analysis (Caldera) | ✅ Done |
| G | Host log correlation | ✅ Done (gap confirmed) |
| H | Wazuh SIEM analysis | ✅ Done (post-restoration) |
| I | Multi-protocol enumeration analysis | ✅ Done (I8) |
| J | SSH brute-force detection in SIEM | ✅ Done (I9) |
| K | Detection gap synthesis | ✅ Done |
| L | Phase 1 report writing | ⏳ In progress |
| M | Phase 2 - Suricata rules | ⏳ Next |

---

## 5. Working Hypotheses - Final

| # | Hypothesis | Status |
|---|---|---|
| H1 | Attacker = `192.168.100.10` (lab Caldera) | ❌ Refuted - actual: `172.16.50.10` |
| H2 | Vulnerable legacy FTP | ✅ Confirmed - vsftpd 2.3.4 |
| H3 | Exploit yields RCE | ✅ Confirmed - bind shell root port 6200 |
| H4 | "Unusual outbound" = Caldera Sandcat | ✅ Confirmed |
| H5 | Sandcat predates capture | ✅ Confirmed |
| H6 | vsftpd attacker = Sandcat operator | ⚠️ Inconclusive (different IPs, likely separate per lab design) |
| H7 (new) | Attacker active on target beyond PCAP window | ✅ Confirmed - Wazuh shows recon back to May 9 07:48 UTC, plus SSH brute-force |

---

## 6. Findings Log

### I1 - vsFTPd 2.3.4 vulnerable service (CVE-2011-2523)
- **Evidence:** PCAP banner `220 (vsFTPd 2.3.4)` from `192.168.10.10:21`
- **Description:** Backdoor-laced build from July 2011. `USER xxx:)` triggers root bind shell on port 6200.
- **Reference:** CVE-2011-2523, CVSS 10.0
- **Confidence:** High

### I2 - FTP reconnaissance (May 9 20:12 → 22:12 UTC visible in PCAP, but extends back to 07:48 UTC per Wazuh)
- **Evidence:** PCAP - 12 FTP request sequences from `172.16.50.10`; Wazuh CSV - earliest CONNECT timestamps in `full_log` go back to May 9 07:48 UTC
- **PCAP patterns:**
  - 7× `USER anonymous + PASS guest@ + LIST + QUIT` (content mapping)
  - 5× `USER <account> + PASS wrongpassword + QUIT` (username enumeration)
- **Wazuh confirmation:** rule.id 11401 fires 43× in the CSV, rule.id 11402 fires 14× (anonymous auth success)
- **MITRE:** T1595.002, T1078.003, T1589

### I3 - Exploit triggered (May 9 22:53:31 UTC)
- **Evidence:** PCAP - `USER baduser:)` + `PASS anything`. No QUIT after.
- **MITRE:** T1190
- **Note:** vsftpd 2.3.4 does **not log** the exploit attempt - Wazuh search `full_log: "baduser"` returns zero results, confirming the backdoor bypasses application-level logging

### I4 - Root bind shell on port 6200 (May 9 22:53:35 UTC)
- **Evidence:** PCAP TCP stream 70, ~20 seconds
- **8 commands:** `id`, `whoami`, `uname -a`, `hostname`, `cat /etc/passwd`, `ls /home`, `ifconfig`, `netstat -an | grep LISTEN`
- **MITRE:** T1059.004 + T1033, T1082, T1087.001, T1083, T1016, T1049

### I5 - Pre-existing Caldera Sandcat C2 implant (entire PCAP window)
- **Evidence:** PCAP TCP stream 6, conversation to `10.40.0.200:8888`, 2218 frames, 572 KB
- **Beacon every ~40-50s**, decoded Base64 JSON reveals: `paw=mesdec`, `pid=4749`, `ppid=1`, `location=/opt/caldera/sandcat`, `username=root`, `privilege=Elevated`
- **C2 server response:** empty instruction set (`[]`)
- **MITRE:** T1071.001, T1029, T1102
- **Note:** This is the "unusual outbound connection" reported by NexaCorp. Predates the captured window.

### I6 - Host logs do not cover incident window
- **Evidence:** auth.log starts May 10 06:47, syslog starts May 10 06:37 with `syslogd restart`
- **Searches in provided logs:** `vsftpd|ftp`, `172.16.50.10`, `10.40.0.200` all return 0 results

### I7 - Wazuh detection coverage (post-restoration analysis)
- **Logged:** 2026-05-11, finalized after CSV export analysis
- **Phase:** Defense / SIEM
- **Total events ingested for agent `020`** (`location: *nexacorp*`): **397**
- **Filter `data.srcip: "172.16.50.10"` (attacker):** 74 of 397 events
- **Severity distribution (full 397 events):**

| Level | Count | % |
|---|---|---|
| 3 | 351 | 88.4% |
| 4 | 2 | 0.5% |
| 5 | 28 | 7.1% |
| 6 | 12 | 3.0% |
| **10** | **4** | **1.0%** |
| ≥12 | 0 | 0% |

- **Only 4 high-severity alerts in the entire incident:**

| Time (ingestion) | Rule.id | Level | Description |
|---|---|---|---|
| 13:27:57.309 | 11452 | 10 | vsftpd: Multiple FTP connection attempts from same source IP |
| 13:27:57.265 | 11452 | 10 | vsftpd: Multiple FTP connection attempts from same source IP |
| 13:27:54.799 | 5551 | 10 | PAM: Multiple failed logins in a small period of time |
| 13:17:26.066 | 5551 | 10 | PAM: Multiple failed logins in a small period of time |

- **Rule 11452 threshold:** 12 occurrences of rule 11401 from same source IP in 60 seconds
- **Rule 5551 threshold:** 8 occurrences of rule 5503 in 120 seconds
- **Conclusion:** Wazuh did detect the *brute-force fingerprint* of the attack (level 10, MITRE T1110 Brute Force), but:
  - **None** of the 4 alerts identifies the actual CVE-2011-2523 exploitation
  - **None** identifies the bind shell on port 6200
  - **None** identifies the Caldera C2 beacon
  - All 4 alerts would have classified as routine brute-force noise in a real SOC queue
  - The exploit payload itself (`USER baduser:)`) was **never logged** by vsftpd, so no rule could ever match it

### I8 - Multi-protocol service enumeration (PCAP)
- **Evidence:** Beyond FTP, attacker `172.16.50.10` enumerated 5 additional services:
  - HTTP/80: 26+ GET requests (`/`, `/robots.txt`, `/index.php`, `/admin`, `/login`, `/phpmyadmin`)
  - SSH/22: 2 banner grabs (`SSH-2.0-OpenSSH_4.7p1`)
  - SMTP/25: 3 banner grabs
  - Telnet/23: 2 connections
  - MySQL/3306: 1 banner
- **HTTP user-agents:** `curl/7.81.0`, `Wget/1.21.2`
- **MITRE:** T1046, T1592.002

### I9 - SSH brute-force attempts (Wazuh only, not visible in PCAP)
- **Logged:** 2026-05-11 after Wazuh CSV analysis
- **Evidence:** Wazuh CSV shows:
  - **16× rule 5503** (PAM: User login failed) - level 5
  - **12× rule 5706** (sshd: insecure connection attempt - scan) - level 6
  - **2× rule 5551** (PAM: Multiple failed logins in small period) - level 10
  - **12× rule 5715** (sshd: authentication success) - level 3
  - **10× rule 5602** (telnetd: Remote connection) - level 3
- **Description:** The attacker also attempted SSH brute-force, partially out of the PCAP window (which only shows 2 SSH banner-grab frames). The PAM failures triggered rule 5551 (level 10) twice, demonstrating that Wazuh correctly detects rapid brute-force attempts on PAM/SSH - but only when the attack cadence is fast enough to cross the threshold (8 failures in 120s for rule 5551).
- **Note on 5715 (12 SSH successes):** Likely a mix of legitimate admin sessions (`msfadmin` from `192.168.10.1` visible in auth.log) and possibly attacker sessions if credentials were obtained. Requires `full_log` inspection per event.
- **MITRE:** T1110 (Brute Force)

### I10 - Anomalous sudo activity
- **Logged:** 2026-05-11 after Wazuh CSV analysis
- **Evidence:** Wazuh CSV shows:
  - **61× rule 5402** (Successful sudo to ROOT executed) - level 3
  - **17× rule 5407** (Successful sudo executed) - level 3
  - **2× rule 5403** (First time user executed sudo) - level 4
- **Description:** **80 sudo events** in the agent's history. Most concerning is rule 5403 - **two users executed sudo for the first time on this host**. This is a classic IoC pattern (an account that never used sudo suddenly does). Without `full_log` field correlation for these specific events, the user identity and exact timestamps are inferred but not yet confirmed.
- **Recommendation:** Pull the full_log of all 80 sudo events from Wazuh and identify which user accounts triggered them, and at what timestamps relative to the FTP exploit.
- **MITRE:** T1548.003 (Sudo and Sudo Caching) - possible

---

## 7. IOCs

### 7.1 Network

| Type | Value | Context |
|---|---|---|
| IP (src) | `172.16.50.10` | Attacker |
| IP (dst) | `192.168.10.10` | Target |
| IP (C2) | `10.40.0.200` | Caldera Sandcat C2 |
| Port | `21/tcp` | vsftpd 2.3.4 vulnerable service |
| Port | `6200/tcp` | Backdoor bind shell (CVE-2011-2523) |
| Port | `8888/tcp` | Caldera C2 endpoint |

### 7.2 Payload signatures

| Signature | Context |
|---|---|
| `USER` argument matching regex `.*:\)$` | CVE-2011-2523 trigger |
| FTP banner `220 (vsFTPd 2.3.4)` | Vulnerable service |
| HTTP POST `/beacon` with UA `Go-http-client/1.1` | Caldera beacon |
| HTTP `Server: Python/3.10 aiohttp/3.13.4` on :8888 | Caldera C2 server |

### 7.3 Host artifacts

| Type | Value |
|---|---|
| Binary path | `/opt/caldera/sandcat` |
| Process | PID 4749, PPID 1 |
| User | `root` |
| Caldera paw | `mesdec` |
| Caldera group | `lab-unknown` |

---

## 8. Timeline (consolidated, UTC)

| # | Timestamp | Source | Event |
|---|---|---|---|
| 01 | **May 9 ~07:48** | Wazuh (full_log) | First connection from `172.16.50.10` to vsftpd (per rule 11452 previous_output) |
| 02 | May 9 ~13:23 → 19:05 | Wazuh | Continued FTP reconnaissance every ~20-90 min |
| 03 | May 9 19:05:38 | Wazuh | **Rule 11452 (level 10) would fire here** if SIEM was live - 12 FTP connects in 60s observed |
| 04 | May 9 20:08:30 | PCAP frame 1+ | **Caldera Sandcat already beaconing** (pre-existing implant) |
| 05 | May 9 20:10:48 | PCAP | First HTTP recon from attacker |
| 06 | May 9 20:12:36 | PCAP | First FTP banner exposed `220 (vsFTPd 2.3.4)` |
| 07 | May 9 20:12 → 22:12 | PCAP | 12 FTP recon/enum attempts visible in PCAP window |
| 08 | May 9 20:54 → 22:54 | PCAP | Multi-protocol banner grabs (HTTP/SSH/SMTP/Telnet/MySQL) |
| 09 | May 9 ~21:00-22:00 | Wazuh | **Rule 5551 (level 10) PAM brute-force** - also from `172.16.50.10` (16× failed PAM auths) |
| 10 | **May 9 22:53:31** | PCAP | **🚨 EXPLOIT: `USER baduser:)` (CVE-2011-2523)** |
| 11 | May 9 22:53:32 | PCAP | `PASS anything` - flow ends without QUIT |
| 12 | **May 9 22:53:35** | PCAP | **🚨 Bind shell TCP/6200 opened** |
| 13-20 | 22:53:35 → 22:53:55 | PCAP | 8 root commands (id/whoami/uname/.../netstat) |
| 21 | May 9 ~22:53:55 | PCAP | Bind shell ends (~20s session) |
| 22 | 23:05 → May 10 01:13 | PCAP | 6 additional FTP recon attempts post-exploit |
| 23 | May 10 01:39:03 | PCAP frame 5194 | End of capture |
| 24 | May 10 06:37:10 | syslog | `syslogd restart` (VM reboot) |
| 25 | May 10 08:47:22 | auth.log | First post-incident SSH login (`msfadmin` from 192.168.10.1) |
| 26 | **May 11 11:39** | Coach | Wazuh log ingestion pipeline restored |
| 27 | May 11 13:17-13:28 | Wazuh | Bulk ingestion of 397 NexaCorp events into SIEM, triggering 4 retrospective level-10 alerts |

---

## 9. Detection Gap Analysis (final)

### 9.1 What Wazuh ingested (397 events, agent `020`, `location: *nexacorp*`)

| Rule.id | Description | Level | Count |
|---|---|---|---|
| 5501 | PAM: Login session opened | 3 | 98 |
| 5502 | PAM: Login session closed | 3 | 92 |
| **5402** | **Successful sudo to ROOT executed** | 3 | **61** |
| 11401 | vsftpd: FTP session opened | 3 | 43 |
| 5407 | Successful sudo executed | 3 | 17 |
| 5503 | PAM: User login failed | 5 | 16 |
| 11402 | vsftpd: FTP Authentication success | 3 | 14 |
| 5715 | sshd: authentication success | 3 | 12 |
| 5706 | sshd: insecure connection attempt (scan) | 6 | 12 |
| 5602 | telnetd: Remote host connection | 3 | 10 |
| 11403 | vsftpd: Login failed | 5 | 10 |
| 12119 | BIND has been started | 3 | 4 |
| **11452** | **vsftpd: Multi-connect from same source IP** | **10** | **2** |
| 1006 | Syslogd restarted | 5 | 2 |
| **5551** | **PAM: Multi-failed logins** | **10** | **2** |
| 5403 | First time user executed sudo | 4 | 2 |

### 9.2 What Wazuh did NOT detect

- ❌ The CVE-2011-2523 exploit payload (`USER baduser:)`) - vsftpd does not log it
- ❌ The bind shell on TCP/6200 (Wazuh has no network telemetry)
- ❌ The 8 root commands executed via the backdoor (no auditd, no NIDS)
- ❌ The Caldera HTTP beacon to `10.40.0.200:8888` (no NIDS, no proxy logs)
- ❌ The HTTP path enumeration (`/admin`, `/phpmyadmin`, `/login`)
- ❌ The multi-protocol banner grabbing pattern

### 9.3 What Wazuh DID detect (with caveats)

**4 alerts at level 10:**
1. **2× rule 11452** (vsftpd brute-force, MITRE T1110): correctly identifies high frequency FTP connections from `172.16.50.10`, but classifies as "brute-force" - not "exploitation"
2. **2× rule 5551** (PAM brute-force, MITRE T1110): identifies the rapid SSH/PAM auth failures, but again classifies as brute-force noise

Neither rule pointed to:
- The actual exploitation method (smiley payload)
- The post-exploit shell access
- The persistent C2 channel

### 9.4 Root cause of detection gap

1. **No application-level exploit detection** - Wazuh rules for vsftpd only parse syslog-style events (CONNECT, LOGIN OK/FAIL). They do not parse the `USER` argument or look for exploit patterns.
2. **No network IDS integration** - the Caldera beacon and bind shell traffic are structurally invisible to a host-based SIEM agent.
3. **No process / file integrity monitoring** for `/opt/caldera/sandcat` - the implant binary's installation was not detected.
4. **Brute-force rules detect collateral signals only** - the 4 level-10 alerts correctly identify "abnormal connection volume" but do not surface the actual intrusion path.
5. **Signal-to-noise ratio:** 88.4% of events are level 3 (informational). 4 high-severity alerts out of 397 = 1.0% - easily dismissed as routine brute-force activity in a real SOC.

### 9.5 Recommendations summary

See client report §7 for the full prioritized list.

---

## 10. Phase 2 - Suricata Rules Notebook

Rules to deploy (7 total, see `lab.rules`):

1. **vsftpd 2.3.4 USER smiley** (SID 9000001) - CVE-2011-2523 trigger
2. **vsftpd 2.3.4 banner** (SID 9000002) - vulnerable service exposure
3. **Inbound port 6200** (SID 9000003) - backdoor bind shell
4. **Caldera beacon request** (SID 9000004) - `POST /beacon` + `Go-http-client/1.1`
5. **Caldera C2 server response** (SID 9000005) - aiohttp Python signature
6. **HTTP admin path enumeration** (SID 9000006) - `/admin`, `/phpmyadmin`, `/login`
7. **FTP user enumeration** (SID 9000007) - slow brute-force pattern

Test workflow in `workflow.md`.

---

## 11. Open Questions / Followups

- **Q:** Pull `full_log` for all 80 sudo events (rule 5402 + 5407 + 5403) to identify who executed them and when - could reveal post-exploit lateral movement
- **Q:** Investigate the 12 SSH authentication successes (rule 5715) - which usernames? Same `192.168.10.1` admin, or attacker?
- **Q:** Caldera C2 origin compromise - initial install pre-dates PCAP. Worth requesting NexaCorp's network captures or netflow from days before May 9.
- **Q:** Audit `/opt/caldera/` directory contents and process tree on the live host (post-Phase 1, with client authorization)

---

## 12. Operational Notes (BeCode internal)

- Coach the lab coach confirmed (2026-05-11 12:50) Wazuh log ingestion pipeline issue; restored at 11:39 UTC.
- SOC workstation `blue11` password changed from default at session start.
- Suricata gotcha: `comm` shows `Suricata-Main` (capital S), `pkill suricata` (lowercase) fails silently. Use `pkill -9 -f suricata` or `kill -9 <PID>`.

---

## 13. References

- Briefings 1-3 (BeCode lab)
- Sarah Chen briefing - Coach 2026-05-10 20:33
- CVE-2011-2523: https://nvd.nist.gov/vuln/detail/CVE-2011-2523
- vsftpd 2.3.4 backdoor postmortem: https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
- Metasploitable 2: https://docs.rapid7.com/metasploit/metasploitable-2/
- MITRE Caldera: https://caldera.mitre.org/
- MITRE ATT&CK: https://attack.mitre.org

---

*End of Phase 1 journal. Phase 2 lab notebook to be appended.*
