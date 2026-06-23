# NexaCorp DFIR Engagement (INC-2026-001) - Linux Infrastructure Compromise

DFIR investigation and detection engineering on a simulated intrusion against NexaCorp infrastructure. Conducted as a 4-day solo engagement (BeCode Brussels Blue & Red Team bootcamp, Mission 01). The deliverable is a 54-page findings report (PDF) plus 7 validated Suricata rules that catch the captured incident in PCAP replay.

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#methodology)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Detection](https://img.shields.io/badge/Suricata-7%20rules%20validated-green.svg)](detection/lab.rules)
[![CVE](https://img.shields.io/badge/CVE--2011--2523-vsftpd%20backdoor-critical.svg)](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

## Contents

- [⚠ Operational notice](#-operational-notice)
- [At a glance](#at-a-glance)
- [Engagement context](#engagement-context)
- [Executive summary](#executive-summary)
- [Kill chain summary](#kill-chain-summary)
- [How to read this report](#how-to-read-this-report)
- [Methodology](#methodology)
- [Tools used](#tools-used)
- [Findings summary](#findings-summary)
- [Detection engineering](#detection-engineering)
- [Repository layout](#repository-layout)
- [Reproducibility](#reproducibility)
- [Known limits](#known-limits)
- [NexaCorp DFIR series](#nexacorp-dfir-series)
- [Acknowledgments](#acknowledgments)
- [About](#about)
- [License](#license)

## ⚠ Operational notice

**This is a lab engagement against fictitious infrastructure.** NexaCorp is a fictional client used as the scenario for BeCode Brussels Mission 01. The compromised host is a Metasploitable 2 VM intentionally vulnerable for security training, and the Caldera Sandcat implant is part of the lab teaching the analyst what a real intruder's beacon traffic looks like. No real organization, network, or human was attacked.

All IP addresses, hostnames, and indicators of compromise published in this report (`172.16.50.10`, `192.168.10.10`, `10.40.0.200`, `blue11`, `mesdec`, etc.) are **lab-local artifacts**, not real-world threat intelligence. Do not feed them to a SIEM as IOCs.

**Publication authorized** by BeCode lab coach (Thomas B.) on 2026-05-17. The full Confidentiality Statement appears in the findings report (section "Distribution and Classification").

## At a glance

| Engagement metadata | Value |
|---|---|
| Reference | `BCC-2026 / INC-2026-001` |
| Duration | 4 days (solo) |
| Phases | DFIR (forensic) + detection engineering |
| Delivered | 2026-05-15 |
| Status | Complete (Phase 1 + Phase 2) |

| Investigation output | Value |
|---|---|
| Findings | **10** (3 CRITICAL, 3 HIGH, 2 MEDIUM, 2 LOW) |
| MITRE ATT&CK techniques mapped | 14 |
| Network capture analyzed | 5,194 packets over 5h31m (943 KB PCAP) |
| Wazuh events correlated | 397 from agent `020` |
| Suricata rules authored | **7** (SID 9000001-9000007) |
| Rules validated by PCAP replay | **7/7** (40 fast.log alerts, 314 eve.json records) |

## Engagement context

**Scenario (fictional).** NexaCorp, a mid-sized corporate client, contacted BeCode Corp's blue team after their internal monitoring flagged **unexpected outbound traffic from one of their internal Linux servers**. Their firewall logged the traffic but raised no actionable alert. The board needed a determination before deciding on disclosure and regulatory notification.

**Mandate.** Investigate the suspected incident window, characterize the attacker's path of entry and post-exploitation activity, assess what the existing detection stack caught (and missed), and deliver a prioritized remediation plan. A second phase added detection engineering: produce ready-to-deploy network IDS rules that would catch a recurrence in real time.

**Evidence package received from the client.**

| Artefact | Coverage | Note |
|---|---|---|
| Network capture (PCAP) | 2026-05-09 20:08 to 2026-05-10 01:39 UTC (5h31m, 5,194 packets) | Starts mid-incident: implant already beaconing in frame 1 |
| Host authentication log | 2026-05-10 06:47 UTC onward | Post-incident only (gap of ~5 hours after PCAP ends) |
| Host syslog | 2026-05-10 06:37 UTC onward | First entry is `syslogd restart`, suggests VM reboot |
| SIEM alerts export (Wazuh) | n/a | File was an HTTP 404 response, not data. Recovered 397 events later via direct dashboard query |

**Educational context.** This engagement was delivered during the **BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026)** as Mission 01: a solo, time-boxed investigation simulating a real DFIR consulting engagement. The lab infrastructure, NexaCorp identity, and IOC values are deliberately fictional. The methodology, tools, and report format follow real-world standards (NIST SP 800-61r2, SANS PICERL, MITRE ATT&CK).

## Executive summary

> 📄 **The full 54-page findings report is the canonical deliverable.**
> [Download the PDF](reports/INC-2026-001_Findings_Report.pdf) (215 KB) or [browse the Markdown source](reports/INC-2026-001_Findings_Report.md) for grep/citation.

On the evening of **2026-05-09 at 22:53 UTC**, an external attacker (`172.16.50.10`) compromised a NexaCorp internal server (`192.168.10.10`) by exploiting **CVE-2011-2523**, the backdoor present in `vsftpd` 2.3.4 (a build that has been publicly documented as compromised since July 2011). A single FTP `USER` request ending with `:)` triggered an unauthenticated root bind shell on TCP/6200. The attacker ran **8 reconnaissance commands** over a 20-second session (no persistence, no exfiltration, no lateral movement via this access vector) and disconnected.

Independently, the same host was found to be running a **pre-existing MITRE Caldera "Sandcat" agent** at `/opt/caldera/sandcat` (root, daemonized) beaconing every 40-50 seconds in cleartext HTTP to `10.40.0.200:8888` throughout the captured window. This is the "unusual outbound connection" originally flagged by the client and indicates a **prior compromise not represented in the evidence package** (the implant was already active in the first PCAP frame).

The existing **Wazuh SIEM ingested 397 events** from the target host but raised only **4 high-severity alerts (1.0% of total)**, all classified as generic brute-force (MITRE T1110). None identified the CVE-2011-2523 exploit payload, the bind shell on TCP/6200, or the Caldera C2 channel: the exploit byte (`USER baduser:)`) is **never logged by vsftpd itself**, and the SIEM had no network telemetry to see the rest. The 7 Suricata rules delivered in Phase 2 close all three gaps.

**Headline IOCs (lab-bound, do not feed to a real SIEM):**

| Type | Value | Context |
|---|---|---|
| Source IP (attacker) | `172.16.50.10` | vsftpd exploit, multi-protocol recon, SSH brute-force |
| Target IP | `192.168.10.10` | Compromised internal server (Metasploitable 2) |
| C2 IP | `10.40.0.200:8888` | Caldera Sandcat command-and-control |
| Backdoor port | `6200/tcp` | CVE-2011-2523 root bind shell |
| Exploit payload | FTP `USER` ending with `:)` | Backdoor trigger pattern |

## Kill chain summary

The captured incident has two distinct strands, reconstructed from the PCAP:

1. **Exposed service**: `vsftpd` 2.3.4, a build with a publicly documented backdoor (CVE-2011-2523), was reachable on the internal network (Finding I1).
2. **Exploit**: a single FTP `USER` request ending with `:)` triggered the backdoor (Finding I3).
3. **Root bind shell**: an unauthenticated root shell opened on TCP/6200; the attacker ran 8 reconnaissance commands over a 20-second session, then disconnected, with no persistence or exfiltration through this vector (Finding I4).
4. **Parallel C2 (pre-existing)**: independently, a MITRE Caldera Sandcat implant was already beaconing in cleartext HTTP to `10.40.0.200:8888` throughout the window, evidence of a prior compromise not represented in the evidence bundle (Finding I5).

## How to read this report

The repository is organized so that you can dive in at the right depth for your role:

| If you are a... | Start here | Time |
|---|---|---|
| **Recruiter or hiring manager** | This README + skim the [PDF](reports/INC-2026-001_Findings_Report.pdf) executive summary | 5 min |
| **SOC analyst evaluating fit** | [PDF sections 5 (Detection Gap) and 8 (Detection Engineering)](reports/INC-2026-001_Findings_Report.pdf) + [`detection/lab.rules`](detection/lab.rules) | 20 min |
| **DFIR practitioner** | Full [PDF](reports/INC-2026-001_Findings_Report.pdf) + [`notes/journal.md`](notes/journal.md) for the investigation trail | 60 min |
| **Detection engineer** | [`detection/lab.rules`](detection/lab.rules) + [`detection/README.md`](detection/README.md) for deployment and replay validation | 30 min |
| **Anyone who wants to grep, cite, or diff** | [Markdown source of the report](reports/INC-2026-001_Findings_Report.md) | as needed |

**Canonical deliverable:** the PDF in `reports/`. The Markdown source is identical content, kept in the repo for searchability and version control.

**Investigation trail:** `notes/journal.md` is the analyst's working notebook (hypotheses tested and refuted, evidence inventory, plan status). It complements the formal report by showing **how** the conclusions were reached, not just the conclusions themselves.

**Detection ruleset:** `detection/lab.rules` contains the 7 Suricata rules with full per-keyword justification in inline comments. `detection/README.md` documents the deploy-and-replay validation workflow used to confirm each rule fires on the captured incident.

## Methodology

The engagement follows three industry-standard frameworks layered together.

### NIST SP 800-61r2: Computer Security Incident Handling Guide

NIST's 4-phase model (Preparation, Detection & Analysis, Containment / Eradication / Recovery, Post-Incident Activity) provides the high-level structure. In this engagement, **Phase 1 of the deliverable maps to NIST "Detection & Analysis"** (PCAP forensics, SIEM correlation, attacker timeline reconstruction). **Phase 2 maps to NIST "Lessons Learned"** translated into preventive controls (the 7 Suricata rules and the prioritized recommendation list in report section 7).

### SANS PICERL: tactical investigation flow

PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) is the SANS Incident Response Process. Applied in this engagement:

| PICERL phase | This engagement |
|---|---|
| **Preparation** | Coach-validated lab environment, signed-off evidence package, defined scope (forensic + detection eng), 4-day timebox |
| **Identification** | PCAP triage + Wazuh event correlation + hypothesis-driven analysis (7 hypotheses, 1 refuted, 5 confirmed, 1 inconclusive) |
| **Containment / Eradication / Recovery** | Documented as P0 recommendations (host quarantine, vsftpd removal, Caldera implant cleanup) but not executed (out of scope: forensic analysis only, not active response) |
| **Lessons Learned** | Phase 2 detection engineering: 7 Suricata rules + tuning notes + false-positive analysis (report section 8) |

### MITRE ATT&CK: technique mapping

Every finding is mapped to one or more MITRE ATT&CK techniques to allow the client to correlate this incident with their existing threat model. **14 distinct techniques** are referenced across the 10 findings:

- **Reconnaissance:** T1595.002, T1592.002, T1589
- **Initial Access:** T1190 (Exploit Public-Facing Application via CVE-2011-2523)
- **Execution:** T1059.004 (Unix Shell)
- **Discovery:** T1033, T1082, T1087.001, T1083, T1016, T1049, T1046
- **Credential Access:** T1110 (Brute Force)
- **Command and Control:** T1071.001, T1102 (Caldera Sandcat beacon)
- **Privilege Escalation:** T1078.003, T1548.003 (suspected sudo activity)

The complete technique table per finding is in [report section 4 (IOCs)](reports/INC-2026-001_Findings_Report.md) and the per-finding deep dives in sections 3 and 5.

### Reproducibility

Every claim in the report is traceable to an artefact in the evidence package, with the exact `tshark` filter, Wazuh query, or Suricata replay command needed to reproduce it. See **Annex A (Reproducibility commands)** in the report and the **[Reproducibility](#reproducibility) section below** for a quick-start.

## Tools used

**Network forensics**

- [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html): CLI Wireshark for PCAP triage, TCP stream reconstruction (`-z follow,tcp,ascii`), protocol filtering, and field extraction
- [`tcpreplay`](https://tcpreplay.appneta.com/) and `tcprewrite`: PCAP replay onto a live monitoring interface for Suricata rule validation, with MTU adjustment to fit lab `ens19` (1450 bytes)
- Base64 decoders: reconstruct Caldera Sandcat C2 payloads (beacon body and operator response)

**Network IDS / detection engineering**

- [Suricata 6.0.4](https://suricata.io/) (`afpacket` mode, single-thread, Hyperscan disabled in lab): authored, validated and tuned the 7 rules in this deliverable
- `suricata -T`: config and rule validation during deployment and tuning
- `kill -USR2 $(pgrep suricata)`: live rule reload during iterative tuning

**SIEM and host telemetry**

- [Wazuh](https://wazuh.com/) (manager + dashboard): event correlation, severity distribution analysis, rule lookup (`rule.id 11452`, `5551`, etc.), CSV export of 397 events
- Standard Linux text utilities (`grep`, `awk`, `jq`): log mining and JSON parsing

**Adversary emulation context** (referenced, not operated)

- [MITRE Caldera](https://caldera.mitre.org/) (Sandcat agent): present on the target host as the simulated pre-existing C2 implant being characterized

**Reference frameworks**

- [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final): Computer Security Incident Handling Guide
- [SANS PICERL](https://www.sans.org/blog/incident-handlers-handbook/): tactical investigation flow
- [MITRE ATT&CK](https://attack.mitre.org/): technique attribution
- [CVE-2011-2523 advisory](https://nvd.nist.gov/vuln/detail/CVE-2011-2523): vsftpd 2.3.4 backdoor reference

## Findings summary

The 10 findings (`I1` to `I10`) are documented in detail in the [findings report](reports/INC-2026-001_Findings_Report.md). Each entry includes evidence, reproducibility commands, MITRE ATT&CK mapping, and remediation guidance.

| ID | Severity | Title | Primary MITRE technique |
|---|---|---|---|
| **I1** | 🔴 CRITICAL | vsftpd 2.3.4 vulnerable service exposed on the internal network | T1190 |
| **I2** | 🟡 MEDIUM | Extended low-and-slow reconnaissance phase preceding the exploit | T1595.002, T1589 |
| **I3** | 🟠 HIGH | CVE-2011-2523 exploitation via `USER` smiley backdoor trigger | T1190 |
| **I4** | 🔴 CRITICAL | Unauthenticated root bind shell on TCP/6200, 8 enumeration commands executed | T1059.004, T1082 |
| **I5** | 🔴 CRITICAL | Pre-existing MITRE Caldera Sandcat C2 implant (independent of the FTP attack) | T1071.001, T1102 |
| **I6** | 🟢 LOW | Multi-protocol service enumeration (HTTP, SSH, SMTP, Telnet, MySQL) | T1046 |
| **I7** | 🟡 MEDIUM | SSH brute-force attempts visible in Wazuh, outside the PCAP capture window | T1110 |
| **I8** | 🟠 HIGH | Anomalous sudo activity including 2 first-time-sudo events | T1548.003 |
| **I9** | 🟠 HIGH | Insufficient Wazuh SIEM detection coverage for this attack class | (defensive gap) |
| **I10** | 🟢 LOW | Host audit logs do not cover the incident window | (evidence gap) |

**Severity distribution:** 3 CRITICAL / 3 HIGH / 2 MEDIUM / 2 LOW

**Reading order recommendation:** start with I1 (the vulnerable service), then I3 then I4 (the actual exploitation chain), then I5 (the parallel, unrelated C2 implant). I2 and I6 give the reconnaissance context. I7 to I10 are the defensive-posture findings (what monitoring saw vs missed).

## Detection engineering

Phase 2 of the engagement produced 7 Suricata rules (SID `9000001` to `9000007`) covering the captured incident across three angles: **the exploit signature**, **the post-exploit shell**, and **the parallel C2 channel**. Each rule is validated by offline PCAP replay against a Suricata 6.0.4 instance on the SOC workstation.

### The 7 rules

| SID | Detection target | Layer | MITRE technique | Fired in replay |
|---|---|---|---|---|
| **9000001** | vsftpd 2.3.4 backdoor trigger: `USER` argument ending with `:)` | TCP/21 payload | T1190 | ✅ 1/1 |
| **9000002** | vsftpd 2.3.4 vulnerable banner advertised (`220 (vsFTPd 2.3.4)`) | TCP/21 payload | T1190 | ✅ 30 (banner repeated on every FTP session) |
| **9000003** | Inbound TCP connection to backdoor port 6200 (SYN-only) | TCP/6200 | T1059.004 | ✅ 1/1 (bind shell connection) |
| **9000004** | MITRE Caldera Sandcat agent beacon (`POST /beacon` + UA `Go-http-client/1.1`) | TCP+content (port-agnostic) | T1071.001, T1102 | ✅ 1 (throttled to 1 per source per 60s) |
| **9000005** | Caldera C2 server response (HTTP `Server: Python/3.10 aiohttp/3.13.4`) | TCP+content (port-agnostic) | T1071.001 | ✅ 1 (throttled to 1 per source per 300s) |
| **9000006** | HTTP admin-path enumeration from curl/Wget (`/admin`, `/login`, `/phpmyadmin`) | TCP/80 payload | T1595.002, T1592.002 | ✅ 3 |
| **9000007** | Slow-paced FTP `USER` enumeration (5+ attempts in 30 min from same source) | TCP/21 + threshold | T1589, T1078.003 | ✅ 3 |

### Validation summary

| Metric | Value |
|---|---|
| Rules authored | **7** |
| Rules that fired correctly in PCAP replay | **7/7** ✅ |
| Alerts in `fast.log` (deduplicated, SOC view) | **40** |
| Records in `eve.json` (raw, pre-throttle) | **314** |
| Suricata version | 6.0.4 (afpacket, single-thread) |
| Replay command | `tcpreplay --intf1=ens19 --topspeed attack_mtu.pcap` |
| CI validation | [`markdownlint`, typography, and `suricata -T` rule check](.github/workflows/ci.yml) on every push |

The 40-vs-314 spread reflects deliberate throttling on rules 9000003, 9000004, 9000005, 9000006 to give SOC analysts a clean operational view while preserving the raw alert stream in `eve.json` for forensic deep-dives.

### Notable design decisions

Four iterative fixes during deployment are documented in [`detection/README.md`](detection/README.md). Key lessons:

1. **Port-agnostic HTTP detection.** Rules 9000004 and 9000005 (Caldera) were initially written with `alert http` and `http.uri` keywords, which only engage Suricata's HTTP parser on port 80. Caldera C2 runs on port 8888, so the parser was bypassed and the rules never fired. Fix: rewrite in TCP+content mode (`alert tcp ... content:"POST /beacon"; content:"Go-http-client/1.1";`) which matches raw HTTP bytes regardless of port.
2. **`flow:established` unreliable during PCAP replay.** A captured TCP handshake outside the replay window leaves the flow state machine in an indeterminate state. Removing `flow:established` from the Caldera rules makes them match in both live and replay modes.
3. **Explicit flow direction for SYN-only rules.** Rule 9000003 (port 6200) raised `SC_WARN_POOR_RULE: SYN-only ... w/o direction specified`. Fixed by adding `flow:to_server,not_established`.
4. **`HOME_NET` vs `EXTERNAL_NET` in RFC1918-only labs.** When attacker, target, and C2 all live in private space, `EXTERNAL_NET = !$HOME_NET` becomes empty and rules of the form `$EXTERNAL_NET any -> $HOME_NET 21` never match. Lab fix: use `any` in both. Production fix: narrow `HOME_NET` to the protected segment only.

### False-positive considerations

Per-rule false-positive analysis is documented in [report section 8.5](reports/INC-2026-001_Findings_Report.md). Most rules carry negligible risk in a well-scoped environment; rules 9000005 (aiohttp Server header) and 9000006 (curl/Wget on admin paths) require tuning if benign internal Python services or administrative scripting are present.

## Repository layout

```text
NexaCorp-DFIR-INC-2026-001/
├── README.md                                   (this file)
├── LICENSE                                     (MIT)
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml                              markdownlint + typography + Suricata rule check
├── reports/
│   ├── INC-2026-001_Findings_Report.pdf       canonical 54-page deliverable
│   └── INC-2026-001_Findings_Report.md        same content, Markdown source
├── detection/
│   ├── lab.rules                               7 Suricata rules (SID 9000001-9000007)
│   └── README.md                               deploy + replay validation workflow
├── evidence-summary/
│   └── ioc-summary.md                          indicators of compromise (SIEM-ingestible)
├── methodology/
│   ├── attack-timeline.md                      incident timeline (UTC)
│   └── attck-mapping.md                        MITRE ATT&CK mapping table
└── notes/
    └── journal.md                              analyst investigation journal (hypotheses, plan, IOCs, timeline)
```

**File classifications:**

| Path | Role | Audience |
|---|---|---|
| `reports/*.pdf` | Canonical deliverable, formal report | Client, recruiter, auditor |
| `reports/*.md` | Same content, grep-friendly source | Anyone citing or diffing |
| `detection/lab.rules` | Production-ready Suricata ruleset | SOC / detection engineer |
| `detection/README.md` | Deployment + replay validation guide | Detection engineer onboarding |
| `evidence-summary/ioc-summary.md` | Indicators of compromise, by category | SOC / threat hunting |
| `methodology/attack-timeline.md` | Incident timeline (UTC) | DFIR practitioner |
| `methodology/attck-mapping.md` | MITRE ATT&CK mapping table | DFIR / detection engineer |
| `notes/journal.md` | Investigation working notebook | DFIR practitioner studying the method |
| `.github/workflows/ci.yml` | Automated markdownlint, typography, and Suricata rule validation (`suricata -T`, runs when `detection/*.rules` is present) on push | CI |

## Reproducibility

Every claim in the findings report is traceable to an artefact in the evidence package. The PCAP itself is not redistributed (BeCode lab property), but the commands and queries are documented so that anyone with their own copy can reproduce the analysis.

### Reproduce key findings (PCAP analysis)

Requires `tshark` (Wireshark CLI) and the original `attack.pcap`:

```bash
# 1. PCAP overview
tshark -r attack.pcap -q -z io,stat,0

# 2. TCP conversations (reveals attacker, target, C2)
tshark -r attack.pcap -q -z conv,tcp | head -30

# 3. Confirm vsftpd 2.3.4 banner exposure (Finding I1)
tshark -r attack.pcap -Y "ftp && ip.src == 192.168.10.10" \
  -T fields -e frame.time -e ftp.response.code -e ftp.response.arg | head -5

# 4. Find the CVE-2011-2523 exploit payload (Finding I3)
tshark -r attack.pcap -Y 'ftp.request.command == "USER"' \
  -T fields -e frame.time -e ftp.request.arg

# 5. Reconstruct the root shell session on TCP/6200 (Finding I4)
tshark -r attack.pcap -q -z follow,tcp,ascii,70

# 6. Reconstruct the Caldera C2 beacon (Finding I5)
tshark -r attack.pcap -q -z follow,tcp,ascii,6 | head -50
```

### Reproduce rule validation (Suricata replay)

Requires Suricata 6.0.x, `tcpreplay`, and a monitored interface (`ens19` in the lab; substitute your own):

```bash
# 1. Install the ruleset
sudo cp detection/lab.rules /etc/suricata/rules/learner/lab.rules

# 2. Hot-reload Suricata without restart
sudo kill -USR2 $(pgrep -f suricata)
sleep 5

# 3. Clear the alert log for a clean baseline
sudo truncate -s 0 /var/log/suricata/fast.log

# 4. Replay the PCAP at top speed
sudo tcpreplay --intf1=ens19 --topspeed attack_mtu.pcap

# 5. Count alerts per rule (expect 7 distinct SIDs)
sudo grep -oE '\[1:[0-9]+:' /var/log/suricata/fast.log | sort | uniq -c | sort -rn
```

Expected output (after one full replay):

```text
     30 [1:9000002:    (vsftpd banner repeated per session)
      3 [1:9000007:    (FTP USER enumeration threshold)
      3 [1:9000006:    (HTTP admin path enumeration)
      1 [1:9000005:    (Caldera C2 response)
      1 [1:9000004:    (Caldera Sandcat beacon, throttled)
      1 [1:9000003:    (Backdoor port 6200 SYN)
      1 [1:9000001:    (vsftpd USER smiley exploit)
```

**7/7 rules fire correctly.** The full evidence package (`fast.log`, `eve.json`, throttling config, Suricata version snapshot) is enumerated in **Annex E of the [findings report](reports/INC-2026-001_Findings_Report.md)**.

## Known limits

- **Evidence package starts mid-incident.** The PCAP begins at 2026-05-09 20:08 UTC, but the Caldera Sandcat agent is already actively beaconing in frame 1. The initial compromise that installed the implant occurred earlier and is not represented in the data. Conclusions about pre-implant activity are extrapolated from Wazuh `full_log` fields, not directly observed.
- **Host audit logs do not overlap the attack window.** Local `auth.log` and `syslog` start ~5 hours after the PCAP ends, with the first entry being `syslogd restart` (likely VM reboot). No rotated log files were provided. This is documented as Finding I10.
- **Scope was forensic + detection engineering, not live response.** Containment, eradication, forensic acquisition (memory image, disk image), and persistence enumeration are documented as **P0 recommendations** in the report, but were not executed: the engagement did not have live host access. A follow-up engagement would be required to close those loops.
- **The 7 Suricata rules detect this specific incident signature.** A sophisticated attacker can evade them by changing the exploit byte pattern (alternative null-byte terminators on the `USER` argument), recompiling Caldera with a different User-Agent, or moving the C2 to encrypted HTTPS (TLS metadata analysis like JA3/JA4 would be the fallback). The rules are appropriate for the captured threat scenario; longer-term detection strategy should add behavioral and metadata-based detections.
- **Wazuh ingestion gap during the investigation.** The SIEM log ingestion pipeline was temporarily unavailable until 2026-05-11 11:39 UTC (mid-investigation, restored by the lab coach). The 4 high-severity alerts therefore appear in the dashboard with **ingestion timestamps** (May 11 13:17-13:28) rather than the actual incident timestamps (May 9 21:00-22:53), which distorts the apparent timing of correlation events.
- **`HOME_NET` was set to `any` for the lab.** In a real NexaCorp deployment, `HOME_NET` must be narrowed to the protected segment only (e.g. `192.168.10.0/24`) so that `EXTERNAL_NET = !$HOME_NET` correctly covers the attacker space. The rules as delivered are lab-tuned and need this single config change before production use.
- **4-day timebox: 2 followups remain.** Pulling `full_log` for all 80 sudo events to identify which user accounts triggered them (and timestamps relative to the FTP exploit), and reviewing the 12 SSH authentication successes to distinguish legitimate admin sessions from attacker-controlled ones. Both are documented in the report's "Open Questions" annex.

## NexaCorp DFIR series

- **INC-2026-001**: this repository
- [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002): privilege escalation and persistence (Tor SSH, SUID, backdoor account)
- [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003): month-1 cross-incident assessment
- [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004): SQL injection (web portal)
- [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005): OS command injection and web shell (web portal)
- [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006): stored XSS and session hijacking (web portal)
- [INC-2026-007](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-007): IDOR and broken access control (NexaPortal); Month 2 capstone

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design, mid-investigation Wazuh ingestion fix, publication authorization for portfolio use.
- **MITRE** for the Caldera framework that powered the simulated C2 implant, and for the ATT&CK knowledge base used to map every finding.
- **Suricata project** for the engine that made the 7 rules deployable in under 30 minutes.

## About

Solo DFIR engagement delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 01, on 2026-05-15.

Author: **[Johan-Emmanuel Hatchi](https://github.com/Jhatchi)** ([LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)).

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC / DFIR / detection engineering roles where this kind of end-to-end investigation work (PCAP forensics, SIEM correlation, IDS rule writing, formal client reporting) is in scope.

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The Suricata rules in `detection/lab.rules` and the report text are both released under the same MIT license: free to copy, adapt, and redeploy with attribution. The PCAP, lab infrastructure, and engagement briefings remain BeCode Brussels property and are not redistributed.
