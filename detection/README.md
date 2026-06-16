# INC-2026-001 - Phase 2 Workflow Guide
## Suricata Rule Deployment, Testing, and Validation

---

This guide walks you through deploying the Suricata rules, replaying the
evidence PCAP, validating that the rules fire correctly, and capturing
the evidence for your Phase 2 report.

**Estimated time:** 30-60 minutes including troubleshooting.

---

## Prerequisites

Before starting, confirm the following are in place on your SOC workstation:

```bash
# 1. Suricata is running with exactly one process
pgrep -af suricata
# Should show one line - note the PID

# 2. The rules file location is correct
ls -la /etc/suricata/rules/learner/lab.rules
# Should exist (was empty when this engagement started)

# 3. Suricata config includes the rules file
sudo grep -E "rule-files|learner" /etc/suricata/suricata.yaml
# Should show:
#   rule-files:
#     - learner/lab.rules

# 4. The evidence PCAP is in place
ls -lh ~/inc-2026-001/pcap/attack.pcap
# Should be ~943 KB

# 5. The MTU-trimmed PCAP location
ls /tmp/attack_mtu.pcap 2>/dev/null || echo "Need to generate with tcprewrite"
```

If any check fails, stop and fix the prerequisite before continuing.

---

## Step 1 - Deploy the rules

The `lab.rules` file is delivered alongside this guide. Copy it into place:

```bash
# Backup current empty rules (just in case)
sudo cp /etc/suricata/rules/learner/lab.rules /etc/suricata/rules/learner/lab.rules.empty.bak

# Deploy the new rules
sudo cp ~/inc-2026-001/notes/lab.rules /etc/suricata/rules/learner/lab.rules

# Verify
sudo wc -l /etc/suricata/rules/learner/lab.rules
# Should be around 200 lines (includes comments)

# Sanity-check syntax - Suricata can validate offline
sudo suricata -T -c /etc/suricata/suricata.yaml
# Should end with: "Suricata configuration was successfully loaded."
# If errors appear, fix them before reloading
```

---

## Step 2 - Reload Suricata to apply rules

Suricata supports hot-reload via SIGUSR2 - **no restart needed**:

```bash
# Signal Suricata to reload rules
sudo kill -USR2 $(pgrep -f suricata)

# Wait for reload to complete
sleep 3

# Verify rules are loaded
sudo tail -30 /var/log/suricata/suricata.log | grep -i "signatures\|reload"
# Should show a recent line: "X signatures processed. Y are IP-only rules..."
# Expected: 7 signatures (rules 9000001-9000007)
```

If the log still says "0 signatures processed", the SIGUSR2 didn't take.
Try restarting Suricata fully:

```bash
sudo pkill -9 -f suricata
sleep 3
sudo rm -f /var/run/suricata.pid /var/run/suricata-command.socket
sudo suricata -c /etc/suricata/suricata.yaml -i ens19 -D
sleep 5
sudo tail -30 /var/log/suricata/suricata.log
```

---

## Step 3 - Prepare the PCAP for replay (MTU trimming)

The lab interface `ens19` has MTU 1450 (smaller than typical Ethernet 1500).
Replaying packets larger than the MTU will fail. We use `tcprewrite` to trim:

```bash
sudo tcprewrite \
  --mtu=1400 \
  --mtu-trunc \
  --infile=$HOME/inc-2026-001/pcap/attack.pcap \
  --outfile=/tmp/attack_mtu.pcap

# Verify
ls -lh /tmp/attack_mtu.pcap
# Should be roughly the same size as the original (~943K)
```

---

## Step 4 - Clear previous alerts and replay

```bash
# Empty fast.log so we see ONLY alerts from this replay
sudo truncate -s 0 /var/log/suricata/fast.log

# Replay the PCAP onto ens19 at top speed
sudo tcpreplay --intf1=ens19 --topspeed /tmp/attack_mtu.pcap

# Expected output: "Actual: 5194 packets (881759 bytes) sent in X.XX seconds."
```

The replay completes in under a second. Suricata processes packets in
real-time but may need a moment to flush alerts to disk.

---

## Step 5 - Check fast.log for alerts

```bash
# Wait briefly for alerts to flush
sleep 2

# View all alerts produced
sudo cat /var/log/suricata/fast.log

# Or in real-time
sudo tail -f /var/log/suricata/fast.log
# (Ctrl-C to exit)
```

### Expected alerts (and approximately how many of each)

| SID | Rule | Expected count | Reason |
|---|---|---|---|
| 9000001 | vsftpd 2.3.4 USER smiley | **1** | Single exploit event at 22:53:31 |
| 9000002 | vsftpd 2.3.4 banner | ~14 | Once per FTP connection (every recon attempt + the exploit) |
| 9000003 | Inbound port 6200 | **1** | Single bind shell connection at 22:53:35 |
| 9000004 | Caldera beacon (request) | Many (~150-200) | Every ~40-50s for 5h30 |
| 9000005 | Caldera server response | Throttled (~70) | Throttle to 1/5min per src - depends on throttle calculation |
| 9000006 | HTTP admin path enum | 3-6 | Each of /admin, /phpmyadmin, /login from curl/Wget |
| 9000007 | FTP user enum threshold | 1+ | Fires when 5+ USER commands seen in 30min |

### What to capture for the Phase 2 report

```bash
# Count alerts per rule SID
sudo grep -oE "\[1:9000[0-9]+:" /var/log/suricata/fast.log | sort | uniq -c | sort -rn

# Save fast.log for evidence
cp /var/log/suricata/fast.log ~/inc-2026-001/notes/fast.log.phase2_replay

# Pretty timestamps + screenshot opportunity:
sudo head -50 /var/log/suricata/fast.log
```

---

## Step 6 - Troubleshooting

### If a rule does NOT fire when expected

**Check 1 - Is the rule actually loaded?**
```bash
sudo grep "9000001" /etc/suricata/rules/learner/lab.rules
# Should match
sudo tail -30 /var/log/suricata/suricata.log | grep "signatures processed"
# Should show 7 signatures
```

**Check 2 - Is the traffic actually reaching Suricata?**
```bash
# Check Suricata's packet stats
sudo cat /var/log/suricata/stats.log | tail -50 | grep -E "decoder.pkts|alert"
# Should show non-zero packet counts after the replay
```

**Check 3 - Is the rule syntactically correct?**
```bash
# Run Suricata in test mode to see parser errors
sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep -E "ERROR|WARN"
```

**Check 4 - Replay didn't reach Suricata?**
```bash
# Sniff ens19 during replay to confirm packets are visible
# Terminal 1:
sudo tcpdump -i ens19 -c 20 port 21
# Terminal 2:
sudo tcpreplay --intf1=ens19 --topspeed /tmp/attack_mtu.pcap
# Should see FTP packets in Terminal 1
```

### If a rule fires WAY too much (FP)

Tighten the rule. Common adjustments:
- Add `depth:N` to limit content match position
- Add `pcre:` for stricter pattern matching
- Add `flow:established,to_server` to restrict direction
- Add `threshold:type limit, track by_src, count 1, seconds 60` to rate-limit

### If Suricata crashes or doesn't start after rule changes

```bash
# Restore the empty rules file
sudo cp /etc/suricata/rules/learner/lab.rules.empty.bak /etc/suricata/rules/learner/lab.rules

# Restart Suricata
sudo pkill -9 -f suricata
sleep 3
sudo rm -f /var/run/suricata.pid /var/run/suricata-command.socket
sudo suricata -c /etc/suricata/suricata.yaml -i ens19 -D

# Re-add rules one by one to identify the broken one
```

---

## Step 7 - Iterate on false positives

After the first replay, check whether any rule fired on legitimate-looking
traffic (other than the attack patterns we want to catch):

```bash
# Inspect all alerts in eve.json (JSON format, more detail)
sudo cat /var/log/suricata/eve.json \
  | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        ev = json.loads(line)
        if ev.get('event_type') == 'alert':
            print(f\"{ev['timestamp'][:19]}  {ev['alert']['signature_id']}  {ev['src_ip']}:{ev.get('src_port','-')} -> {ev['dest_ip']}:{ev.get('dest_port','-')}  {ev['alert']['signature']}\")
    except: pass
" | head -50
```

If any alert seems suspicious or off-topic, document it in your Phase 2 report
as a known false positive and propose a tuning step.

---

## Step 8 - Capture evidence for the report

```bash
# Create an evidence directory for Phase 2
mkdir -p ~/inc-2026-001/reports/phase2_evidence

# Copy fast.log
sudo cp /var/log/suricata/fast.log ~/inc-2026-001/reports/phase2_evidence/fast.log

# Copy the relevant eve.json subset (alerts only)
sudo bash -c 'cat /var/log/suricata/eve.json | grep "\"event_type\":\"alert\""' \
  > ~/inc-2026-001/reports/phase2_evidence/eve.alerts.json

# Statistics summary
sudo grep -oE "\[1:9000[0-9]+:" /var/log/suricata/fast.log \
  | sort | uniq -c | sort -rn \
  > ~/inc-2026-001/reports/phase2_evidence/alert_count_by_sid.txt

# Take a screenshot of fast.log displayed in your terminal
# (use cmd+shift+4 on macOS or your distribution's screenshot tool)

# Fix permissions so you can read everything as your user
sudo chown -R blue11:blue11 ~/inc-2026-001/reports/phase2_evidence/
```

---

## Phase 2 report structure

When writing the Phase 2 report, include:

1. **The rules themselves** - paste `lab.rules` content with header comments preserved
2. **Per-rule justification** - short paragraph explaining the detection logic
3. **Test evidence** - `fast.log` content + counts per SID + screenshot
4. **False positive analysis** - anything that fired unexpectedly + how you handled it
5. **Rule limitations & evasion**:
   - Rule 9000001: bypassed if attacker sends `USER aaa:)bbb` (smiley not at end) - but vsftpd 2.3.4 still triggers because it scans for `:)` anywhere. Improve with pcre matching `:\)` anywhere.
   - Rule 9000003: bypassed if attacker uses a different bind port (vsftpd backdoor is hardcoded to 6200 but a custom backdoor might not be)
   - Rule 9000004: bypassed if attacker changes the User-Agent string (trivial) or URI (`/beacon` is the Caldera default but can be configured)
   - Rule 9000005: bypassed if Caldera is reconfigured to mask its Server header (Python aiohttp accepts custom headers)
   - Rule 9000006: bypassed by using a non-tooling User-Agent (e.g., a real browser UA)
   - Rule 9000007: bypassed by spacing attempts >30 min apart, or by using multiple source IPs
6. **Beyond detection - recommendations** (from your Phase 1 report, reuse + expand)

---

## Quick reference card

```bash
# Edit rules
sudo nano /etc/suricata/rules/learner/lab.rules

# Reload
sudo kill -USR2 $(pgrep -f suricata) && sleep 3

# Clear alerts
sudo truncate -s 0 /var/log/suricata/fast.log

# Replay
sudo tcpreplay --intf1=ens19 --topspeed /tmp/attack_mtu.pcap

# Check alerts
sudo tail -50 /var/log/suricata/fast.log

# Count per rule
sudo grep -oE "\[1:9000[0-9]+:" /var/log/suricata/fast.log | sort | uniq -c | sort -rn
```

---

*End of workflow guide.*
