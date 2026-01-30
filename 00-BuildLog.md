# Home Lab Build Log

## Inventory (Baseline)

- Switch: TP-Link TL-SG108E
- Switch IP: 192.0.2.X
- Port 1: Home Router (uplink)
- Port 2: Home Assistant Pi (Pi 4B 4GB)
- Port 3: Server Pi (Pi 4B 8GB)
- Home LAN: 192.0.2.X

---

## Change Log

### Change 001 - Capture Baseline Switch Info

**Date:** 12/30/2025 2:36PM  
**Objective:** Record current state before changes  
**Action:** Screenshot System Info page  
**Evidence:** evidence/screenshots/  
**Result:** Complete

---

### Change 002 - Enable 802.1Q VLAN

**Date:** 12/30/2025 7:27PM  
**Objective:** Turn on VLAN capability without changing current connectivity  
**Action:** Enable 802.1Q VLAN in switch UI (no port membership changes yet)  
**Evidence:** evidence/screenshots/  
**Result:** Complete

---

### Change 003 - Create VLANs 10/20/30/40

**Date:** 12/30/2025 7:36PM  
**Objective:** Create lab VLANs and prepare Port 3 for tagged VLAN traffic later  
**Action:** Add VLANs 10, 20, 30, 40 and set Port 3 as TAGGED member of each VLAN  

**VLAN Names:**
- VLAN 10 = LAB-MGMT
- VLAN 20 = LAB-SRV
- VLAN 30 = LAB-CLIENT
- VLAN 40 = LAB-IOT

**Evidence:** evidence/screenshots/  
**Result:** Complete

---

### Change 004 - Confirm PVIDs for Ports 1-3 Stay on VLAN 1

**Date:** 12/30/2025 8:00PM  
**Objective:** Keep Router, Home Assistant, and Server Pi uplink stable on home network while VLANs are staged. All ports PVID=1 (default) to keep VLAN 1 as native/untagged during staging.  
**Action:** Set/confirm PVID: Port1=1, Port2=1, Port3=1  
**Evidence:** evidence/screenshots/Change004-pvid-ports1-3.png  
**Result:** Complete

---

### Change 005 - Port 4 = VLAN 30 Access Port (LAB-CLIENT)

**Date:** 1/2/2026 1:48PM (Updated 1/4/2026 6:42PM)  
**Objective:** Make Port 4 a client test port in VLAN 30  
**Action:**
- VLAN 30: Port 4 UNTAGGED
- VLAN 1: Port 4 NOT MEMBER
- PVID Port 4 = 30
- Mac test client plugged into Port 4; received APIPA (169.x) before DHCP service configured

**Evidence:** evidence/screenshots/Change005-vlan30-port4.png  
**Result:** Complete

---

### Change 006 - Install Ubuntu Server 64-bit on Server Pi (Router)

**Date:** 1/4/2026 6:43PM  
**Objective:** Build lab router host (router-on-a-stick) on Server Pi  
**Decision:** Upstream (home LAN) uses DHCP initially to avoid IP conflicts; switch to static later  
**Evidence:** None available  
**Result:** Complete

---

### Change 007 - Server Pi Baseline (Updates + Verify Upstream Networking)

**Date:** 1/5/2026 8:08PM  
**Objective:** Bring OS up to date and confirm upstream connectivity on VLAN 1  
**Action:** apt update/upgrade; verify IP, route, DNS, internet reachability  
**Validation:** `ip -br a`, `ip r`, ping 1.1.1.1, DNS lookup works  
**Evidence:** evidence/screenshots/Change007-baseline.png  
**Result:** Complete

---

### Change 008 - Configure VLAN Interfaces on Server Pi (Netplan)

**Date:** 1/5/2026 9:07PM  
**Objective:** Create router-on-a-stick VLAN interfaces: eth0.10/20/30/40  
**Validation:** `ip -br a` shows eth0.10=10.0.10.1, eth0.20=10.0.20.1, eth0.30=10.0.30.1, eth0.40=10.0.40.1  
**Result:** Complete

---

### Change 009 - Enable IP Forwarding (Routing)

**Date:** 1/5/2026 9:14PM  
**Objective:** Allow Pi to route between VLANs and upstream  
**Validation:** net.ipv4.ip_forward = 1  
**Evidence:** evidence/screenshots/Change009-ip-forwarding.png  
**Result:** Complete

---

### Change 010 - Firewall + NAT (nftables)

**Date:** 1/5/2026 10:09PM  
**What:** Configured nftables firewall with NAT masquerading  

**Why:**
- Enable VLANs to reach internet via NAT
- Segment VLANs (only MGMT can reach other VLANs)
- Secure Pi management (only SSH from MGMT/upstream)

**Config:** `/etc/nftables.conf`  
**Verification:** `ping 8.8.8.8` from Pi successful  
**Evidence:** \HomeLab\evidence\screenshots  
**Result:** Complete

---

### Change 011 - Validation Test

**Date:** 1/6/2026 12:06PM  
**Tests Performed from MacBook (10.0.30.116 on VLAN 30):**
- Ping gateway 10.0.30.1, 10.0.20.1, 10.0.40.1, and 10.0.10.1: Success
- Ping internet 8.8.8.8: Success  
- DNS resolution (google.com): Success
- Ping other VLAN gateways (10.0.10.1): Success (expected—Pi allows ICMP to itself)

**Note:** Full inter-VLAN segmentation test requires devices on multiple VLANs  
**Result:** DHCP, routing, NAT, DNS all functional  
**Evidence:** \HomeLab\evidence\screenshots  
**Result:** Complete

---

### Change 012 - DHCP + DNS for VLANs (dnsmasq)

**Date:** 1/6/2026  
**What:** Installed and configured dnsmasq as DHCP/DNS server  
**Config:** `/etc/dnsmasq.conf`  

**DHCP Ranges:**
- VLAN 10 (MGMT): 10.0.10.100-200
- VLAN 20 (SRV): 10.0.20.100-200
- VLAN 30 (CLIENT): 10.0.30.100-200
- VLAN 40 (IOT): 10.0.40.100-200

**DNS:** Forwarding to 8.8.8.8 / 8.8.4.4  
**Verification:** MacBook on Port 4 received 10.0.30.116  
**Result:** DHCP working, devices can get IPs on all VLANs  
**Evidence:** \HomeLab\evidence\screenshots  
**Result:** Complete

---

### Change 019 - Configuration Backups

**Date:** 1/6/2026 9:06PM  
**What:** Created backup copies of critical config files before making changes  

**Files Backed Up:**
- `/etc/nftables.conf` → `/etc/nftables.conf.backup`
- `/etc/dnsmasq.conf` → `/etc/dnsmasq.conf.backup`
- `/etc/netplan/01-lab-router.yaml` → `/etc/netplan/01-lab-router.yaml.backup`

**Why:** Safety measure before Phase 1 changes (moving HA to VLAN 40)  
**Restore Command (if needed):** `sudo cp [file].backup [file]`  
**Evidence:** \HomeLab\evidence\screenshots  
**Result:** Complete

---

### Change 020 - Install Docker

**Date:** 1/6/2026 9:06PM  
**What:** Installed Docker Engine on Server Pi  
**Version:** Docker 29.1.3  
**Why:** Foundation for running containerized services (monitoring, logging, etc.)  
**Verification:** `docker --version` and `docker ps` successful  
**User Permissions:** Added 'admin' user to docker group (no sudo required)  
**Evidence:** \HomeLab\evidence\screenshots  
**Result:** Complete

---

### Change 021 - Deploy Uptime Kuma Monitoring

**Date:** 1/6/2026 9:54PM  
**What:** Deployed Uptime Kuma monitoring dashboard in Docker container  
**Container:** louislam/uptime-kuma:1  
**Access:** http://192.0.2.Xx:3001  
**Firewall Rule Added:** Allow TCP port 3001 from upstream + MGMT VLAN  

**Monitors Configured:**
- VLAN 30 Gateway (10.0.30.1) - Ping
- Internet Connectivity (8.8.8.8) - Ping  
- DNS Resolution (google.com) - HTTP check
- SSH Service on Pi (127.0.0.1:22) - TCP Port
- DNS Service (127.0.0.1:53) - DNS query
- Home Assistant (192.0.2.X211:8123) - HTTP

**Troubleshooting:** Initial deployment used bridge network (isolated), causing 100% packet loss. Redeployed with --network host to access Pi's network stack directly.  
**Evidence:** \HomeLab\evidence\screenshots  
**Result:** All monitors showing UP status, baseline monitoring established  
**Result:** Complete

---

### Change 022 - Set Up Prometheus + Grafana

**Date:** 1/7/2026 1:52PM  
**What:** Deployed full metrics collection and visualization stack using Docker containers

**Components Deployed:**

1. **Node Exporter** (prom/node-exporter:latest)
   - Port: 9100
   - Purpose: Exposes Pi system metrics (CPU, memory, disk, network)
   - Network: Host mode (required for VLAN interface visibility)

2. **Prometheus** (prom/prometheus:latest)
   - Port: 9090
   - Purpose: Scrapes and stores time-series metrics
   - Config: `/home/admin/prometheus/prometheus.yml`
   - Scrape interval: 15 seconds
   - Retention: 15 days (default)

3. **Grafana** (grafana/grafana:latest)
   - Port: 3000
   - Purpose: Visualizes metrics in dashboards
   - Data source: Prometheus (http://localhost:9090)
   - Dashboard: "Node Exporter Full" (ID: 1860)

**Firewall Rules Added:**
```
# Prometheus web UI
iif "eth0" ip saddr $UPSTREAM tcp dport 9090 accept
iif "eth0.10" ip saddr $VLAN_MGMT tcp dport 9090 accept

# Grafana web UI
iif "eth0" ip saddr $UPSTREAM tcp dport 3000 accept
iif "eth0.10" ip saddr $VLAN_MGMT tcp dport 3000 accept
```

**Metrics Visible:**
- **System:** CPU usage per core, load average (1/5/15 min), uptime
- **Memory:** Used/available/cached, swap usage
- **Disk:** I/O rates (read/write), filesystem usage by mount point
- **Network:** Bytes received/transmitted per interface:
  - eth0 (upstream 192.0.2.x)
  - eth0.10 (MGMT VLAN 10.0.10.x)
  - eth0.20 (SRV VLAN 10.0.20.x)
  - eth0.30 (CLIENT VLAN 10.0.30.x)
  - eth0.40 (IoT VLAN 10.0.40.x)

**Troubleshooting Performed:**
1. Docker network creation failed (iptables conflict with nftables) - Solution: Used --network host for all containers
2. Grafana dashboard showed "No data" - Solution: Verified Prometheus data source URL, adjusted time range to "Last 15 minutes"
3. VLAN interfaces not visible in Node Exporter metrics - Solution: Redeployed with --network host

**Validation Tests:**
- Prometheus targets showing UP (node-exporter + prometheus)
- Grafana successfully queried Prometheus API
- Dashboard panels populated with live data
- Network traffic test: 100 pings from MacBook (VLAN 30) showed spike on eth0.30 graph
- All 4 VLAN interfaces visible in Network Traffic Basic panel

**Key Achievement:** Successfully visualized per-VLAN network traffic in real-time. Can monitor bandwidth usage on each isolated network segment independently.

**Documentation Created:**
- Full deployment guide: `04-Troubleshooting/prometheus-grafana-deployment-guide.md`
- Architecture diagram: `04-Troubleshooting/monitoring-architecture.md`
- Quick reference: `04-Troubleshooting/monitoring-quick-reference.md`

**My Understanding:**  
Uptime Kuma monitors service availability—whether things are reachable (ping, HTTP, TCP checks). Prometheus collects performance metrics like CPU usage, memory, disk I/O, and network bandwidth per interface. Grafana visualizes those metrics in dashboards. Together: Uptime Kuma tells you if something is broken, Prometheus/Grafana tell you why or how badly.

**Access URLs:**
- Uptime Kuma: http://192.0.2.Xx:3001
- Prometheus: http://192.0.2.Xx:9090
- Grafana: http://192.0.2.Xx:3000

**Evidence:**
- `03-Evidence/step21-grafana-dashboard-working.png`
- `03-Evidence/step21-vlan-network-traffic.png`
- `03-Evidence/step21-prometheus-targets.png`

**Result:** Complete operational monitoring capability established

---

### Change 023 - Intentional Break + Troubleshoot (Complete)

**Date:** 1/8/2026 - 1/9/2026  

**Incidents Completed:**

**Incident 001: dnsmasq Failure (Two-Phase Test)**
- Duration: 40 minutes total (24 min initial test + 16 min controlled test)
- Key Learning: Troubleshooting actions (unplugging cable) can worsen outages
- Discovered that routing and DNS are separate layers
- Documented full incident report with diagnostic commands

**Incident 002: Uptime Kuma Failure**
- Start: 09:09:12 CST
- Resolution: ~09:11:00 CST
- Duration: Approximately 1-2 minutes
- Key Learning: Monitoring failure doesn't equal service failure
- Container stopped gracefully (exit code 0), all data saved properly
- Practiced Docker container troubleshooting vs systemd services

**Skills Demonstrated:**
- Incident response procedures
- Systematic diagnostic methodology
- Docker container management
- Differentiating between service types (core vs monitoring)
- Writing professional incident reports

**Evidence:**
- `04-Troubleshooting/incident-001-dnsmasq-failure.md`
- `04-Troubleshooting/incident-002-uptime-kuma-failure.md`
- Screenshots in `03-Evidence/step22-*`

**Result:** Complete

---

### Change 024 - Create Runbooks

**Date:** 1/9/2026  
**What:** Created step-by-step troubleshooting guides for common problems

**Runbooks Created:**
1. dnsmasq Service Failure - DHCP/DNS troubleshooting procedures
2. Docker Container Issues - Container lifecycle and common failures
3. Network Connectivity Problems - Layer-by-layer diagnostic process

**Format:** Each runbook includes symptoms, diagnostics, resolution steps, verification, and prevention strategies

**Purpose:** Enable quick problem resolution without having to remember every detail or search through incident reports

**Location:** `04-Troubleshooting/runbooks/`

**Skills Demonstrated:**
- Technical writing
- Process documentation
- Systematic troubleshooting methodology
- Knowledge transfer

**Result:** Complete

---

### Change 025 - Automated Backups + Restore Test

**Date:** 1/9/2026  
**What:** Created automated backup system for critical configuration files

**Why I Did This:**  
If I mess up a config file or something breaks, I need a way to restore everything back to a working state without rebuilding from scratch. Backups are useless if you never test them, so I also tested the restore process to make sure it actually works.

**What I Created:**

**Backup Script** (`backup-configs.sh`):
- Backs up firewall rules, DNS/DHCP config, network settings, and monitoring config
- Creates a timestamped folder so I can see when each backup was made
- Automatically deletes old backups (keeps the last 5 to save space)
- Creates a manifest file that lists what's in each backup

**Restore Script** (`restore-configs.sh`):
- Shows me a list of available backups to choose from
- Asks me to confirm before overwriting anything
- Restores all the config files
- Optionally reloads all the services automatically so changes take effect

**Automated Schedule:**  
Set up a cron job to run backups automatically every day at 2:00 AM. This means I don't have to remember to do it manually.

**How I Tested It:**
1. Ran the backup script to create a backup
2. Added a test comment to the firewall config file
3. Ran the restore script and selected the backup
4. Verified the test comment was gone (file was restored to original state)
5. All services (firewall, DNS, network) reloaded successfully

**What I Learned:**

Testing the restore is just as important as creating backups. I could have been backing up for months and not realized the restore didn't work until I actually needed it in an emergency. Now I know the process works and I can recover from mistakes quickly.

I also learned about cron jobs for scheduling automated tasks. The backup runs every night at 2 AM without me having to do anything.

**Where Everything Is Saved:**
- Backup script: `/home/admin/backup-configs.sh`
- Restore script: `/home/admin/restore-configs.sh`
- Backups folder: `/home/admin/config-backups/[timestamp]/`
- Backup log: `/home/admin/backup.log`
- Cron schedule: `crontab -l` to view

**Skills I Used:**
- Writing bash scripts
- Testing backup and restore procedures
- Setting up cron jobs for automation
- Disaster recovery planning

**Result:** Backup system is working and tested. I can recover from config mistakes in under 5 minutes.

---

### Change 026 - Configure Admin PC Management Access + Test Segmentation

**Date:** 1/11/2026 and 1/12/2026
**What:** Added firewall rules to allow admin PC (on WiFi) to manage lab infrastructure

**PC Details:**
- IP Address: 192.0.2.XXXX (WiFi, home network)
- Temporary setup until structured cabling is installed

**Firewall Rules Added:**
- SSH access to Pi (port 22)
- Uptime Kuma access (port 3001)
- Prometheus access (port 9090)
- Grafana access (port 3000)
- ICMP (ping) for diagnostics

**Why Temporary:**
PC is currently on WiFi (192.0.2.Xx network). Future plan includes structured cabling project to run Ethernet through walls/ceiling, install patch panel, and move PC to wired MGMT VLAN (10.0.10.x) for proper segmentation.

**Skills Demonstrated:**
- Firewall rule design for admin access
- Understanding of network segmentation concepts
- Planning for future infrastructure improvements

**Result:** PC can manage all lab services via WiFi while maintaining some network segmentation

**Segmentation Testing Performed:**

**Test 1: Admin PC (192.0.2.Xx) Access:**
- SSH to Pi: Success
- Uptime Kuma (port 3001): Success
- Prometheus (port 9090): Success
- Grafana (port 3000): Success
- Result: Admin has full management access

**Test 2: VLAN 30 (Client) Segmentation:**
- Ping gateway (10.0.30.1): Success (expected—ICMP to gateway allowed)
- SSH to Pi (10.0.30.1:22): Blocked (segmentation working)
- Access Uptime Kuma (10.0.30.1:3001): Blocked (segmentation working)
- Ping internet (8.8.8.8): Success (internet access allowed)
- Browser to google.com: Success (NAT working)
- Result: VLAN 30 has internet access only, cannot reach management tools

**What I Learned:**

Network segmentation isn't just about creating VLANs—it's about enforcing access control with firewall rules. I can ping VLAN gateways from VLAN 30 because the firewall allows ICMP to the Pi itself for diagnostics, but I can't SSH or access web services because those ports are restricted to the management network only.

This proves the difference between the INPUT chain (traffic to the Pi) and the FORWARD chain (traffic between VLANs). Pinging a gateway tests the INPUT chain. Accessing services on the Pi or devices in other VLANs tests the FORWARD chain, which is where segmentation actually happens.

**Why This Matters:**

If an IoT device in VLAN 40 gets compromised, the attacker is trapped in that VLAN. They can't SSH to the Pi, can't access monitoring dashboards, and can't pivot to other VLANs. The breach is contained. This is called "limiting the blast radius" and it's a key security principle in network design.

**Future Plan:**
When structured cabling is installed (after Phase 4), PC will be moved to wired connection on switch Port 5 (VLAN 10 access port) for proper management VLAN segmentation.

**Skills Demonstrated:**
- Firewall rule design for admin access control
- Network segmentation testing methodology
- Understanding INPUT vs FORWARD chains in firewalls
- Security testing and validation

**Result:** Segmentation verified working. Admin PC has necessary access. VLAN 30 properly isolated.

### Change 027 - Implement Granular Firewall Rules (Least-Privilege)

**Date:** 1/12/2026  
**What:** Redesigned firewall rules to enforce least-privilege access control instead of broad "allow all" rules

**Previous Problems:**
- MGMT VLAN had unrestricted access to all VLANs on all ports
- Entire upstream network (192.0.2.X) could attempt SSH
- No logging of dropped traffic (couldn't see what was being blocked)

**New Firewall Design:**

**INPUT Chain (Traffic to Pi):**
- SSH (port 22): Only from MGMT VLAN and Admin PC
- Web UIs (ports 3000, 3001, 9090): Only from MGMT VLAN and Admin PC
- DHCP (port 67): All VLANs (required for IP assignment)
- DNS (port 53): All VLANs (required for name resolution)
- ICMP (ping): All VLANs and Admin PC (diagnostics)
- Logging: Dropped INPUT packets logged with rate limit

**FORWARD Chain (Inter-VLAN Traffic):**
- MGMT VLAN: Can reach VLAN gateways + internet only (not devices inside other VLANs)
- SRV VLAN: Internet access only
- CLIENT VLAN: Internet access only
- IoT VLAN: Internet access + upstream network (for Home Assistant to control WiFi devices)
- Logging: Dropped FORWARD packets logged with rate limit

**Key Security Improvements:**

**Least-Privilege Access:**
Only specific services on specific ports are allowed. No blanket "allow all" rules. If a service isn't explicitly permitted, it's denied by default.

**Reduced Attack Surface:**
Random devices on upstream network can't attempt SSH anymore. Only admin workstation has management access.

**Visibility:**
Added logging to see what's being blocked. Rate-limited to prevent log flooding. Can now detect port scans, unauthorized access attempts, and misconfigurations.

**Explicit Allow Lists:**
Using TCP port sets for web UIs makes rules more maintainable and clear about what's allowed.

**Testing Performed:**

**Admin PC Access (Should Work):**
- SSH to Pi: Success
- Uptime Kuma (port 3001): Success
- Prometheus (port 9090): Success
- Grafana (port 3000): Success

**VLAN 30 Segmentation (Should Be Blocked):**
- SSH to Pi: Blocked (timeout)
- Web UIs: Blocked (timeout)
- Internet access: Success
- Ping gateway: Success

**Firewall Logs:**
Checked for dropped packets, logs showing blocked connection attempts from VLAN 30 as expected.

**What I Learned:**

The principle of least privilege means starting with "deny all" and only allowing what's specifically needed. This is harder to configure than "allow everything from trusted networks" but much more secure. If a device or VLAN gets compromised, the attacker is limited to only what that device legitimately needed access to.

Adding logging is critical for security. Without logs, I wouldn't know if someone was trying to break in or if my firewall was accidentally blocking legitimate traffic. Rate-limiting the logs prevents an attacker from flooding my logs to hide their activity or fill up disk space.

**Skills Demonstrated:**
- Least-privilege security design
- Firewall rule optimization
- Security logging implementation
- Access control policy enforcement

**Result:** Firewall rules tightened, attack surface reduced, visibility into blocked traffic established

---

### Change 028 - Implement fail2ban (SSH Brute-Force Protection)

**Date:** 1/10/2026  
**What:** Installed and configured fail2ban to automatically block IP addresses making repeated failed SSH login attempts

**Configuration:**
- Ban time: 10 minutes
- Max retries: 5 failed attempts
- Find time: 10 minute window
- Whitelisted: localhost + 192.0.2.X (admin network)
- Monitored service: SSH (port 22)
- Log file: /var/log/auth.log

**How fail2ban Works:**

fail2ban monitors SSH authentication logs. When an IP address fails to log in 5 times within a 10-minute window, fail2ban adds a firewall rule blocking that IP for 10 minutes. This protects against automated brute-force attacks where bots try thousands of password combinations.

**Testing Performed:**

Intentionally failed SSH login 5 times from admin PC to test fail2ban. Got banned for 10 minutes as configured. Had to wait for automatic unban. This proved fail2ban is working correctly and will protect against real brute-force attacks.

**Commands for Management:**

Check status:
```bash
sudo fail2ban-client status sshd
```

Check banned IPs:
```bash
sudo fail2ban-client status sshd
```

Manually unban an IP:
```bash
sudo fail2ban-client unban [IP_ADDRESS]
```

View fail2ban logs:
```bash
sudo tail /var/log/fail2ban.log
```

**What I Learned:**

Testing security controls can lock you out if you're not careful. Always have a backup access method (physical access, second terminal, or wait for auto-unban). Also learned the importance of whitelisting admin networks—production systems should never lock out legitimate administrators.

fail2ban is a critical security layer. Without it, automated bots can try millions of password combinations over time. With fail2ban, they get 5 tries and then they're blocked. This dramatically reduces the attack surface.

**Real-World Application:**

When I deploy the website in Phase 3 and expose services to the internet, fail2ban will automatically protect against SSH brute-force attacks. I'll be able to see ban logs showing real attack attempts and prove the security measures are working.

**Skills Demonstrated:**
- Intrusion prevention system configuration
- Security testing and validation
- Understanding of brute-force attack patterns
- Recovery procedures for locked-out scenarios

**Result:** SSH brute-force protection active. System will automatically ban attackers after 5 failed login attempts.

---

### Change 029 - Centralized Logging Configuration

**Date:** 1/12/2026  
**What:** Configured rsyslog to collect and organize system logs, security events, and service activity in centralized locations

**Log Directory Created:** `/var/log/lab/`

**Log Files Configured:**
- `firewall-input.log` - Dropped packets to Pi (INPUT chain)
- `firewall-forward.log` - Blocked inter-VLAN traffic (FORWARD chain)
- `ssh-auth.log` - SSH authentication attempts (successful and failed)
- `dnsmasq.log` - DHCP leases and DNS queries
- `fail2ban-activity.log` - Ban/unban events
- `docker.log` - Container activity

**Log Rotation:**
- Daily rotation
- Keep 7 days of logs
- Compress old logs to save space
- Automatic cleanup of logs older than 7 days

**Log Analysis Script:** `~/analyze-logs.sh`

Provides quick summary of:
- Failed SSH attempts
- Most blocked IPs
- fail2ban bans
- DHCP activity
- Inter-VLAN blocks

**What I Learned:**

Centralized logging is critical for both troubleshooting and security. When something breaks, logs tell you what happened and when. When you're under attack, logs show you who's attacking and what they're trying to access.

The logs won't populate much in a lab environment until services are exposed to the internet. Once the website goes live in Phase 3, I'll see real attack attempts, failed logins, and blocked traffic. This is when logging becomes valuable for incident response.

Log rotation prevents logs from filling up the disk. Without rotation, a high-traffic server could fill its entire disk with logs in days or weeks.

**Skills Demonstrated:**
- rsyslog configuration
- Log rotation setup
- Bash scripting for log analysis
- Understanding of different log types and their purposes

**Result:** Logging infrastructure ready. Will populate with events as they occur. Analysis tools in place for security monitoring.

---

### Change 030 - Deploy Suricata IDS (Intrusion Detection System)

**Date:** 1/13/2026  
**What:** Installed and configured Suricata to monitor network traffic for attacks, exploits, and suspicious behavior

**What Suricata Does:**

Suricata is an intrusion detection system that inspects all network traffic in real-time. Unlike fail2ban which only protects SSH, Suricata monitors everything—HTTP traffic, DNS queries, port scans, exploit attempts, malware communication, and more.

**Configuration:**
- Monitoring interface: eth0 (upstream traffic)
- Ruleset: Emerging Threats Open (free community rules)
- Logs: /var/log/suricata/fast.log (alerts) and eve.json (detailed data)
- Networks monitored: 192.0.2.X + all lab VLANs (10.10.x.)

**Detection Capabilities:**
- Port scanning (someone mapping the network)
- Brute-force attempts (not just SSH)
- Web application attacks (SQL injection, XSS)
- Malware command-and-control traffic
- Protocol violations
- Suspicious outbound connections

**Testing Performed:**

Ran nmap port scan from MacBook (VLAN 30) against the Pi. Suricata detected and logged the scan attempts. Alerts showed in `/var/log/suricata/fast.log` proving detection is working.

**Script Created:** `~/suricata-check.sh`

Shows Suricata status, alert counts, recent alerts, and top alert types. Run this daily to see what's being detected.

**What I Learned:**

Intrusion detection is different from intrusion prevention. Suricata detects attacks and logs them but doesn't automatically block them (that's what the firewall does). The value is visibility—I can see attack patterns, identify compromised devices, and understand what threats my network faces.

False positives are normal with IDS. Not every alert is a real attack. The "wrong thread" alerts I saw are just internal Suricata processing messages on the Raspberry Pi's limited CPU. Real attacks look different—multiple alerts from external IPs, known exploit signatures, suspicious protocol behavior.

Once the website goes live in Phase 3, Suricata will detect real attacks from the internet. I'll see SQL injection attempts, directory traversal scans, bot traffic, and more. This data proves the security measures are necessary and working.

**Real-World Application:**

In enterprise networks, IDS feeds like Suricata alerts go to a SIEM (Security Information and Event Management) system for centralized monitoring. Security teams use this data to identify breaches, track attackers, and improve defenses. Even in my home lab, I now have visibility into network threats I wouldn't have known about otherwise.

**Skills Demonstrated:**
- IDS deployment and configuration
- Rule management and updates
- Log analysis and alert interpretation
- Understanding signature-based detection
- Distinguishing false positives from real threats

**Result:** Network-wide intrusion detection active. All traffic monitored for attack patterns. Alert logging configured and tested.

---

### Change 031 - Move PC to MGMT VLAN (Completed)

**Date:** 1/14/2026  
**What:** Successfully moved admin PC from upstream WiFi (192.0.2.Xx) to wired MGMT VLAN (10.0.10.x)

**Configuration:**
- Switch Port 5: VLAN 10 access port, PVID 10
- PC IP: 10.0.10.XXX (DHCP from dnsmasq)
- Gateway: 10.0.10.1
- DNS: 10.0.10.1

**Firewall Updates:**
- Removed specific WiFi IP whitelist rules
- Updated MGMT VLAN FORWARD rules to allow full access:
```
  iif "eth0.10" ip saddr $VLAN_MGMT accept
```
- MGMT can now access all VLANs and internet

**Testing:**
- SSH to Pi via 10.0.10.1: Success
- Web UIs (Uptime Kuma, Prometheus, Grafana): Success
- Internet access: Success
- Ping devices in other VLANs: Success
- All monitoring services operational

**Issues Encountered:**

Initially couldn't access web UIs or internet from MGMT VLAN. Root cause was firewall FORWARD rules were too restrictive—only allowed MGMT to reach gateway IPs and had issues with internet routing. Fixed by simplifying to single rule allowing all MGMT VLAN traffic.

Brief DNS test failure in Uptime Kuma (99.56% uptime) during configuration changes. Self-resolved, likely due to network reconfiguration or brief upstream DNS timeout. Monitoring for recurring issues.

**What I Learned:**

When designing firewall rules, sometimes simpler is better. The MGMT VLAN should have broad access to manage infrastructure, so a single permissive rule makes sense. Other VLANs get restrictive rules to limit blast radius.

IP addressing in VLANs: Each VLAN interface on the router has its own IP, and devices use the gateway IP on their own subnet. From MGMT VLAN (10.0.10.x), access the Pi via 10.0.10.1, not 192.0.2.X125.

**Skills Demonstrated:**
- VLAN access port configuration
- Firewall rule troubleshooting
- Understanding layer 3 routing and gateway addressing
- Network connectivity testing and validation

**Result:** PC successfully on MGMT VLAN with full management access to lab infrastructure. Ready for Phase 3.

---

### Change 032 - Domain Registration and DNS Configuration

**Date:** 1/14/2026  
**What:** Registered domain example.com and configured DNS records to point to home public IP for VPN and website access

**Domain Details:**
- Domain: example.com
- Registrar: Namecheap
- Cost: $2/year (.xyz TLD)
- WHOIS Privacy: Enabled (personal info hidden from public lookup)

**DNS Records Configured:**

| Type | Host | Value | Purpose |
|------|------|-------|---------|
| A Record | @ | <YOUR_PUBLIC_IP> | Main domain (example.com) |
| A Record | vpn | <YOUR_PUBLIC_IP> | VPN access (vpn.example.com) |
| A Record | memecoin | <YOUR_PUBLIC_IP> | Website (memecoin.example.com) |

**How DNS Works:**

DNS (Domain Name System) translates human-readable domain names into IP addresses. When someone types vpn.example.com, DNS servers respond with "that's at <YOUR_PUBLIC_IP>" (my home's public IP address). Their device then connects to that IP, hits my home router, and port forwarding directs the traffic to the appropriate service on my Pi.

**Why Point to Home IP:**

The domain points to my home network's public IP (<YOUR_PUBLIC_IP>) because that's where the server is physically located. This is the same concept as enterprise networks—a company's website DNS points to their office building's public IP, then internal routing forwards traffic to the correct server on the correct VLAN inside the building.

**Multi-Layer Addressing:**

1. **Public Layer (Internet):** example.com → <YOUR_PUBLIC_IP> (what the world sees)
2. **Home Network Layer:** Router forwards to Pi at 192.0.2.X125 (internal routing)
3. **VLAN Layer:** Pi serves content from appropriate VLAN (VLAN 20 for website, VLAN 10 for VPN)

Internet users never see the internal network structure (192.0.2.Xx or 10.10.x.x addresses)—only the public-facing domain and IP. This provides security through network segmentation.

**DMZ Architecture:**

The SRV VLAN (10.0.20.) acts as a DMZ (Demilitarized Zone)—a network segment that sits between the internet and internal trusted networks. The website will be hosted in this VLAN, isolated from the management VLAN. If the website is compromised, attackers are trapped in VLAN 20 by firewall rules and cannot pivot to MGMT VLAN (10.0.10.) where admin tools and SSH access exist.

This is standard enterprise security architecture: public-facing services in DMZ, management/sensitive systems in separate trusted networks, firewall rules preventing lateral movement between zones.

**Testing Performed:**

Verified DNS propagation using nslookup:
```
nslookup example.com → <YOUR_PUBLIC_IP> ✓
nslookup vpn.example.com → <YOUR_PUBLIC_IP> ✓
nslookup memecoin.example.com → <YOUR_PUBLIC_IP> ✓
```

All records resolving correctly to home public IP.

**What I Learned:**

Classic DMZ Architecture

INTERNET
    ↓
EXTERNAL FIREWALL
    ↓
DMZ (10.50.20.)
├─ Web Server (10.50.20.10)
├─ Mail Server (10.50.20.11)
└─ DNS Server (10.50.20.12)
    ↓
INTERNAL FIREWALL
    ↓
INTERNAL NETWORK (10.50.10.)
├─ Database Server (10.50.10.15) ← Not accessible from internet
├─ File Server (10.50.10.16)
└─ Admin Workstations (10.50.10.)

DNS is the phone book of the internet—it maps memorable names to numerical IP addresses. Without DNS, users would have to memorize IP addresses for every website. Understanding DNS is fundamental to deploying any internet-facing service.

The relationship between public IPs, private IPs, and VLANs demonstrates multi-tier network architecture. External users only interact with the public layer, while internal routing and segmentation happen invisibly behind the firewall. This is how all major websites and services operate at scale.

Dynamic DNS (DDNS) could be added later if my ISP changes my public IP frequently—a script on the Pi would detect IP changes and automatically update DNS records, ensuring the domain always points to the current IP.

**Skills Demonstrated:**
- Domain registration and management
- DNS record configuration (A records)
- Understanding of public vs private IP addressing
- Multi-tier network architecture design
- DMZ security concepts
- Translating theory to practical implementation

**Result:** Domain successfully registered and DNS configured. Internet users can now resolve example.com subdomains to home network. Ready for VPN and website deployment.

---

### Change 033 - WireGuard VPN Configuration (Partial Implementation)

**Date:** 1/15/2026  
**What:** Configured WireGuard VPN server for remote access to MGMT VLAN, encountered ISP equipment limitations

**Configuration Completed:**
- Installed WireGuard on Pi
- Generated server and client cryptographic key pairs
- Configured VPN server (wg0 interface at 10.99.X.X/24)
- Created client configuration for Windows
- DNS pointing to vpn.example.com
- Proper routing to MGMT VLAN (10.0.10.)

**Technical Details:**
- VPN Network: 10.99.X.X
- Server IP: 10.99.X.1
- Client IP: 10.99.X.2
- Protocol: UDP
- Ports Tested: 51820, 443
- Encryption: Modern cryptographic suite (Curve25519, ChaCha20, Poly1305)

**Issue Encountered:**

AT&T BGW210 gateway does not properly forward UDP traffic despite correct NAT/Gaming configuration. Port 51820 UDP and port 443 UDP both remain closed from external testing, even with:
- Correct port forwarding rules configured
- Firewall restrictions disabled
- WireGuard service confirmed listening on Pi
- Internal network routing verified

This is a known limitation of some ISP-provided gateway equipment, particularly AT&T residential gateways which have restricted port forwarding capabilities for certain protocols.

**What I Learned:**

VPN technology involves multiple layers:
1. **Cryptographic layer** - Key exchange and encrypted tunneling
2. **Network layer** - Routing between VPN network and internal VLANs
3. **Infrastructure layer** - Port forwarding, NAT, upstream connectivity

I successfully configured layers 1 and 2. Layer 3 was blocked by equipment outside my control. In a production environment, solutions would include:
- Requesting ISP bridge mode (gateway becomes simple modem, use own router)
- Cloud-hosted VPN endpoint (Pi connects out to VPS, users connect to VPS)
- Alternative port/protocol (some ISPs allow certain ports)
- Business-class internet with fewer restrictions

**Skills Demonstrated:**
- VPN server configuration
- Public key cryptography
- Network address translation concepts
- Troubleshooting methodology
- Understanding of OSI layer interactions
- Documentation of unsuccessful implementations (equally valuable)

**Security Note:**

WireGuard service stopped and disabled. Port forwards removed from router. No open ports to internet. System remains secure.

---

Change 034 - Memecoin Tracker Development Application
Date: 1/16/2026
What: Built real-time cryptocurrency token tracker using PumpPortal WebSocket API
Purpose: Development application to practice WebSocket integration, real-time data handling, and frontend development
Location: /home/admin/memecoin-tracker/
Technology Stack:

Backend: Node.js + Express
WebSocket: wss://pumpportal.fun/api/data
Frontend: Vanilla JavaScript (HTML/CSS)

Features Implemented:

Real-time token creation monitoring
Trading statistics (buys, sells, volume, market cap)
Token metadata display
Auto-refresh every 15 seconds

Initial Issues:

WebSocket data structure confusion (PumpPortal sends different events)
Frontend not displaying data properly
Had to rebuild server.js and frontend multiple times

Solution:

Separated token creation events from trading events
Subscribed to both subscribeNewToken and subscribeTokenTrade methods
Built clean frontend that displays all available data fields

Deployment:

Development environment: http://10.0.10.1:3100 (MGMT VLAN)
Firewall rule added: iif "eth0.10" ip saddr $VLAN_MGMT tcp dport 3100 accept

Commands Used:
bashmkdir /home/admin/memecoin-tracker
cd /home/admin/memecoin-tracker
npm init -y
npm install express ws cors
nano server.js
mkdir public
nano public/index.html
node server.js  # Initial testing
What I Learned:
WebSocket APIs send different message types that need to be handled separately. Token creation events contain metadata (name, symbol, description) while trade events contain activity data (buys, sells, volume). The app needs to combine both data sources to show complete information.
Real-time data applications require proper state management—the server maintains a Map of tokens keyed by mint address, updating as new events arrive.
Skills Demonstrated:

WebSocket client implementation
Real-time data handling
State management in Node.js
Frontend JavaScript (fetch API, DOM manipulation)
Error handling for external APIs

Result: Working real-time memecoin tracker in development environment

---

Change 035 - Portfolio Website Development
Date: 1/16/2026
What: Built professional portfolio landing page with live cryptocurrency price tracking
Purpose: Public-facing website to showcase homelab capabilities and demonstrate API integration
Location: /home/admin/portfolio-site/
Technology Stack:

Backend: Node.js + Express
API Integration: CoinGecko (cryptocurrency prices)
Frontend: Vanilla JavaScript with modern CSS

Features:

Live crypto prices (BTC, ETH, SOL, DOGE, SHIB, PEPE, BONK, WIF)
24-hour price change indicators (color-coded red/green)
Market cap display
VLAN architecture showcase
Project list highlighting homelab work
Auto-refresh every 60 seconds

API Endpoint Created:
javascriptapp.get('/api/crypto-prices', async (req, res) => {
  const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
    params: {
      ids: 'bitcoin,ethereum,solana,dogecoin,shiba-inu,pepe,bonk,dogwifcoin',
      vs_currencies: 'usd',
      include_24hr_change: 'true',
      include_market_cap: 'true'
    }
  });
  res.json(response.data);
});
Design:

Dark theme (#0a0e27 background)
Purple gradient header (#667eea → #764ba2)
Glassmorphism card effects
Responsive grid layout
Hover animations on crypto cards

Deployment:

Development environment: http://10.0.10.1:3200 (MGMT VLAN)
Firewall rule added: iif "eth0.10" ip saddr $VLAN_MGMT tcp dport 3200 accept

Installation Commands:
bashmkdir /home/admin/portfolio-site
cd /home/admin/portfolio-site
npm init -y
npm install express axios cors
nano server.js
mkdir public
nano public/index.html
node server.js
What I Learned:
External API integration requires error handling—if CoinGecko is down or rate-limited, the site should gracefully display an error instead of crashing. The frontend uses try/catch blocks and displays user-friendly error messages.
CSS Grid and Flexbox enable responsive layouts that work on desktop and mobile without media queries for basic layouts. The crypto cards automatically reflow based on screen size.
Skills Demonstrated:

RESTful API integration
Async/await JavaScript
CSS Grid layout
Frontend state management
Error handling for external dependencies

Result: Professional portfolio site running in development environment, ready for production deployment

---

Change 036 - Nginx Installation and Configuration
Date: 1/19/2026
What: Installed Nginx web server as reverse proxy for production deployment
Why Nginx:
Nginx acts as the DMZ boundary—it's the only service directly exposed to the internet. Behind Nginx, the Node.js application runs on a separate network (SRV VLAN), isolated from management tools. If an attacker compromises the website, they're trapped in the SRV VLAN and cannot access SSH, Grafana, Prometheus, or other management services in the MGMT VLAN.
Installation:
bashsudo apt install nginx -y
sudo systemctl enable nginx
sudo systemctl start nginx
Initial Configuration: /etc/nginx/sites-available/portfolio
nginxserver {
    listen 80;
    server_name example.com www.example.com;

    location / {
        proxy_pass http://localhost:3200;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
Enabled Site:
bashsudo ln -s /etc/nginx/sites-available/portfolio /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
Testing:
bashcurl http://10.0.10.1  # Should show portfolio site
What I Learned:
Reverse proxies add a layer of abstraction between users and backend applications. Users connect to Nginx on port 80/443, Nginx forwards requests to the Node.js app on port 3200, then returns responses to users. The backend app never directly handles internet traffic.
Nginx configuration testing (nginx -t) prevents broken configs from crashing the web server. Always test before reloading.
Skills Demonstrated:

Reverse proxy configuration
Virtual host setup
Proxy headers for IP forwarding
Service management

Result: Nginx successfully proxying to portfolio application on port 80

---

Change 037 - SSL Certificate with Let's Encrypt
Date: 1/19/2026
What: Obtained free SSL/TLS certificate for HTTPS encryption using Let's Encrypt
Installation:
bashsudo apt install certbot python3-certbot-nginx -y
DNS Configuration (Namecheap):

Added A record: www.example.com → <YOUR_PUBLIC_IP>
Waited 10 minutes for DNS propagation
Verified: nslookup www.example.com returned correct IP

Certificate Request:
bashsudo certbot --nginx -d example.com -d www.example.com
Prompts Answered:

Email: <YOUR_EMAIL> (for renewal notices)
Agree to Terms of Service: Yes
Share email with EFF: Yes

Initial Failure:
First attempt failed with DNS error for www.example.com. The subdomain didn't exist in DNS yet. Added A record on Namecheap, waited for propagation, then retry succeeded.
Certificate Details:

Issuer: Let's Encrypt
Validity: 90 days
Location: /etc/letsencrypt/live/example.com/
Auto-renewal: Configured via certbot cron job

Nginx Auto-Configuration:
Certbot automatically modified the Nginx config to:

Listen on port 443 (HTTPS)
Include SSL certificate paths
Redirect HTTP (port 80) → HTTPS (port 443)

Verification:
bashsudo certbot certificates
sudo certbot renew --dry-run  # Test auto-renewal
Testing:
bashcurl https://example.com  # Should return HTML with SSL
What I Learned:
SSL/TLS certificates encrypt traffic between users and the server, preventing eavesdropping and man-in-the-middle attacks. Let's Encrypt provides free certificates with automated renewal, making HTTPS accessible to everyone.
Certbot's Nginx integration is powerful—it automatically edits the Nginx config, sets up SSL parameters, and configures HTTP → HTTPS redirects. Manual SSL configuration would be much more complex.
DNS propagation takes time (5-30 minutes). Always verify DNS records before requesting certificates to avoid rate-limiting from failed attempts.
Skills Demonstrated:

SSL/TLS certificate management
DNS troubleshooting
Certbot automation
HTTPS configuration
Understanding of public key infrastructure (PKI)

Result: Website secured with valid SSL certificate, accessible at https://example.com

---

Change 038 - AT&T Router Port Forwarding
Date: 1/19/2026
What: Configured port forwarding on AT&T BGW210 gateway to expose website to internet
Router Details:

Model: AT&T BGW210
Admin URL: http://192.0.2.X
Pi internal IP: 192.0.2.X

Port Forwarding Rules Created:
ServiceExternal PortInternal IPInternal PortProtocolHTTP80192.0.2.X80TCPHTTPS443192.0.2.X443TCP
Configuration Steps:

Logged into router at 192.0.2.X
Navigated to Settings → Firewall → NAT/Gaming
Added HTTP and HTTPS rules pointing to "lab-router" device
Router auto-resolved "lab-router" to 192.0.2.X

Initial Issue:
Website unreachable from internet even with correct port forwarding. Port checker showed ports 80/443 as closed. Suspected firewall blocking on Pi.
Testing:
bash# From phone (cellular network, off WiFi)
curl http://example.com  # Connection timeout
```

**What I Learned:**

Port forwarding has two components:
1. **Router level:** Forward external ports to internal IP (AT&T gateway)
2. **Firewall level:** Allow traffic on those ports (Pi nftables)

Both must be configured correctly for traffic to reach the destination. The port forward was correct, but the Pi's firewall was blocking traffic on eth0 interface.

Some ISP routers (like AT&T) use device hostnames instead of requiring manual IP entry. The router maintains a DHCP clients list and resolves "lab-router" to its current IP automatically.

**Skills Demonstrated:**
- NAT configuration
- Port forwarding setup
- Understanding multi-layer network security
- ISP gateway management

**Result:** Port forwarding configured (but website still unreachable due to firewall issue, resolved in next change)

---

### Change 039 - Firewall Configuration for Public Traffic (eth0)

**Date:** 1/19/2026  
**What:** Added firewall rules to allow internet traffic on ports 80/443 to reach Nginx

**Problem Discovered:**

Existing nftables rules only handled VLAN interfaces (eth0.10, eth0.20, etc.). Public traffic arrives on the parent interface **eth0** (not a VLAN subinterface), so it was being blocked by the default drop policy.

**Network Flow:**
```
Internet → AT&T Gateway → Pi eth0 (192.0.2.X) → BLOCKED
                                                    ↓ (needed rule)
                                                  Nginx → Portfolio app
Firewall Rule Added: /etc/nftables.conf
bash# Allow web traffic on eth0 (from internet)
iif "eth0" tcp dport { 80, 443 } accept comment "Allow HTTP/HTTPS from internet"
Applied:
bashsudo nft -f /etc/nftables.conf
Testing:
bash# From phone (cellular)
curl https://example.com  # SUCCESS - returned HTML
What I Learned:
VLAN interfaces (eth0.10, eth0.20) are logical subinterfaces of the parent interface (eth0). Traffic can arrive on either the parent or subinterfaces depending on whether it's tagged or untagged. Public internet traffic arrives untagged on eth0, while inter-VLAN traffic uses tagged subinterfaces.
This is a critical lesson for firewall design—you must explicitly allow traffic on EVERY interface it could arrive on. Allowing traffic on eth0.10 doesn't automatically allow it on eth0.
Skills Demonstrated:

Understanding VLAN tagging vs untagged traffic
Firewall troubleshooting methodology
Interface-specific firewall rules
Public-facing service security

Result: Website accessible from internet at https://example.com

---

Change 040 - Enhanced Nginx Security Configuration
Date: 1/19/2026
What: Implemented rate limiting, security headers, and bot blocking in Nginx
Security Enhancements:
1. Rate Limiting:
nginx# In http block:
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

# In server block:
limit_req zone=general burst=20 nodelay;
limit_conn addr 10;

10 requests per second per IP
Burst allowance: 20 requests
Maximum 10 concurrent connections per IP

2. Security Headers:
nginxadd_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' https: 'unsafe-inline' 'unsafe-eval';" always;
3. Bot Blocking:
nginxif ($http_user_agent ~* (bot|crawl|spider|scrape|http|wget|curl|nikto|scan)) {
    return 403;
}
4. Hidden File Protection:
nginxlocation ~ /\. {
    deny all;
}
What Each Security Feature Does:
Rate Limiting: Prevents DDoS attacks and aggressive scrapers by limiting how fast a single IP can make requests.
X-Frame-Options: Prevents clickjacking attacks where the site is embedded in an iframe on a malicious page.
X-Content-Type-Options: Prevents MIME sniffing attacks where browsers try to guess file types.
X-XSS-Protection: Enables browser built-in XSS filtering.
Content-Security-Policy: Restricts what resources the page can load, mitigating XSS attacks.
Bot Blocking: Blocks automated scrapers and scanners based on user-agent strings.
Testing:
bash# Regular curl blocked by bot filter
curl https://example.com  # 403 Forbidden

# Browser user-agent works
curl -A "Mozilla/5.0" https://example.com  # Returns HTML
What I Learned:
Defense in depth means multiple layers of security. Even with a firewall, adding application-level security (Nginx) provides additional protection. If an attacker bypasses one layer, they hit the next.
HTTP security headers are simple to implement but provide significant protection against common web attacks. They're considered best practice for any public-facing web server.
User-agent filtering is effective against unsophisticated bots but can be bypassed easily by attackers who spoof headers. It's one layer of many, not a complete solution.
Skills Demonstrated:

Web application security hardening
Understanding of common web attacks (XSS, clickjacking, MIME sniffing)
Rate limiting configuration
HTTP header security

Result: Multi-layered security protecting public website

---

Change 041 - fail2ban Configuration for Nginx
Date: 1/19/2026
What: Extended fail2ban to protect Nginx from web application attacks
Configuration File: /etc/fail2ban/jail.d/nginx.conf
ini[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-noscript]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
Applied:
bashsudo systemctl restart fail2ban
sudo fail2ban-client status
Active Jails After Configuration:

sshd (SSH protection - from Change 028)
nginx-http-auth (failed authentication attempts)
nginx-limit-req (rate limit violations)

What Each Jail Protects Against:
nginx-http-auth: Brute-force attempts on password-protected areas.
nginx-noscript: Script injection attempts (PHP, SQL).
nginx-badbots: Known malicious bot signatures.
nginx-noproxy: Proxy abuse attempts.
nginx-limit-req: Excessive requests violating rate limits.
Verification:
bashsudo fail2ban-client status nginx-limit-req
What I Learned:
fail2ban for web services works the same as SSH—it monitors logs for attack patterns and automatically adds firewall rules to ban offending IPs. The difference is the log files and patterns being monitored.
Web application attacks leave different signatures than SSH brute-force. Script injections show up in access logs, rate limit violations in error logs. fail2ban needs to monitor multiple log files with different regex patterns.
Skills Demonstrated:

Web application intrusion prevention
Log-based attack detection
fail2ban jail configuration
Understanding of web attack patterns

Result: Automated IP banning for web application attacks

---

Change 042 - Suricata Configuration for Public Traffic Monitoring
Date: 1/19/2026
What: Extended Suricata IDS to monitor public-facing traffic on eth0 interface
Previous Configuration:
Suricata was only monitoring VLAN interfaces (eth0.10, eth0.20, eth0.30, eth0.40) from Change 030. Public internet traffic arrives on eth0 (parent interface), so it wasn't being monitored for attacks.
Configuration Update: /etc/suricata/suricata.yaml
Added eth0 to af-packet interface list:
yamlaf-packet:
  - interface: eth0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    
  - interface: eth0.10
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    
  # ... other VLAN interfaces
Restart and Verification:
bashsudo suricata -T -c /etc/suricata/suricata.yaml  # Test config
sudo systemctl restart suricata
sudo suricatasc -c "iface-list"  # Verify interfaces
What This Achieves:
Now Suricata monitors:

eth0: Public internet traffic (website visitors, attacks from internet)
eth0.10: MGMT VLAN internal traffic
eth0.20: SRV VLAN internal traffic (future)
eth0.30: CLIENT VLAN internal traffic
eth0.40: IoT VLAN internal traffic

Complete network visibility for security monitoring.
What I Learned:
IDS must monitor EVERY network segment where attacks could occur. Before this change, Suricata could detect internal threats (compromised device scanning VLANs) but couldn't see external attacks against the website.
Adding eth0 monitoring means Suricata now sees:

Port scans from internet
Web application exploit attempts
Malicious traffic patterns
Botnet command-and-control communication
All threats that failed other security layers

Skills Demonstrated:

IDS interface management
Network segmentation monitoring
Understanding of attack surfaces
Comprehensive security coverage

Result: Suricata monitoring all network interfaces including public-facing traffic

---

Change 043 - Enhanced Suricata Analysis Script
Date: 1/19/2026
What: Completely rewrote suricata-check.sh for better usability and threat assessment
Problems with Original Script:

Raw output difficult to read
No differentiation between real threats and false positives
TCP handshake errors (noise) mixed with actual attacks
No risk assessment or recommendations

New Script Features:
1. Color-Coded Output:

Green: All clear, no threats
Yellow: Low/moderate risk
Red: High risk, action needed

2. Filters TCP Noise:
bashgrep -v "SURICATA STREAM"  # Removes handshake errors
grep -E "ET EXPLOIT|ET ATTACK|ET MALWARE|ET SCAN"  # Shows real threats only
3. Threat Assessment Levels:

0 threats: All Clear
1-4 threats: Low Risk
5-19 threats: Moderate Risk
20+ threats: High Risk

4. Top Attacking IPs:
Shows external IPs with alert counts, flags suspicious activity (10+ alerts).
5. fail2ban Integration:
Shows currently banned IPs and which jails triggered bans.
6. Actionable Recommendations:
Based on threat level, provides specific commands to investigate further.
Script Location: /home/admin/suricata-check.sh
Usage:
bash./suricata-check.sh
```

**Example Output:**
```
╔════════════════════════════════════════════════════╗
║        🛡️  SURICATA SECURITY REPORT 🛡️           ║
╔════════════════════════════════════════════════════╗

✓ Suricata Status: RUNNING

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 ALERT SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Alerts Today: 9384
Critical Threats:   3

⚠ SECURITY STATUS: LOW RISK
  Minor suspicious activity detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 RECENT THREATS (Last 10)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[SCAN] 01/19/2026-12:47:29 ET SCAN Zmap User-Agent
[EXPLOIT] 01/19/2026-15:30:55 ET EXPLOIT Zimbra XXE
What I Learned:
Security tools generate enormous amounts of data. The value isn't in the raw data, it's in the analysis. A security report should answer: "Am I under attack?" and "What should I do about it?"
False positives are normal in IDS. Suricata sees thousands of TCP handshake "errors" that are just normal network behavior on Raspberry Pi's limited CPU. Filtering noise from signal is critical for effective monitoring.
Color coding and visual hierarchy make reports scannable. Security teams need to assess threats quickly—well-formatted output enables that.
Skills Demonstrated:

Bash scripting with advanced text processing
Log analysis and filtering
Security report generation
User interface design (CLI)
Threat prioritization

Result: User-friendly security reports filtering noise from real threats

---

Change 044 - Security Analysis and Threat Response
Date: 1/19/2026
What: Analyzed first real attack attempts detected by Suricata IDS
Attacks Detected:
1. Zmap Port Scan:

Source: 20.65.195.96
Target: 192.0.2.X:443 (HTTPS)
Signature: ET SCAN Zmap User-Agent (Inbound)
What it is: Automated port scanning tool
Risk: Low - Just reconnaissance, no actual attack

2. Zimbra Exploit Attempts:

Source: 79.124.40.174
Exploits: CVE-2019-9621, CVE-2019-9670
Target: 192.0.2.X:80 (HTTP)
Signature: ET EXPLOIT Zimbra XML External Entity Injection
What it is: Automated exploit scanner trying known Zimbra vulnerabilities
Risk: Low - We don't run Zimbra, exploits failed

Analysis Performed:
Checked Nginx Logs:
bashsudo grep "79.124.40.174" /var/log/nginx/access.log
Found HTTP 403 (Forbidden) responses—Nginx's bot blocking rejected the requests.
Why Attacks Failed:

Wrong Target Software: Exploits target Zimbra email server, we run Nginx + Node.js
Bot Blocking: Nginx detected suspicious user-agent and returned 403
Rate Limiting: Even if attempts succeeded, rate limits would throttle attacks
fail2ban: Repeated attempts would trigger automatic IP ban
Firewall: Only ports 80/443 exposed, all other services blocked

fail2ban Status:
bashsudo fail2ban-client status
Currently Banned IPs: 0
No bans triggered because attacks were single attempts, not repeated.
What I Learned:
This is Normal Internet Background Noise:
Public-facing websites are constantly scanned by automated bots looking for vulnerabilities. Seeing 50-200 exploit attempts per day is normal, not an indication of targeted attacks. These are opportunistic bots trying every known CVE against every IP they find.
Defense in Depth Worked:
Multiple security layers stopped the attacks:

Suricata detected and logged (visibility)
Nginx blocked suspicious requests (application security)
Firewall limited exposed services (network security)
fail2ban ready to ban repeated attempts (automated response)

Even if one layer failed, others would stop the attack.
IDS Provides Visibility:
Without Suricata, I wouldn't know these attacks happened. The attacks failed silently—Nginx returned 403, end of story. Suricata proved the attacks occurred and security measures worked as designed.
False Positives vs Real Threats:
101,539 total alerts doesn't mean 101,539 attacks. Most (99%+) are false positives:

TCP handshake "errors" (normal Pi behavior)
Ubuntu update servers flagged as suspicious (known false positive)
DNS queries flagged (benign)

Only 3 real threats detected—the rest is noise. Filtering is essential.
Skills Demonstrated:

Log correlation across multiple systems
Threat analysis and risk assessment
Understanding of exploit mechanics
Distinguishing false positives from real attacks
Incident response procedures

Result: Confirmed security posture working, attacks detected and blocked, no compromise

---

Change 045 - PM2 Process Manager Deployment
Date: 1/19/2026
What: Installed PM2 to keep Node.js applications running 24/7 without requiring open SSH sessions
Problem:
Node.js apps (portfolio site, memecoin tracker) were started manually with node server.js. When SSH session closed or terminal was killed, the processes died. Website went offline every time I disconnected.
Solution: PM2 (Process Manager 2)
PM2 is a production process manager for Node.js that:

Keeps apps running in background
Auto-restarts crashed apps
Starts apps on system boot
Provides logs and monitoring
Load balances (not used here)

Installation:
bashsudo npm install -g pm2
Started Applications:
bashcd /home/admin/portfolio-site
pm2 start server.js --name portfolio

cd /home/admin/memecoin-tracker
pm2 start server.js --name memecoin-tracker

pm2 list  # View running apps
Issue Encountered - Port Conflict:
Portfolio app showed 43 restarts in PM2, using 100% CPU. Logs showed no errors, just kept restarting.
Diagnosis:
bashsudo ss -tlnp | grep :3200
# Found old node process (PID 82781) already using port 3200
Root Cause:
Old node server.js process from manual testing was still running. PM2 tried to start a new process on port 3200, failed because port was taken, crashed immediately, PM2 auto-restarted it, repeat infinitely.
Resolution:
bashsudo kill 82781  # Killed old process
pm2 list  # Restart count stopped climbing
Configured Auto-Start on Boot:
bashpm2 startup systemd  # Generates systemd unit file
# Copied and ran command PM2 provided:
sudo env PATH=$PATH:/usr/bin /usr/local/lib/node_modules/pm2/bin/pm2 startup systemd -u admin --hp /home/admin

pm2 save  # Save current process list
PM2 Management Commands:
bashpm2 list              # Show all apps
pm2 logs portfolio    # View logs
pm2 restart portfolio # Restart app
pm2 stop portfolio    # Stop app
pm2 delete portfolio  # Remove from PM2
pm2 monit            # Live monitoring
What I Learned:
Production applications need process managers. Running node server.js manually is fine for development, but production systems require:

Background execution
Auto-restart on crash
Startup on boot
Log management
Monitoring

PM2 error messages can be misleading. "No errors in logs" doesn't mean "working correctly"—it means the app starts successfully then immediately exits for a different reason (port conflict).
Always check for port conflicts before starting services. ss -tlnp | grep :<port> shows what's using a port.
Skills Demonstrated:

Process management
Daemon/service configuration
Troubleshooting high CPU usage
Understanding port binding conflicts
Production deployment practices

Result: Both applications running 24/7, auto-restart on crash, start on boot

---

Change 046 - Firewall Auto-Start Issue Identified
Date: 1/20/2026
What: Discovered firewall rules not loading automatically on boot, requiring manual restart
Problem:
After rebooting Pi to test PM2 auto-start, internet connectivity from PC failed. Running sudo nft -f /etc/nftables.conf manually restored connectivity, proving firewall rules weren't loading on boot.
Diagnosis:
bashsudo systemctl status nftables
# Showed active but rules weren't applied

sudo nft list ruleset | head -20
# Empty or incomplete ruleset

sudo systemctl is-enabled nftables
# Would show if service starts on boot
Likely Causes:

Timing Issue: nftables service starting before network interfaces are ready (common with VLANs)
Service Not Enabled: nftables.service not set to start automatically
Dependency Problem: nftables lacks dependency on network being online

Solution (Applied in Next Change):
Create systemd override to:

Ensure nftables starts AFTER network is online
Add 5-second delay for VLAN interfaces to initialize
Make service wait for completion before continuing boot

Temporary Workaround:
bash# After each reboot, manually run:
sudo nft -f /etc/nftables.conf
```

**What I Learned:**

Service dependencies in systemd are critical for network services. A firewall that loads before network interfaces exist will load an empty/incomplete ruleset, leaving the system unprotected or breaking connectivity.

VLANs add complexity—parent interface (eth0) might be up, but VLAN subinterfaces (eth0.10, eth0.20) take extra time to initialize. Firewall rules referencing those interfaces fail if applied too early.

**Skills Demonstrated:**
- systemd service troubleshooting
- Understanding boot order and dependencies
- Network initialization timing issues
- Identifying root cause vs symptoms

**Result:** Issue identified, temporary workaround documented, permanent fix planned

---

### Change 047 - Move Portfolio to SRV VLAN (Proper DMZ Architecture)

**Date:** 1/20/2026  
**What:** Migrated portfolio application from localhost to SRV VLAN for proper network segmentation and DMZ isolation

**Why This Matters:**

**Before (Incorrect):**
```
Internet → Nginx (MGMT VLAN) → localhost:3200 (same server)
```
Everything on management network. If website compromised, attacker has access to management tools.

**After (Proper DMZ):**
```
Internet → Nginx (MGMT VLAN 10.0.10.1) 
    ↓ Firewall controls access
Portfolio App (SRV VLAN 10.0.20.1) ← Isolated in DMZ
Website isolated in SRV VLAN. If compromised, firewall prevents lateral movement to MGMT VLAN where SSH, Grafana, Prometheus exist.
Implementation Steps:
1. Bind App to SRV VLAN IP:
Edited /home/admin/portfolio-site/server.js:
javascript// Changed from:
app.listen(PORT, () => {

// To:
app.listen(PORT, '10.0.20.1', () => {
2. Restarted App:
bashpm2 restart portfolio
pm2 logs portfolio  # Verified: "running on http://10.0.20.1:3200"
3. Tested Direct Access:
bashcurl http://10.0.20.1:3200  # Returned HTML - working
curl http://localhost:3200    # 502 Bad Gateway - correct (no longer listening)
4. Updated Nginx Reverse Proxy:
Edited /etc/nginx/sites-available/portfolio:
nginx# Changed from:
proxy_pass http://localhost:3200;

# To:
proxy_pass http://10.0.20.1:3200;
5. Tested Nginx Config:
bashsudo nginx -t  # Syntax OK
sudo systemctl reload nginx
6. Initial Test (Expected Failure):
bashcurl https://example.com  # Hung/timed out
Nginx couldn't reach app because firewall blocks MGMT → SRV by default.
7. Added Firewall Rules:
Edited /etc/nftables.conf in FORWARD chain:
bash# Allow Nginx (MGMT) to proxy to portfolio app (SRV VLAN)
iif "eth0.10" oif "eth0.20" ip saddr 10.0.10.1 ip daddr 10.0.20.1 tcp dport 3200 ct state new,established accept comment "Nginx → Portfolio"
iif "eth0.20" oif "eth0.10" ip saddr 10.0.20.1 ip daddr 10.0.10.1 tcp sport 3200 ct state established accept comment "Portfolio → Nginx (return)"
8. Applied Firewall:
bashsudo nft -f /etc/nftables.conf
9. Final Testing:
bashcurl http://10.0.20.1:3200        # Works - app accessible on SRV VLAN
curl https://example.com         # Works - Nginx proxies to SRV VLAN
# From phone (cellular): https://example.com - Works publicly
Issue Encountered - Bot Blocking Broke curl:
Regular curl https://example.com returned 403 because Nginx's bot blocking rule matched "curl" in user-agent string.
Resolution:
Modified bot blocking in Nginx config:
nginx# Block bad bots, but allow curl from internal/admin
set $block_bot 0;

if ($http_user_agent ~* (bot|crawl|spider|scrape|wget|nikto|scan)) {
    set $block_bot 1;
}

# Don't block curl from localhost/internal networks
if ($remote_addr ~* "^(127\.0\.0\.1|10\.|192\.168\.)") {
    set $block_bot 0;
}

if ($block_bot = 1) {
    return 403;
}
```

Now blocks internet bots, but allows curl from internal IPs for testing.

**Final Architecture:**
```
Internet (Public)
    ↓
AT&T Gateway (192.0.2.X) - Port Forward 80/443
    ↓
Pi eth0 (192.0.2.X) - Firewall allows 80/443 only
    ↓
MGMT VLAN (10.0.10.1)
    ├─ Nginx :80/443 (DMZ boundary)
    │   ├─ SSL termination
    │   ├─ Rate limiting
    │   ├─ Bot blocking
    │   └─ Security headers
    ↓ Firewall allows MGMT → SRV only port 3200
SRV VLAN (10.0.20.1)
    └─ Portfolio App :3200 (isolated, DMZ'd)
Security Layers:

AT&T firewall (only 80/443 forwarded)
Pi firewall on eth0 (only 80/443 accepted from internet)
Nginx reverse proxy (rate limiting, bot blocking, SSL)
VLAN segmentation (MGMT ↔ SRV firewall rules)
Application in DMZ (can't reach MGMT even if compromised)

What I Learned:
DMZ (Demilitarized Zone) Architecture:
A DMZ is a network segment that sits between untrusted (internet) and trusted (internal) networks. Public-facing services go in the DMZ. If they're compromised, the attacker is trapped by firewall rules and cannot pivot to trusted internal systems.
This is standard enterprise security architecture—every organization with public services uses this model.
Zero-Trust Principles:
Even though both Nginx and the app are on the same physical server, they're on different VLANs. The firewall enforces access control between them. Only the specific port needed (3200) is allowed, only from the specific source (10.0.10.1).
If the app is compromised, the attacker cannot:

SSH to the router (blocked by firewall)
Access Grafana/Prometheus (different VLAN, blocked)
Scan other VLANs (FORWARD rules prevent it)
Pivot to other services on MGMT VLAN

This limits the "blast radius" of a breach.
Interview Talking Point:
"I deployed the public-facing website to a dedicated server VLAN, completely isolated from my management network. Nginx acts as a reverse proxy on the management VLAN, with firewall rules allowing ONLY the proxy connection to the DMZ'd application. This follows zero-trust principles—even if the website is compromised, the attacker is contained in the server VLAN and cannot pivot to management systems like Grafana, Prometheus, or the router configuration."
Skills Demonstrated:

DMZ architecture implementation
Zero-trust network design
Inter-VLAN firewall rules
Understanding of attack surface reduction
Production security best practices

Result: Portfolio website isolated in DMZ (SRV VLAN), proper network segmentation achieved, attack surface minimized

---

Change 048 - Firewall Auto-Start Fix + System Reboot Test
Date: 1/20/2026
What: Resolved firewall not loading on boot and verified all services auto-start correctly
Problem:
From Change 046, firewall rules weren't loading automatically on boot. After reboot, internet connectivity failed until firewall was manually restarted.
Solution Implemented:
1. Verified nftables Enabled:
bashsudo systemctl is-enabled nftables
# If disabled: sudo systemctl enable nftables
2. Created systemd Override:
bashsudo mkdir -p /etc/systemd/system/nftables.service.d/
sudo nano /etc/systemd/system/nftables.service.d/override.conf
Override contents:
ini[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
What This Does:

After=network-online.target: Don't start until network is fully online
Wants=network-online.target: Request network-online but don't fail if missing
ExecStartPre=/bin/sleep 5: Wait 5 seconds for VLAN interfaces to initialize
RemainAfterExit=yes: Keep service marked as active after rules load

3. Reloaded systemd:
bashsudo systemctl daemon-reload
4. Tested Reboot:
bashsudo reboot
Post-Reboot Verification (After 2-3 minutes):
bash# SSH back in after boot

# Check firewall loaded
sudo nft list ruleset | head -20
# Showed rules present - SUCCESS

# Check PM2 apps running
pm2 list
# Both portfolio and memecoin-tracker online - SUCCESS

# Check website accessible
curl http://10.0.20.1:3200  # Portfolio app responds
curl https://example.com   # Public site works

# From PC - internet access
ping 8.8.8.8  # SUCCESS - no manual firewall restart needed

# Check Suricata, fail2ban
sudo systemctl status suricata  # Active
sudo systemctl status fail2ban  # Active
All Services Auto-Started Successfully:

✅ nftables (firewall with all rules)
✅ PM2 (portfolio + memecoin-tracker apps)
✅ Nginx (reverse proxy)
✅ Suricata (IDS)
✅ fail2ban (IPS)
✅ Docker containers (Prometheus, Grafana, Uptime Kuma)
✅ DNS/DHCP (dnsmasq)

What I Learned:
systemd Service Dependencies Are Critical:
Services starting in the wrong order cause failures. Network services especially need careful dependency management:

nftables needs network interfaces to exist
VLANs need parent interface to be up
Applications need firewall rules applied

The After=network-online.target ensures the entire network stack is ready before firewall rules load. The 5-second delay gives VLAN subinterfaces extra time to initialize.
Testing Auto-Start is Essential:
Services that work when started manually might fail on boot due to:

Different environment variables
Missing dependencies
Timing issues
Service ordering

Always reboot and verify everything comes up correctly. This is production readiness testing.
Skills Demonstrated:

systemd service configuration
Understanding boot process and dependencies
System integration testing
Disaster recovery validation (system can recover from reboot)

Result: All services confirmed auto-starting on boot, firewall rules loading correctly, system production-ready for 24/7 operation

---

### Change 049 - Claude CLI Integration

**Date:** 1/23/2026  
**What:** Installed Claude CLI for AI-powered security analysis

**Installation:**
```bash
curl -O https://claude.ai/download/cli/linux-arm64
sudo install claude /usr/local/bin/
claude auth
```

**Purpose:** AI consultation for security decisions and analysis

**What I Learned:**
- AI tool integration
- Prompt engineering basics
- Privacy vs capability tradeoffs

**Skills Demonstrated:** AI integration, security-conscious tool adoption

**Result:** Claude CLI operational for security consultation


### Change 050 - Ollama Local AI Deployment

**Date:** 1/24/2026  
**What:** Deployed Ollama with qwen2.5:3b for private AI inference

**Installation:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b
```

**Model Selection:** qwen2.5:3b chosen for balance of size (2GB), performance (10-15 sec), and capability

**System Impact:**
- RAM: +2GB
- No interference with other services

**What I Learned:**
- Local AI deployment on constrained hardware
- Model selection based on capabilities
- Performance vs privacy tradeoffs

**Skills Demonstrated:** Local AI infrastructure, resource optimization, privacy-preserving architecture

**Result:** Ollama operational for private analysis, completing hybrid AI strategy

---

### Change 051 - Physical Infrastructure Documentation

**Date:** 1/30/2026  
**What:** Update documents and photographed physical setup

**Photos Added:**
- Rack overview
- Router Pi
- Switch connections
- Cable management

**Purpose:** Professional documentation for portfolio

**Skills Demonstrated:** Documentation practices, professional presentation

**Result:** Complete visual documentation added to repository

