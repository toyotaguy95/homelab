# Enterprise-Grade Homelab Infrastructure

A production-ready homelab environment built on Raspberry Pi 5, demonstrating enterprise networking principles, security hardening, and comprehensive monitoring systems.

🌐 **Live Demo:** [Portfolio Website](https://example.com) *(Replace with your actual site when sharing with employers)*

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Network Design](#network-design)
- [Security Implementation](#security-implementation)
- [Monitoring & Observability](#monitoring--observability)
- [Key Achievements](#key-achievements)
- [Documentation](#documentation)

---

## 🎯 Overview

This project showcases a fully functional homelab that mirrors enterprise network architecture and security practices. Built from scratch with a focus on proper network segmentation, defense-in-depth security, and production-grade monitoring.

**Project Duration:** 12/30/2025 - 1/20/2026  
**Status:** Production (24/7 uptime)

---

## 🏗️ Architecture

### Network Topology

![Physical Topology](evidence/diagrams/01-physical-topology.png)

![VLAN Logical Topology](evidence/diagrams/02-vlan-logical-topology.png)

### Security Architecture

![Security Architecture](evidence/diagrams/03-security-architecture.png)

### Traffic Flow

![Website Traffic Flow](evidence/diagrams/04-website-traffic-flow.png)

---

## 💻 Technologies Used

### Infrastructure
- **Router:** Raspberry Pi 4b (8GB RAM) - Router-on-a-Stick
- **Switch:** TP-Link TL-SG108E (Managed, 802.1Q VLAN Support)
- **OS:** Ubuntu Server 24.04 LTS (64-bit ARM)

### Networking
- **VLANs:** 802.1Q trunking with 4 isolated networks
- **Routing:** Linux kernel routing with nftables firewall
- **DHCP/DNS:** dnsmasq with per-VLAN scopes
- **Domain:** Public DNS with Let's Encrypt SSL

### Security
- **Firewall:** nftables (zone-based policies)
- **IDS:** Suricata with Emerging Threats ruleset
- **IPS:** fail2ban (SSH + Nginx protection)
- **Web Security:** Nginx reverse proxy with rate limiting, bot blocking, security headers

### Monitoring
- **Metrics:** Prometheus + Node Exporter
- **Visualization:** Grafana dashboards
- **Service Monitoring:** Uptime Kuma
- **Logging:** Centralized rsyslog with rotation

### Web Services
- **Reverse Proxy:** Nginx with SSL/TLS termination
- **SSL Certificates:** Let's Encrypt (auto-renewal)
- **Applications:** Node.js (Express) with PM2 process management
- **Containerization:** Docker for isolated service deployment

---

## 🌐 Network Design

### VLAN Segmentation

| VLAN | Name | Network | Purpose |
|------|------|---------|---------|
| 10 | Management | 10.0.10.0/24 | Admin access, monitoring tools, infrastructure services, development/testing environment |
| 20 | Server (DMZ) | 10.0.20.0/24 | Public-facing services, isolated from management, production environment|
| 30 | Client | 10.0.30.0/24 | Personal devices, internet-only access |
| 40 | IoT/Dev | 10.0.40.0/24 | IoT devices |

### Router-on-a-Stick Configuration

The Raspberry Pi acts as the central router with VLAN subinterfaces:
- `eth0` - Upstream connection (ISP gateway)
- `eth0.10` - MGMT VLAN (10.0.10.1/24)
- `eth0.20` - SRV VLAN (10.0.20.1/24)
- `eth0.30` - CLIENT VLAN (10.0.30.1/24)
- `eth0.40` - IOT VLAN (10.0.40.1/24)

All inter-VLAN routing enforced through nftables firewall rules.

---

## 🔒 Security Implementation

### Defense in Depth (6 Layers)

1. **ISP Gateway Firewall** - Only ports 80/443 forwarded
2. **nftables Firewall** - Stateful packet filtering on all interfaces
3. **Suricata IDS** - Real-time threat detection across 5 interfaces
4. **fail2ban IPS** - Automated IP banning for repeated attacks
5. **Nginx Security** - Application-level protection (rate limiting, bot blocking)
6. **VLAN Isolation** - DMZ architecture prevents lateral movement

### DMZ Architecture

Public services isolated in Server VLAN (10.0.20.0/24):
- Internet users → Nginx (MGMT VLAN) → Firewall rule → App (SRV VLAN)
- If compromised, attacker trapped in DMZ
- Cannot access management tools, SSH, or other VLANs
- Demonstrates zero-trust security principles

### Firewall Rules Summary

**INPUT Chain (Traffic to Router):**
- SSH (22): MGMT VLAN only
- Web UIs (3000, 3001, 9090): MGMT VLAN only
- DHCP/DNS (53, 67): All VLANs
- HTTP/HTTPS (80, 443): Internet (public services)

**FORWARD Chain (Inter-VLAN Routing):**
- MGMT → All VLANs (management access)
- MGMT → SRV port 3200 only (Nginx reverse proxy)
- All VLANs → Internet (NAT)
- Default: DENY (least-privilege)

---

## 📊 Monitoring & Observability

### Metrics Collection
- **Prometheus** scrapes system metrics every 15 seconds
- **Node Exporter** exposes CPU, memory, disk, network stats
- **Per-VLAN traffic monitoring** via interface-specific metrics
- **15-day retention** for historical analysis

### Dashboards
- **Grafana:** "Node Exporter Full" dashboard (ID: 1860)
  - Real-time CPU usage per core
  - Memory usage with breakdown (used/cached/available)
  - Network traffic per VLAN interface
  - Disk I/O rates and filesystem usage

### Service Health
- **Uptime Kuma** monitors:
  - VLAN gateways (ping checks)
  - Internet connectivity
  - DNS resolution
  - SSH service
  - Web services (HTTP checks)

### Security Monitoring
- **Suricata** generates alerts for:
  - Port scans
  - Exploit attempts
  - Malware communication
  - Protocol violations
- **fail2ban** automatically bans IPs after repeated attacks
- **Custom script** (`suricata-check.sh`) provides daily threat summaries

### Logging
- Centralized logging in `/var/log/lab/`
- 7-day retention with compression
- Logs: firewall drops, SSH auth, DHCP leases, fail2ban activity
- Analysis script for quick incident review

---

## 🏆 Key Achievements

### Network Engineering
- ✅ Designed and implemented 4-VLAN segmented network
- ✅ Configured 802.1Q trunking and VLAN tagging
- ✅ Built router-on-a-stick architecture
- ✅ Implemented NAT with proper routing tables
- ✅ Deployed authoritative DNS with public domain

### Security
- ✅ Deployed multi-layer security (firewall, IDS, IPS)
- ✅ Implemented DMZ architecture for public services
- ✅ Hardened web server with security headers and rate limiting
- ✅ Achieved zero-trust network design (least-privilege access)
- ✅ Detected and blocked real-world attacks (Suricata logged 7 exploit attempts)

### DevOps/SRE
- ✅ Set up production monitoring stack (Prometheus/Grafana)
- ✅ Automated backups with 5-day retention
- ✅ Implemented configuration management and version control
- ✅ Created runbooks for common incident scenarios
- ✅ Deployed containerized services with Docker

### Web Development
- ✅ Built production website with HTTPS (Let's Encrypt)
- ✅ Configured Nginx reverse proxy with SSL termination
- ✅ Implemented Node.js applications with PM2 process management
- ✅ Integrated external APIs (CoinGecko for live crypto prices)
- ✅ Achieved 24/7 uptime with auto-restart on failures

### Physical Infrastructure
- ✅ Installed 12-port patch panel for professional cable management
- ✅ Ran structured cabling (Cat5e) through walls
- ✅ Installed wall jacks in multiple rooms
- ✅ Documented with T568B wiring standard

---

## 📚 Documentation

### Complete Build Log
See [BuildLog.md](BuildLog.md) for detailed change history with 48 documented changes including:
- Configuration decisions and rationale
- Troubleshooting steps for issues encountered
- Testing and validation procedures
- Lessons learned and skills gained
- There are also runbooks

### Configuration Files
Sample configurations in [`configs/`](configs/) directory:
- Nginx reverse proxy setup
- nftables firewall rules
- dnsmasq DHCP/DNS configuration
- Netplan network interface definitions

### Scripts
Automation scripts in [`scripts/`](scripts/) directory:
- `backup-configs.sh` - Automated daily backups
- `suricata-check.sh` - Security threat analysis
- `analyze-logs.sh` - Centralized log review

### Network Diagrams
Visual architecture diagrams in [`evidence/diagrams/`](evidence/diagrams/):
- Physical topology
- VLAN logical topology
- Security architecture
- Website traffic flow

---

## 🎓 Skills Demonstrated

**Networking:**
- VLAN configuration and 802.1Q trunking
- Routing and subnetting (CIDR notation)
- NAT and port forwarding
- DNS (authoritative and recursive)
- DHCP server configuration

**Linux System Administration:**
- Ubuntu Server deployment and hardening
- systemd service management
- Package management and updates
- User/permission management
- Cron job scheduling

**Security:**
- Firewall design (nftables)
- Intrusion Detection Systems (Suricata)
- Intrusion Prevention Systems (fail2ban)
- SSL/TLS certificate management
- Defense-in-depth architecture

**Monitoring & Observability:**
- Prometheus metrics collection
- Grafana dashboard creation
- Log aggregation and analysis
- Service health monitoring

**DevOps:**
- Docker containerization
- Process management (PM2)
- Automated backups
- Configuration as code
- Version control (Git)

**Web Development:**
- Nginx reverse proxy configuration
- Node.js/Express applications
- RESTful API integration
- Frontend development (HTML/CSS/JavaScript)

---

## 📧 Contact

For questions about this project or to discuss opportunities:

**GitHub:** toyotaguy95  
**LinkedIn:** www.linkedin.com/in/yipinvestmentsllc  
**Email:** yipinvestmentsllc@gmail.com

---

## 📄 License

This project documentation is provided as-is for educational and portfolio purposes.

---

*Last Updated: January 2026*
