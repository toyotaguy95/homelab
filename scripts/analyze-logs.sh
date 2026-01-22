#!/bin/bash

# Lab Log Analysis Script

echo "=== SSH Failed Login Attempts ==="
sudo grep "Failed password" /var/log/lab/ssh-auth.log | tail -10

echo ""
echo "=== Top 10 Blocked IPs (Firewall) ==="
sudo grep "INPUT-DROP:" /var/log/lab/firewall-input.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== fail2ban Bans (Last 24 Hours) ==="
sudo grep "Ban" /var/log/lab/fail2ban-activity.log | grep "$(date +%Y-%m-%d)"

echo ""
echo "=== DHCP Leases Issued Today ==="
sudo grep "DHCPACK" /var/log/lab/dnsmasq.log | grep "$(date +%b\ %e)"

echo ""
echo "=== Firewall Forward Drops (Inter-VLAN Blocks) ==="
sudo tail -20 /var/log/lab/firewall-forward.log