#!/bin/bash

echo "╔════════════════════════════════════════════════════╗"
echo "║           DAILY SECURITY CHECK                     ║"
echo "╔════════════════════════════════════════════════════╗"
echo ""

# Suricata threats
echo "━━━ SURICATA THREATS ━━━"
./suricata-check.sh
echo ""

# fail2ban status
echo "━━━ FAIL2BAN STATUS ━━━"
sudo fail2ban-client status
echo ""

# Nginx attack count today
echo "━━━ NGINX ATTACKS TODAY ━━━"
TODAY=$(date +%d/%b/%Y)
ATTACK_COUNT=$(sudo grep "$TODAY" /var/log/nginx/access.log | grep -E "404|400|403" | wc -l)
echo "Total blocked requests today: $ATTACK_COUNT"
echo ""

# System load
echo "━━━ SYSTEM LOAD ━━━"
uptime
echo ""

# Service status
echo "━━━ SERVICE STATUS ━━━"
systemctl is-active nginx && echo "✓ Nginx: Running" || echo "✗ Nginx: Down"
systemctl is-active suricata && echo "✓ Suricata: Running" || echo "✗ Suricata: Down"
systemctl is-active fail2ban && echo "✓ fail2ban: Running" || echo "✗ fail2ban: Down"
echo ""

# PM2 apps
echo "━━━ PM2 APPLICATIONS ━━━"
pm2 list
echo ""

# Docker containers
echo "━━━ DOCKER CONTAINERS ━━━"
docker ps --format "table {{.Names}}\t{{.Status}}"
echo ""

echo "╚════════════════════════════════════════════════════╝"