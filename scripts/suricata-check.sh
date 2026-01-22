#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        🛡️  SURICATA SECURITY REPORT 🛡️           ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo ""

# Check if Suricata is running
STATUS=$(systemctl is-active suricata)
if [ "$STATUS" = "active" ]; then
    echo -e "${GREEN}✓ Suricata Status: RUNNING${NC}"
else
    echo -e "${RED}✗ Suricata Status: STOPPED${NC}"
    exit 1
fi
echo ""

# Count alerts from today
TODAY=$(date +%m/%d/%Y)
TOTAL_ALERTS=$(grep -c "$TODAY" /var/log/suricata/fast.log 2>/dev/null || echo "0")

# Count REAL threats (not TCP noise)
REAL_THREATS=$(grep "$TODAY" /var/log/suricata/fast.log 2>/dev/null | \
    grep -v "SURICATA STREAM" | \
    grep -v "ET INFO" | \
    grep -Ec "ET EXPLOIT|ET ATTACK|ET MALWARE|ET SCAN" || echo "0")

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}📊 ALERT SUMMARY${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Total Alerts Today: $TOTAL_ALERTS"
echo -e "Critical Threats:   ${RED}$REAL_THREATS${NC}"
echo ""

# Threat assessment
if [ "$REAL_THREATS" -eq 0 ]; then
    echo -e "${GREEN}✓ SECURITY STATUS: ALL CLEAR${NC}"
    echo -e "${GREEN}  No active threats detected${NC}"
elif [ "$REAL_THREATS" -lt 5 ]; then
    echo -e "${YELLOW}⚠ SECURITY STATUS: LOW RISK${NC}"
    echo -e "${YELLOW}  Minor suspicious activity detected${NC}"
elif [ "$REAL_THREATS" -lt 20 ]; then
    echo -e "${YELLOW}⚠ SECURITY STATUS: MODERATE RISK${NC}"
    echo -e "${YELLOW}  Investigation recommended${NC}"
else
    echo -e "${RED}✗ SECURITY STATUS: HIGH RISK${NC}"
    echo -e "${RED}  Active attack detected - take action!${NC}"
fi
echo ""

# Show recent REAL threats (not TCP noise)
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}🎯 RECENT THREATS (Last 10)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

THREATS=$(grep "$TODAY" /var/log/suricata/fast.log 2>/dev/null | \
    grep -v "SURICATA STREAM" | \
    grep -v "ET INFO" | \
    grep -E "ET EXPLOIT|ET ATTACK|ET MALWARE|ET SCAN" | \
    tail -10)

if [ -z "$THREATS" ]; then
    echo -e "${GREEN}No threats detected today ✓${NC}"
else
    echo "$THREATS" | while read line; do
        if echo "$line" | grep -q "ET EXPLOIT"; then
            echo -e "${RED}[EXPLOIT] $line${NC}"
        elif echo "$line" | grep -q "ET MALWARE"; then
            echo -e "${RED}[MALWARE] $line${NC}"
        elif echo "$line" | grep -q "ET SCAN"; then
            echo -e "${YELLOW}[SCAN] $line${NC}"
        else
            echo "$line"
        fi
    done
fi
echo ""

# Top attacking IPs
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}🌐 TOP SOURCE IPs (Last 24h)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

grep "$TODAY" /var/log/suricata/fast.log 2>/dev/null | \
    grep -v "SURICATA STREAM" | \
    awk '{print $NF}' | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | head -5 | \
    while read count ip; do
        # Check if IP is external (not 192.168.x.x or 10.x.x.x)
        if ! echo "$ip" | grep -qE '^(192\.168|10\.)'; then
            if [ "$count" -gt 10 ]; then
                echo -e "${RED}  $count alerts - $ip ${NC} ⚠️  SUSPICIOUS"
            elif [ "$count" -gt 5 ]; then
                echo -e "${YELLOW}  $count alerts - $ip${NC}"
            else
                echo "  $count alerts - $ip"
            fi
        else
            echo "  $count alerts - $ip (internal)"
        fi
    done

if [ -z "$(grep "$TODAY" /var/log/suricata/fast.log 2>/dev/null)" ]; then
    echo "No external IPs detected"
fi
echo ""

# Check fail2ban status
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}🔒 FAIL2BAN PROTECTION${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BANNED=$(sudo fail2ban-client status 2>/dev/null | grep "Currently banned" | awk '{print $4}')
echo "Currently Banned IPs: ${BANNED:-0}"

# Show banned IPs
for jail in sshd nginx-http-auth nginx-limit-req; do
    JAIL_BANNED=$(sudo fail2ban-client status $jail 2>/dev/null | grep "Currently banned" | awk '{print $4}')
    if [ "$JAIL_BANNED" != "0" ] && [ -n "$JAIL_BANNED" ]; then
        echo -e "${YELLOW}  [$jail] $JAIL_BANNED banned${NC}"
        sudo fail2ban-client status $jail 2>/dev/null | grep "Banned IP" | sed 's/^/    /'
    fi
done
echo ""

# Recommendations
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}💡 RECOMMENDATIONS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$REAL_THREATS" -eq 0 ]; then
    echo -e "${GREEN}✓ System is secure - no action needed${NC}"
elif [ "$REAL_THREATS" -lt 5 ]; then
    echo -e "${YELLOW}→ Monitor logs: sudo tail -f /var/log/suricata/fast.log${NC}"
    echo -e "${YELLOW}→ Check fail2ban: sudo fail2ban-client status${NC}"
else
    echo -e "${RED}→ INVESTIGATE IMMEDIATELY${NC}"
    echo -e "${RED}→ Check Nginx logs: sudo tail -50 /var/log/nginx/access.log${NC}"
    echo -e "${RED}→ Review banned IPs: sudo fail2ban-client status${NC}"
    echo -e "${RED}→ Consider blocking source countries in firewall${NC}"
fi
echo ""

echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}  Report generated: $(date)${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"