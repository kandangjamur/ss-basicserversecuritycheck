#!/bin/bash

# Quick Security Check Script
# Performs basic security verification

echo "🔒 Quick Security Check Script"
echo "=============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_pass() {
    echo -e "[${GREEN}PASS${NC}] $1"
}

check_fail() {
    echo -e "[${RED}FAIL${NC}] $1"
}

check_warn() {
    echo -e "[${YELLOW}WARN${NC}] $1"
}

# SSH Security Checks
echo -e "\n📡 SSH Security Checks"
echo "----------------------"

# Check if password authentication is disabled
if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    check_pass "SSH password authentication is disabled"
else
    check_fail "SSH password authentication is not disabled"
fi

# Check if root login is disabled
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
    check_pass "SSH root login is disabled"
else
    check_fail "SSH root login is not disabled"
fi

# System Security Checks
echo -e "\n🛡️  System Security Checks"
echo "-------------------------"

# Check fail2ban
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    check_pass "Fail2ban is active"
else
    check_fail "Fail2ban is not active"
fi

# Check ClamAV
if command -v clamscan &> /dev/null; then
    check_pass "ClamAV is installed"
else
    check_fail "ClamAV is not installed"
fi

# Check open ports
echo -e "\n🌐 Network Security Checks"
echo "-------------------------"

PUBLIC_PORTS=$(netstat -tuln 2>/dev/null | grep "0.0.0.0:" | awk '{print $4}' | cut -d: -f2 | sort -n | uniq)
NECESSARY_PORTS="22 80 443"

for port in $PUBLIC_PORTS; do
    if echo "$NECESSARY_PORTS" | grep -wq "$port"; then
        check_pass "Port $port is open (necessary)"
    else
        check_warn "Port $port is open (review if necessary)"
    fi
done

echo -e "\n✅ Quick check completed. Run the full Python tool for detailed analysis."
