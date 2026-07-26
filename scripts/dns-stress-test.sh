#!/bin/bash

# DNS Server Stress Test Script
# Exercises UDP, TCP, and DoH pathways against local DoT server

SETUP=${1:-"https://raw.githubusercontent.com/lIONKn/dnsDomains/master/domains_publish.txt"}
DOMAINS_FILE="/tmp/dns-test-domains.txt"
LOCAL_DNS_HOST="127.0.0.1"
LOCAL_DNS_PORT_UDP="8053"
LOCAL_DNS_PORT_TCP="8053"
LOCAL_DNS_PORT_DOT="8853"
DOH_ENDPOINT="http://${LOCAL_DNS_HOST}:80/dns-query"

# Alternative: use a hardcoded list of common domains
HARDCODED_DOMAINS=(
    "www.google.com"
    "www.github.com"
    "www.cloudflare.com"
    "www.amazon.com"
    "www.microsoft.com"
    "www.apple.com"
    "www.netflix.com"
    "www.spotify.com"
    "www.youtube.com"
    "www.twitter.com"
    "www.reddit.com"
    "www.stackoverflow.com"
    "www.wikipedia.org"
    "www.linkedin.com"
    "www.facebook.com"
    "api.openai.com"
    "cdn.jsdelivr.net"
    "www.npmjs.com"
    "docs.docker.com"
    "www.python.org"
    "www.reactjs.org"
    "www.nodejs.org"
    "www.golang.org"
    "www.rust-lang.org"
    "www.typescriptlang.org"
    "www.swift.org"
    "www.kotlinlang.org"
    "www.java.com"
    "www.oracle.com"
    "www.adobe.com"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Domain list (fallback if we can't fetch)
DEFAULT_DOMAINS=(
    "www.google.com"
    "www.github.com"
    "www.cloudflare.com"
    "www.amazon.com"
    "www.microsoft.com"
    "www.apple.com"
    "www.netflix.com"
    "www.spotify.com"
    "www.youtube.com"
    "www.twitter.com"
    "www.reddit.com"
    "www.stackoverflow.com"
    "www.wikipedia.org"
    "www.linkedin.com"
    "www.facebook.com"
    "api.openai.com"
    "cdn.jsdelivr.net"
    "www.npmjs.com"
    "docs.docker.com"
    "www.python.org"
)

echo "🔍 DNS Server Stress Test"
echo "========================"
echo "Target: ${LOCAL_DNS_HOST}:${LOCAL_DNS_PORT_UDP} (UDP/TCP)"
echo "Target: ${LOCAL_DNS_HOST}:${LOCAL_DNS_PORT_DOT} (DoT)"
echo "Target: ${DOH_ENDPOINT} (DoH)"
echo ""

# Function to fetch domain list
fetch_domains() {
    echo "📥 Fetching domain list from ${SETUP}..."
    local http_code
    http_code=$(curl -s -o "${DOMAINS_FILE}" -w "%{http_code}" "${SETUP}")
    if [[ "${http_code}" -eq 200 && -s "${DOMAINS_FILE}" ]]; then
        local count=$(wc -l < "${DOMAINS_FILE}")
        echo "✅ Loaded ${count} domains"
    else
        echo "⚠️  Failed to fetch domain list (HTTP ${http_code}), using fallback list (${#DEFAULT_DOMAINS[@]} domains)"
        printf '%s\n' "${DEFAULT_DOMAINS[@]}" > "${DOMAINS_FILE}"
    fi
}

# Function to get random domain
get_random_domain() {
    local total_lines=$(wc -l < "${DOMAINS_FILE}")
    local random_line=$((RANDOM % total_lines + 1))
    sed -n "${random_line}p" "${DOMAINS_FILE}" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Function to perform UDP DNS lookup
test_udp() {
    local domain=$1
    local start_time=$(date +%s%N)
    
    dig @${LOCAL_DNS_HOST} -p ${LOCAL_DNS_PORT_UDP} "${domain}" A +short > /dev/null 2>&1
    local status=$?
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 )) # Convert to ms
    
    if [ $status -eq 0 ]; then
        echo -e "${GREEN}✓ UDP${NC} | ${domain} | ${duration}ms"
    else
        echo -e "${RED}✗ UDP${NC} | ${domain} | ${duration}ms | exit code: ${status}"
    fi
}

# Function to perform TCP DNS lookup
test_tcp() {
    local domain=$1
    local start_time=$(date +%s%N)
    
    dig @${LOCAL_DNS_HOST} -p ${LOCAL_DNS_PORT_TCP} "${domain}" A +tcp +short > /dev/null 2>&1
    local status=$?
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    if [ $status -eq 0 ]; then
        echo -e "${GREEN}✓ TCP${NC} | ${domain} | ${duration}ms"
    else
        echo -e "${RED}✗ TCP${NC} | ${domain} | ${duration}ms | exit code: ${status}"
    fi
}

# Function to perform DoH lookup
test_doh() {
    local domain=$1
    local start_time=$(date +%s%N)
    
    # Encode domain for DNS query parameter
    local response=$(curl -s -H "accept: application/dns-message" \
        "${DOH_ENDPOINT}?dns=$(echo -n "${domain}" | base64 | tr '+/' '-_' | tr -d '=')" 2>/dev/null)
    
    local status=$?
    
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    if [ $status -eq 0 ] && [ -n "$response" ]; then
        echo -e "${GREEN}✓ DoH${NC} | ${domain} | ${duration}ms"
    else
        echo -e "${RED}✗ DoH${NC} | ${domain} | ${duration}ms | exit code: ${status}"
    fi
}

# Check if domains file exists, if not fetch it
if [ ! -f "${DOMAINS_FILE}" ]; then
    fetch_domains
fi

echo ""
echo "🚀 Starting DNS stress test..."
echo "Press Ctrl+C to stop"
echo ""

# Main loop
cycle=1
total_udp=0
total_tcp=0
total_doh=0
success_udp=0
success_tcp=0
success_doh=0

while true; do
    domain=$(get_random_domain)
    
    if [ -z "$domain" ]; then
        echo "⚠️  No domain found, skipping"
        continue
    fi
    
    echo "--- Cycle ${cycle} | Domain: ${domain} ---"
    
    # Test UDP
    test_udp "$domain"
    ((total_udp++))
    [ $? -eq 0 ] && ((success_udp++))
    
    sleep 0.1
    
    # Test TCP
    test_tcp "$domain"
    ((total_tcp++))
    [ $? -eq 0 ] && ((success_tcp++))
    
    sleep 0.1
    
    # Test DoH
    test_doh "$domain"
    ((total_doh++))
    [ $? -eq 0 ] && ((success_doh++))
    
    echo ""
    ((cycle++))
    
    # Print periodic summary every 10 cycles
    if [ $((cycle % 10)) -eq 0 ]; then
        udp_pct=$((success_udp * 100 / total_udp))
        tcp_pct=$((success_tcp * 100 / total_tcp))
        doh_pct=$((success_doh * 100 / total_doh))
        echo "📊 Summary so far:"
        echo "   UDP: ${success_udp}/${total_udp} (${udp_pct}%)"
        echo "   TCP: ${success_tcp}/${total_tcp} (${tcp_pct}%)"
        echo "   DoH: ${success_doh}/${total_doh} (${doh_pct}%)"
        echo ""
    fi
done