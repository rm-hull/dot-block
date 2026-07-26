#!/bin/bash

# Quick DNS pathway tester for DoT server
# Usage: ./quick-dns-test.sh [num_tests]

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: ./quick-dns-test.sh [num_tests]"
    echo ""
    echo "Runs a quick DNS test against local DoT server."
    echo ""
    echo "Arguments:"
    echo "  num_tests    Number of test iterations (default: 10)"
    echo ""
    echo "Tests:"
    echo "  UDP  - Standard DNS over UDP on port 8053"
    echo "  TCP  - DNS over TCP on port 8053 (+tcp)"
    echo "  DoT  - DNS over TCP on port 8853 (dev mode)"
    exit 0
fi

NUM_TESTS=${1:-10}

# Validate num_tests is a number
if ! [[ "$NUM_TESTS" =~ ^[0-9]+$ ]]; then
    echo "Error: num_tests must be a positive integer"
    echo "Use --help for usage information"
    exit 1
fi
HOST="127.0.0.1"
PORT_UDP="8053"
PORT_TCP="8853"

SAMPLE_DOMAINS=(
    "www.google.com"
    "www.github.com"
    "www.cloudflare.com"
    "www.amazon.com"
    "api.github.com"
    "cdn.jsdelivr.net"
    "www.reddit.com"
    "www.spotify.com"
    "www.netflix.com"
    "www.microsoft.com"
)

echo "🔍 Quick DNS Pathway Test (${NUM_TESTS} iterations)"
echo "=================================================="
echo "UDP:  ${HOST}:${PORT_UDP}"
echo "TCP:  ${HOST}:${PORT_UDP} (+tcp)"
echo "DoT:  ${HOST}:${PORT_TCP} (+tcp)"
echo ""

success_udp=0
success_tcp=0
success_dot=0

for i in $(seq 1 $NUM_TESTS); do
    # Pick random domain
    domain=${SAMPLE_DOMAINS[$((RANDOM % ${#SAMPLE_DOMAINS[@]}))]}
    
    # UDP test
    if dig @${HOST} -p ${PORT_UDP} "${domain}" A +short > /dev/null 2>&1; then
        echo "✓ UDP:  ${domain}"
        ((success_udp++))
    else
        echo "✗ UDP:  ${domain} FAILED"
    fi
    
    # TCP test (regular DNS over TCP)
    if dig @${HOST} -p ${PORT_UDP} "${domain}" A +tcp +short > /dev/null 2>&1; then
        echo "✓ TCP:  ${domain}"
        ((success_tcp++))
    else
        echo "✗ TCP:  ${domain} FAILED"
    fi
    
    # DoT test (plain TCP on different port)
    if dig @${HOST} -p ${PORT_TCP} "${domain}" A +tcp +short > /dev/null 2>&1; then
        echo "✓ DoT:  ${domain}"
        ((success_dot++))
    else
        echo "✗ DoT:  ${domain} FAILED"
    fi
    
    echo ""
    sleep 0.05
done

echo "=================================================="
echo "Results:"
udp_pct=$((success_udp * 100 / NUM_TESTS))
tcp_pct=$((success_tcp * 100 / NUM_TESTS))
dot_pct=$((success_dot * 100 / NUM_TESTS))
echo "  UDP:  ${success_udp}/${NUM_TESTS} (${udp_pct}%)"
echo "  TCP:  ${success_tcp}/${NUM_TESTS} (${tcp_pct}%)"
echo "  DoT:  ${success_dot}/${NUM_TESTS} (${dot_pct}%)"