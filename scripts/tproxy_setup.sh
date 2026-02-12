#!/bin/bash
# TPROXY setup script for Linux
# This script configures iptables rules for transparent proxy using TPROXY

set -e

# Configuration
TPROXY_PORT=${TPROXY_PORT:-12345}
TPROXY_MARK=${TPROXY_MARK:-1}
ROUTING_TABLE=${ROUTING_TABLE:-100}
BYPASS_MARK=${BYPASS_MARK:-255}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root"
        exit 1
    fi
}

# Check required commands
check_commands() {
    local cmds="iptables ip"
    for cmd in $cmds; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is required but not installed"
            exit 1
        fi
    done
}

# Enable IP forwarding
enable_ip_forward() {
    log_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv4.conf.all.route_localnet=1 > /dev/null
    
    # For IPv6
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1 || true
}

# Setup routing table for TPROXY
setup_routing() {
    log_info "Setting up routing table ${ROUTING_TABLE}..."
    
    # Add routing rule for marked packets
    ip rule del fwmark ${TPROXY_MARK} lookup ${ROUTING_TABLE} 2>/dev/null || true
    ip rule add fwmark ${TPROXY_MARK} lookup ${ROUTING_TABLE}
    
    # Add local route for TPROXY
    ip route del local 0.0.0.0/0 dev lo table ${ROUTING_TABLE} 2>/dev/null || true
    ip route add local 0.0.0.0/0 dev lo table ${ROUTING_TABLE}
    
    log_info "Routing table configured"
}

# Setup iptables rules for TCP TPROXY
setup_tcp_tproxy() {
    log_info "Setting up TCP TPROXY rules..."
    
    # Create TPROXY chain
    iptables -t mangle -N NETPROXY_TPROXY 2>/dev/null || iptables -t mangle -F NETPROXY_TPROXY
    
    # Skip local traffic
    iptables -t mangle -A NETPROXY_TPROXY -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY -d 240.0.0.0/4 -j RETURN
    
    # Skip traffic from proxy itself (marked with BYPASS_MARK)
    iptables -t mangle -A NETPROXY_TPROXY -m mark --mark ${BYPASS_MARK} -j RETURN
    
    # TPROXY TCP traffic
    iptables -t mangle -A NETPROXY_TPROXY -p tcp -j TPROXY \
        --on-port ${TPROXY_PORT} \
        --on-ip 127.0.0.1 \
        --tproxy-mark ${TPROXY_MARK}
    
    # Apply to PREROUTING
    iptables -t mangle -D PREROUTING -j NETPROXY_TPROXY 2>/dev/null || true
    iptables -t mangle -A PREROUTING -j NETPROXY_TPROXY
    
    log_info "TCP TPROXY rules configured"
}

# Setup iptables rules for UDP TPROXY
setup_udp_tproxy() {
    log_info "Setting up UDP TPROXY rules..."
    
    # Create UDP TPROXY chain
    iptables -t mangle -N NETPROXY_TPROXY_UDP 2>/dev/null || iptables -t mangle -F NETPROXY_TPROXY_UDP
    
    # Skip local traffic
    iptables -t mangle -A NETPROXY_TPROXY_UDP -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY_UDP -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY_UDP -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY_UDP -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY_UDP -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A NETPROXY_TPROXY_UDP -d 240.0.0.0/4 -j RETURN
    
    # Skip traffic from proxy itself
    iptables -t mangle -A NETPROXY_TPROXY_UDP -m mark --mark ${BYPASS_MARK} -j RETURN
    
    # TPROXY UDP traffic
    iptables -t mangle -A NETPROXY_TPROXY_UDP -p udp -j TPROXY \
        --on-port ${TPROXY_PORT} \
        --on-ip 127.0.0.1 \
        --tproxy-mark ${TPROXY_MARK}
    
    # Apply to PREROUTING
    iptables -t mangle -D PREROUTING -j NETPROXY_TPROXY_UDP 2>/dev/null || true
    iptables -t mangle -A PREROUTING -j NETPROXY_TPROXY_UDP
    
    log_info "UDP TPROXY rules configured"
}

# Setup OUTPUT chain for local traffic
setup_output_redirect() {
    log_info "Setting up OUTPUT redirect rules..."
    
    # Create OUTPUT chain
    iptables -t mangle -N NETPROXY_OUTPUT 2>/dev/null || iptables -t mangle -F NETPROXY_OUTPUT
    
    # Skip local traffic
    iptables -t mangle -A NETPROXY_OUTPUT -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A NETPROXY_OUTPUT -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A NETPROXY_OUTPUT -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A NETPROXY_OUTPUT -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A NETPROXY_OUTPUT -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A NETPROXY_OUTPUT -d 240.0.0.0/4 -j RETURN
    
    # Skip traffic from proxy itself
    iptables -t mangle -A NETPROXY_OUTPUT -m mark --mark ${BYPASS_MARK} -j RETURN
    
    # Mark packets for rerouting
    iptables -t mangle -A NETPROXY_OUTPUT -p tcp -j MARK --set-mark ${TPROXY_MARK}
    iptables -t mangle -A NETPROXY_OUTPUT -p udp -j MARK --set-mark ${TPROXY_MARK}
    
    # Apply to OUTPUT
    iptables -t mangle -D OUTPUT -j NETPROXY_OUTPUT 2>/dev/null || true
    iptables -t mangle -A OUTPUT -j NETPROXY_OUTPUT
    
    log_info "OUTPUT redirect rules configured"
}

# Clean up all rules
cleanup() {
    log_info "Cleaning up TPROXY rules..."
    
    # Remove from PREROUTING
    iptables -t mangle -D PREROUTING -j NETPROXY_TPROXY 2>/dev/null || true
    iptables -t mangle -D PREROUTING -j NETPROXY_TPROXY_UDP 2>/dev/null || true
    iptables -t mangle -D OUTPUT -j NETPROXY_OUTPUT 2>/dev/null || true
    
    # Flush and delete chains
    iptables -t mangle -F NETPROXY_TPROXY 2>/dev/null || true
    iptables -t mangle -X NETPROXY_TPROXY 2>/dev/null || true
    iptables -t mangle -F NETPROXY_TPROXY_UDP 2>/dev/null || true
    iptables -t mangle -X NETPROXY_TPROXY_UDP 2>/dev/null || true
    iptables -t mangle -F NETPROXY_OUTPUT 2>/dev/null || true
    iptables -t mangle -X NETPROXY_OUTPUT 2>/dev/null || true
    
    # Remove routing rules
    ip rule del fwmark ${TPROXY_MARK} lookup ${ROUTING_TABLE} 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table ${ROUTING_TABLE} 2>/dev/null || true
    
    log_info "Cleanup completed"
}

# Show current status
status() {
    echo "=== TPROXY Configuration Status ==="
    echo ""
    echo "Routing Rules:"
    ip rule list | grep -E "fwmark.*lookup ${ROUTING_TABLE}" || echo "  No TPROXY routing rules found"
    echo ""
    echo "Routing Table ${ROUTING_TABLE}:"
    ip route show table ${ROUTING_TABLE} 2>/dev/null || echo "  Table not found"
    echo ""
    echo "iptables mangle PREROUTING:"
    iptables -t mangle -L PREROUTING -n -v 2>/dev/null | head -20
    echo ""
    echo "NETPROXY_TPROXY chain:"
    iptables -t mangle -L NETPROXY_TPROXY -n -v 2>/dev/null || echo "  Chain not found"
}

# Print usage
usage() {
    echo "Usage: $0 {setup|cleanup|status}"
    echo ""
    echo "Commands:"
    echo "  setup   - Configure TPROXY rules"
    echo "  cleanup - Remove all TPROXY rules"
    echo "  status  - Show current configuration"
    echo ""
    echo "Environment Variables:"
    echo "  TPROXY_PORT    - TPROXY listening port (default: 12345)"
    echo "  TPROXY_MARK    - Packet mark for TPROXY (default: 1)"
    echo "  ROUTING_TABLE  - Routing table number (default: 100)"
    echo "  BYPASS_MARK    - Mark for bypassing proxy (default: 255)"
}

# Main
main() {
    check_root
    check_commands
    
    case "$1" in
        setup)
            enable_ip_forward
            setup_routing
            setup_tcp_tproxy
            setup_udp_tproxy
            setup_output_redirect
            log_info "TPROXY setup completed successfully"
            log_info "Proxy should listen on 127.0.0.1:${TPROXY_PORT}"
            ;;
        cleanup)
            cleanup
            ;;
        status)
            status
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
