#!/bin/bash
# Create a TAP device for libkrun net-tap testing
# Run with: sudo ./create_tap.sh
#
# This script:
# 1. Creates a persistent TAP device owned by the calling user
# 2. Configures IP address (10.0.0.1/24)
# 3. Sets up NAT/masquerading for internet access from guest

set -e

TAP_NAME="${1:-tap0}"
TAP_IP="10.0.0.1"
TAP_NETWORK="10.0.0.0/24"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run with sudo"
    exit 1
fi

if [ -z "$SUDO_USER" ]; then
    echo "Please run with sudo (not as root directly)"
    exit 1
fi

# Check if tap already exists
if ip link show "$TAP_NAME" &>/dev/null; then
    read -p "TAP device '$TAP_NAME' already exists. Delete and recreate? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing $TAP_NAME..."
        ip link delete "$TAP_NAME"
    else
        echo "Aborting."
        exit 1
    fi
fi

echo "Creating TAP device '$TAP_NAME' for user '$SUDO_USER'..."
ip tuntap add dev "$TAP_NAME" mode tap user "$SUDO_USER" vnet_hdr

echo "Configuring IP address $TAP_IP/24..."
ip addr add "$TAP_IP/24" dev "$TAP_NAME"
ip link set "$TAP_NAME" up

echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Find the default outgoing interface
DEFAULT_IF=$(ip route show default | awk '/default/ {print $5}' | head -1)
if [ -z "$DEFAULT_IF" ]; then
    echo "Warning: Could not determine default interface for masquerading"
else
    echo "Setting up NAT/masquerading via $DEFAULT_IF..."
    # Remove old rule if exists (ignore errors)
    iptables -t nat -D POSTROUTING -s "$TAP_NETWORK" -o "$DEFAULT_IF" -j MASQUERADE 2>/dev/null || true
    # Add new rule
    iptables -t nat -A POSTROUTING -s "$TAP_NETWORK" -o "$DEFAULT_IF" -j MASQUERADE
fi

echo ""
echo "Done! TAP device '$TAP_NAME' is ready."
echo ""
echo "Host:  $TAP_IP"
echo "Guest: Configure with 10.0.0.2/24, gateway $TAP_IP"
echo ""
echo "To run the test:"
echo "  KRUN_NO_UNSHARE=1 LIBKRUN_TAP_NAME=$TAP_NAME make test NET=1 TEST=net-tap"
echo ""
echo "Note: KRUN_NO_UNSHARE=1 is required because the TAP device is in the host"
echo "network namespace, not the test's isolated namespace."
