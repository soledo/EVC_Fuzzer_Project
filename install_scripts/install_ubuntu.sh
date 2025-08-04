#!/bin/bash
# Ubuntu/Debian Installation Script for EVC Fuzzing Project
# Tested on: Ubuntu 20.04, 22.04, Debian 11, 12

set -e  # Exit on error

echo "=== EVC Fuzzing Project - Ubuntu/Debian Installation ==="
echo "This script will install all required dependencies."
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "Warning: Running as root. Consider running as regular user with sudo."
fi

# Function to check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print colored output
print_status() {
    echo -e "\033[1;34m[*]\033[0m $1"
}

print_success() {
    echo -e "\033[1;32m[✓]\033[0m $1"
}

print_error() {
    echo -e "\033[1;31m[✗]\033[0m $1"
}

# Update system
print_status "Updating package lists..."
sudo apt update

# Install system dependencies
print_status "Installing system dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    openjdk-11-jre \
    git \
    net-tools \
    iputils-ping \
    tcpdump \
    wireshark \
    build-essential \
    libssl-dev \
    libffi-dev

# Check Python version
print_status "Checking Python version..."
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then 
    print_success "Python $python_version meets minimum requirement ($required_version)"
else
    print_error "Python $python_version does not meet minimum requirement ($required_version)"
    exit 1
fi

# Check Java installation
print_status "Verifying Java installation..."
if command_exists java; then
    java_version=$(java -version 2>&1 | head -n 1)
    print_success "Java installed: $java_version"
else
    print_error "Java installation failed"
    exit 1
fi

# Install Python packages
print_status "Installing Python dependencies..."
cd ..
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    print_success "Python packages installed"
else
    print_error "requirements.txt not found in parent directory"
    exit 1
fi

# Configure IPv6
print_status "Checking IPv6 configuration..."
ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
if [ "$ipv6_disabled" -eq 0 ]; then
    print_success "IPv6 is enabled"
else
    print_status "Enabling IPv6..."
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
    print_success "IPv6 enabled"
fi

# Test virtual interface creation
print_status "Testing virtual interface support..."
if sudo ip link add test-veth type veth peer name test-veth-peer 2>/dev/null; then
    sudo ip link delete test-veth 2>/dev/null
    print_success "Virtual interface support verified"
else
    print_error "Virtual interface creation failed. Kernel module 'veth' may not be loaded."
fi

# Create useful aliases
print_status "Setting up convenience aliases..."
cat >> ~/.bashrc << 'EOF'

# EVC Fuzzing Project aliases
alias evc-sim='cd ~/EVC_Fuzzing_Project/EVC_Simulator'
alias evc-fuzz='cd ~/EVC_Fuzzing_Project/EVC_Fuzzer'
alias evc-vnet-up='sudo ip link add veth-pev type veth peer name veth-evse && sudo ip link set veth-pev up && sudo ip link set veth-evse up'
alias evc-vnet-down='sudo ip link delete veth-pev 2>/dev/null'
EOF

# Final verification
print_status "Running installation verification..."
cd install_scripts
if python3 test_environment.py; then
    print_success "Installation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Source your bashrc: source ~/.bashrc"
    echo "2. Review TESTING.md for usage examples"
    echo "3. Run 'evc-vnet-up' to create virtual test network"
else
    print_error "Installation verification failed"
    exit 1
fi