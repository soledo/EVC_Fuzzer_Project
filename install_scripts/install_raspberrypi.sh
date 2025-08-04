#!/bin/bash
# Raspberry Pi OS Installation Script for EVC Fuzzing Project
# Tested on: Raspberry Pi OS (Bullseye, Bookworm)

set -e  # Exit on error

echo "=== EVC Fuzzing Project - Raspberry Pi Installation ==="
echo "This script will install all required dependencies for Raspberry Pi."
echo ""

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

# Check if running on Raspberry Pi
print_status "Checking if running on Raspberry Pi..."
if [ -f /proc/device-tree/model ]; then
    model=$(cat /proc/device-tree/model)
    print_success "Detected: $model"
else
    print_error "Warning: This doesn't appear to be a Raspberry Pi"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Enable I2C
print_status "Enabling I2C interface..."
if command -v raspi-config >/dev/null 2>&1; then
    sudo raspi-config nonint do_i2c 0
    print_success "I2C enabled"
else
    print_error "raspi-config not found, please enable I2C manually"
fi

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
    i2c-tools \
    python3-smbus \
    python3-rpi.gpio \
    build-essential \
    libssl-dev \
    libffi-dev

# Add user to i2c group
print_status "Adding user to i2c group..."
sudo usermod -a -G i2c $USER
print_success "User added to i2c group (logout required to take effect)"

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
if command -v java >/dev/null 2>&1; then
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
    # On newer Raspberry Pi OS, might need --break-system-packages
    if pip3 install -r requirements.txt 2>/dev/null; then
        print_success "Python packages installed"
    else
        print_status "Trying with --break-system-packages flag..."
        pip3 install --break-system-packages -r requirements.txt
        print_success "Python packages installed"
    fi
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
    # Make persistent
    echo "net.ipv6.conf.all.disable_ipv6 = 0" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 0" | sudo tee -a /etc/sysctl.conf
    print_success "IPv6 enabled"
fi

# Test I2C
print_status "Testing I2C interface..."
if i2cdetect -l 2>/dev/null | grep -q i2c; then
    print_success "I2C interface detected"
else
    print_error "No I2C interface found. Hardware control may not work."
fi

# Test GPIO
print_status "Testing GPIO access..."
if python3 -c "import RPi.GPIO" 2>/dev/null; then
    print_success "GPIO library accessible"
else
    print_error "GPIO library not accessible"
fi

# Test virtual interface creation
print_status "Testing virtual interface support..."
if sudo ip link add test-veth type veth peer name test-veth-peer 2>/dev/null; then
    sudo ip link delete test-veth 2>/dev/null
    print_success "Virtual interface support verified"
else
    print_error "Virtual interface creation failed"
fi

# Create useful aliases
print_status "Setting up convenience aliases..."
cat >> ~/.bashrc << 'EOF'

# EVC Fuzzing Project aliases
alias evc-sim='cd ~/EVC_Fuzzing_Project/EVC_Simulator'
alias evc-fuzz='cd ~/EVC_Fuzzing_Project/EVC_Fuzzer'
alias evc-vnet-up='sudo ip link add veth-pev type veth peer name veth-evse && sudo ip link set veth-pev up && sudo ip link set veth-evse up'
alias evc-vnet-down='sudo ip link delete veth-pev 2>/dev/null'
alias evc-gpio-test='python3 -c "import RPi.GPIO as GPIO; GPIO.setmode(GPIO.BCM); print(\"GPIO OK\")"'
alias evc-i2c-scan='sudo i2cdetect -y 1'
EOF

# GPIO configuration info
print_status "GPIO Pin Configuration:"
echo "  GPIO 17: Relay 1 (J1772 State A)"
echo "  GPIO 27: Relay 2 (J1772 State B)"
echo "  GPIO 22: Relay 3 (CP Connect)"
echo "  GPIO 23: Relay 4 (PP Connect)"

# Final verification
print_status "Running installation verification..."
cd install_scripts
if python3 test_environment.py; then
    print_success "Installation completed successfully!"
    echo ""
    echo "IMPORTANT:"
    echo "1. Logout and login again for i2c group membership to take effect"
    echo "2. Source your bashrc: source ~/.bashrc"
    echo "3. Review TESTING.md for usage examples"
    echo "4. Run 'evc-i2c-scan' to verify I2C devices"
    echo "5. Run 'evc-gpio-test' to verify GPIO access"
else
    print_error "Installation verification failed"
    echo "This may be due to missing hardware interfaces on non-Pi systems"
fi