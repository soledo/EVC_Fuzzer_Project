# Installation Guide - EVC Fuzzing Project

This guide provides detailed instructions for installing and configuring the EVC Fuzzing Project on various platforms.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Software Installation](#software-installation)
   - [Ubuntu/Debian](#ubuntudebian)
   - [Raspberry Pi OS](#raspberry-pi-os)
3. [Network Configuration](#network-configuration)
4. [Hardware Setup (Optional)](#hardware-setup-optional)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Operating System**: Linux-based OS with kernel 4.19+
  - Ubuntu 20.04 LTS or newer
  - Debian 11 (Bullseye) or newer
  - Raspberry Pi OS (Bullseye or newer)
- **Python**: Version 3.8 or higher
- **Java**: JRE 8 or higher (for EXI decoder)
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Storage**: 500MB free space
- **Network**: IPv6-capable network interface

### Network Requirements

- IPv6 support (link-local addresses)
- Raw socket access (requires root/sudo)
- For virtual testing: kernel support for veth interfaces

## Software Installation

### Ubuntu/Debian

1. **Update system packages**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install system dependencies**:
   ```bash
   sudo apt install -y \
       python3 \
       python3-pip \
       python3-dev \
       openjdk-11-jre \
       git \
       net-tools \
       iputils-ping \
       tcpdump \
       wireshark
   ```

3. **Clone the repository**:
   ```bash
   git clone --recurse-submodules <repository-url>
   cd EVC_Fuzzing_Project
   ```

4. **Install Python dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

5. **Verify Java installation**:
   ```bash
   java -version
   ```

### Raspberry Pi OS

1. **Enable I2C (for hardware control)**:
   ```bash
   sudo raspi-config nonint do_i2c 0
   ```

2. **Update system**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

3. **Install dependencies**:
   ```bash
   sudo apt install -y \
       python3-pip \
       openjdk-11-jre \
       i2c-tools \
       python3-smbus \
       git
   ```

4. **Clone and setup**:
   ```bash
   git clone --recurse-submodules <repository-url>
   cd EVC_Fuzzing_Project
   pip3 install -r requirements.txt
   ```

5. **Add user to i2c group**:
   ```bash
   sudo usermod -a -G i2c $USER
   # Logout and login for changes to take effect
   ```

## Network Configuration

### IPv6 Link-Local Setup

1. **Verify IPv6 support**:
   ```bash
   # Check if IPv6 is enabled
   cat /proc/sys/net/ipv6/conf/all/disable_ipv6
   # Should return 0
   ```

2. **Enable IPv6 if disabled**:
   ```bash
   sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
   sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
   ```

3. **Configure network interface for IPv6 link-local**:
   ```bash
   # For physical interface (e.g., eth1)
   sudo ip -6 addr add fe80::1/64 dev eth1
   sudo ip link set eth1 up
   ```

### Virtual Network Setup (for testing)

1. **Create virtual ethernet pair**:
   ```bash
   sudo ip link add veth-pev type veth peer name veth-evse
   sudo ip link set veth-pev up
   sudo ip link set veth-evse up
   ```

2. **Verify interfaces**:
   ```bash
   ip link show | grep veth
   ```

3. **Remove virtual interfaces (cleanup)**:
   ```bash
   sudo ip link delete veth-pev
   ```

## Hardware Setup (Optional)

For hardware-in-the-loop testing with Raspberry Pi:

### GPIO Pin Configuration

1. **Install GPIO libraries**:
   ```bash
   sudo apt install python3-rpi.gpio
   ```

2. **Configure relay pins** (as per hardware documentation):
   - GPIO 17: Relay 1 (J1772 State A)
   - GPIO 27: Relay 2 (J1772 State B)
   - GPIO 22: Relay 3 (CP Connect)
   - GPIO 23: Relay 4 (PP Connect)

### Devolo Green PHY Setup

1. Connect Devolo boards to Raspberry Pi ethernet ports
2. Configure jumpers for 2-wire terminal output (not coax)
3. Verify communication with:
   ```bash
   ping6 -I eth1 fe80::21e:c0ff:fef2:6ca0%eth1
   ```

## Verification

Run the installation verification script:

```bash
cd install_scripts
python3 test_environment.py
```

Expected output:
```
[✓] Python version: 3.8.10
[✓] Java installed: openjdk 11.0.11
[✓] Required Python packages installed
[✓] IPv6 enabled
[✓] Network interfaces available
[✓] EXI decoder accessible
[✓] Installation complete!
```

### Manual Verification

1. **Test EXI decoder**:
   ```bash
   cd shared/java_decoder
   java -jar V2Gdecoder-jar-with-dependencies.jar -h
   ```

2. **Test Python imports**:
   ```bash
   python3 -c "import scapy, tqdm, requests; print('All imports successful')"
   ```

3. **Check network capabilities**:
   ```bash
   # Should show CAP_NET_RAW capability
   getcap $(which python3)
   ```

## Troubleshooting

### Common Issues

1. **Permission denied when running scripts**:
   ```bash
   # Scripts require root for raw socket access
   sudo python3 script_name.py
   ```

2. **Java not found**:
   ```bash
   # Install Java
   sudo apt install default-jre
   # Or specific version
   sudo apt install openjdk-11-jre
   ```

3. **Python module not found**:
   ```bash
   # Ensure pip3 is used
   pip3 install -r requirements.txt
   # Or with --user flag
   pip3 install --user -r requirements.txt
   ```

4. **IPv6 connection issues**:
   ```bash
   # Check IPv6 is enabled
   sudo sysctl net.ipv6.conf.all.disable_ipv6=0
   # Check link-local address exists
   ip -6 addr show dev eth1
   ```

5. **Virtual interface creation fails**:
   ```bash
   # Check if veth module is loaded
   sudo modprobe veth
   # Check kernel support
   lsmod | grep veth
   ```

### Platform-Specific Issues

#### Ubuntu 22.04
- May need to install `python3-scapy` package if pip installation fails
- Firewall may block IPv6 link-local traffic

#### Raspberry Pi
- I2C must be enabled via raspi-config
- User must be in i2c group
- May need to install `python3-smbus` separately

#### Debian 12
- Python 3.11 compatibility verified
- May need `--break-system-packages` flag for pip

### Getting Help

1. Check the [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) file
2. Review existing GitHub issues
3. Enable debug logging in scripts
4. Capture network traffic with tcpdump for analysis

## Next Steps

After successful installation:

1. Review [TESTING.md](TESTING.md) for testing scenarios
2. Read component documentation:
   - [EVC_Simulator/README.md](EVC_Simulator/README.md)
   - [EVC_Fuzzer/README.md](EVC_Fuzzer/README.md)
3. Start with virtual network testing before hardware deployment