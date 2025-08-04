# Troubleshooting Guide - EVC Fuzzing Project

This guide helps resolve common issues when using the EVC Fuzzing Project.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Network Issues](#network-issues)
3. [Python Issues](#python-issues)
4. [Java/EXI Decoder Issues](#javaexi-decoder-issues)
5. [Fuzzing Issues](#fuzzing-issues)
6. [Hardware Issues](#hardware-issues)
7. [Debug Techniques](#debug-techniques)

## Installation Issues

### Python Package Installation Fails

**Problem**: `pip install` fails with permission errors

**Solutions**:
```bash
# Option 1: Use user installation
pip3 install --user -r requirements.txt

# Option 2: Use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Option 3: On newer systems with PEP 668
pip3 install --break-system-packages -r requirements.txt
```

### Java Not Found

**Problem**: Java commands fail or Java not in PATH

**Solutions**:
```bash
# Check Java installation
which java
java -version

# Install Java if missing
# Ubuntu/Debian:
sudo apt install openjdk-11-jre

# Add to PATH if installed but not found
export PATH=$PATH:/usr/lib/jvm/java-11-openjdk-amd64/bin
```

### Scapy Import Error

**Problem**: `ImportError: No module named 'scapy'`

**Solutions**:
```bash
# Install via pip
pip3 install scapy

# Or system package (Ubuntu/Debian)
sudo apt install python3-scapy

# Verify installation
python3 -c "import scapy; print(scapy.__version__)"
```

## Network Issues

### IPv6 Disabled

**Problem**: IPv6 not working or disabled

**Solutions**:
```bash
# Check IPv6 status
cat /proc/sys/net/ipv6/conf/all/disable_ipv6

# Enable IPv6 temporarily
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0

# Enable IPv6 permanently
echo "net.ipv6.conf.all.disable_ipv6 = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Virtual Interface Creation Fails

**Problem**: Cannot create veth interfaces

**Solutions**:
```bash
# Check if veth module is loaded
lsmod | grep veth

# Load veth module
sudo modprobe veth

# Verify kernel support
grep CONFIG_VETH /boot/config-$(uname -r)

# Alternative: use network namespaces
sudo ip netns add test-ns
sudo ip link add veth0 type veth peer name veth1 netns test-ns
```

### Permission Denied on Network Operations

**Problem**: Scripts fail with permission errors

**Solutions**:
```bash
# Run with sudo
sudo python3 script.py

# Or add CAP_NET_RAW capability
sudo setcap cap_net_raw+ep $(which python3)

# Verify capabilities
getcap $(which python3)
```

### Cannot Find Target Device

**Problem**: EVSE/PEV not responding to discovery

**Checks**:
```bash
# Verify link-local addresses
ip -6 addr show

# Test connectivity
ping6 -I eth1 fe80::21e:c0ff:fef2:6ca0%eth1

# Check firewall
sudo ip6tables -L

# Monitor traffic
sudo tcpdump -i eth1 -nn ip6
```

## Python Issues

### Module Import Errors

**Problem**: Custom modules not found

**Solutions**:
```bash
# Add project to Python path
export PYTHONPATH=$PYTHONPATH:/path/to/EVC_Fuzzing_Project

# Or in script
import sys
sys.path.append('../shared/external_libs/HomePlugPWN')
```

### Python Version Incompatibility

**Problem**: Scripts fail on older Python versions

**Check version**:
```bash
python3 --version

# Use specific version
python3.8 script.py

# Install newer Python (Ubuntu)
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.9
```

## Java/EXI Decoder Issues

### EXI Decoder Won't Start

**Problem**: Java decoder fails to run

**Debug steps**:
```bash
# Check Java version
java -version  # Should be 8 or higher

# Test decoder directly
cd shared/java_decoder
java -jar V2Gdecoder-jar-with-dependencies.jar -h

# Check for port conflicts
sudo lsof -i :9000

# Run with more memory
java -Xmx512m -jar V2Gdecoder-jar-with-dependencies.jar -w
```

### Port 9000 Already in Use

**Problem**: Address already in use error

**Solutions**:
```bash
# Find process using port
sudo lsof -i :9000
sudo netstat -tlnp | grep 9000

# Kill the process
sudo kill -9 <PID>

# Or use different port
java -jar V2Gdecoder-jar-with-dependencies.jar -w -p 9001
```

## Fuzzing Issues

### Fuzzer Crashes Immediately

**Problem**: Fuzzer exits without fuzzing

**Debug**:
```bash
# Check if target is running
ps aux | grep EVSE.py

# Verify network setup
ip link show | grep veth

# Run with debug output
sudo python3 unified_fuzzer.py --state state1 --debug

# Check logs
tail -f fuzzing_state_state1.json
```

### No Crashes Detected

**Problem**: Fuzzing runs but finds no crashes

**Considerations**:
- Target may be robust against current mutations
- Increase iteration count
- Try different protocol states
- Monitor target for silent failures

```bash
# Increase iterations
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 1000

# Monitor target memory
watch -n 1 'ps aux | grep EVSE'
```

### Fuzzing Too Slow

**Problem**: Low fuzzing throughput

**Optimizations**:
```bash
# Reduce network delays
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Use faster mutation algorithms
# Edit fuzzer to use simpler mutations

# Run multiple instances
for i in {1..5}; do
    sudo python3 unified_fuzzer.py --state state$i &
done
```

## Hardware Issues

### Raspberry Pi I2C Not Working

**Problem**: I2C devices not detected

**Solutions**:
```bash
# Enable I2C
sudo raspi-config nonint do_i2c 0

# Check I2C devices
sudo i2cdetect -y 1

# Verify kernel modules
lsmod | grep i2c

# Add user to i2c group
sudo usermod -a -G i2c $USER
# Logout and login again
```

### GPIO Access Denied

**Problem**: Cannot control GPIO pins

**Solutions**:
```bash
# Install GPIO library
sudo apt install python3-rpi.gpio

# Run as root
sudo python3 script.py

# Or add user to gpio group
sudo usermod -a -G gpio $USER
```

### Devolo Board Not Responding

**Problem**: HomePlug communication fails

**Checks**:
1. Verify power and connections
2. Check jumper settings (2-wire mode)
3. Test with different Ethernet cable
4. Verify board firmware version

## Debug Techniques

### Enable Debug Logging

**In scripts**:
```python
# Add to script
import logging
logging.basicConfig(level=logging.DEBUG)

# Or via environment
export V2G_DEBUG=1
export SCAPY_DEBUG=1
```

### Network Traffic Analysis

```bash
# Capture all traffic
sudo tcpdump -i any -w debug.pcap

# Filter V2G traffic
sudo tcpdump -i eth1 -nn 'tcp port 61851'

# Analyze with Wireshark
wireshark debug.pcap
```

### Process Monitoring

```bash
# Monitor in real-time
htop

# Trace system calls
sudo strace -p $(pgrep -f EVSE.py)

# Monitor file access
sudo lsof -p $(pgrep -f unified_fuzzer)
```

### Memory Debugging

```bash
# Check for memory leaks
valgrind --leak-check=full python3 script.py

# Monitor memory usage
watch -n 1 'ps aux | grep python3'
```

### Core Dump Analysis

```bash
# Enable core dumps
ulimit -c unlimited

# Set core pattern
echo "/tmp/core.%e.%p" | sudo tee /proc/sys/kernel/core_pattern

# Analyze core dump
gdb python3 /tmp/core.python3.12345
```

## Getting Further Help

1. **Check logs**: Most scripts create log files
2. **Run validation**: `python3 install_scripts/test_environment.py`
3. **Consult documentation**: Review README files in each directory
4. **Debug mode**: Add `-v` or `--debug` flags to scripts
5. **Network capture**: Use tcpdump/Wireshark for protocol issues

### Reporting Issues

When reporting issues, include:
- Operating system and version
- Python version
- Error messages (full traceback)
- Steps to reproduce
- Output of `test_environment.py`
- Relevant log files