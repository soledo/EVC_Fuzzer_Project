# Testing Guide - EVC Fuzzing Project

This guide provides comprehensive testing scenarios for the EVC Fuzzing Project, from basic single-host setups to distributed multi-system deployments.

## Table of Contents

1. [Testing Overview](#testing-overview)
2. [Single Host Testing](#single-host-testing)
3. [Two VM Testing](#two-vm-testing)
4. [Physical Two-Host Testing](#physical-two-host-testing)
5. [Cross-Platform Testing](#cross-platform-testing)
6. [Test Validation](#test-validation)
7. [Performance Testing](#performance-testing)
8. [Troubleshooting Tests](#troubleshooting-tests)

## Testing Overview

### Test Environment Types

1. **Development Testing**: Single host with virtual interfaces
2. **Integration Testing**: Multiple VMs or containers
3. **System Testing**: Physical hardware with real network
4. **Acceptance Testing**: Full hardware-in-the-loop setup

### Prerequisites for All Tests

- Completed installation (see [INSTALLATION.md](INSTALLATION.md))
- Root/sudo access
- IPv6 enabled
- Network interfaces configured

## Single Host Testing

### Quick Test (5 minutes)

This is the fastest way to verify basic functionality.

#### Setup

```bash
# 1. Create virtual network
sudo ip link add veth-pev type veth peer name veth-evse
sudo ip link set veth-pev up
sudo ip link set veth-evse up
```

#### Test Execution

**Terminal 1 - EVSE Simulator**:
```bash
cd EVC_Simulator
sudo python3 EVSE.py --interface veth-evse --mode 0
```

**Terminal 2 - PEV Simulator**:
```bash
cd EVC_Simulator
sudo python3 PEV.py --interface veth-pev --mode 0
```

Expected: Successful SLAC association and V2G session establishment

#### Cleanup

```bash
sudo ip link delete veth-pev
```

### Fuzzing Test (15 minutes)

#### Setup

Same virtual network setup as above.

#### Test Execution

**Terminal 1 - Target EVSE**:
```bash
cd EVC_Simulator
sudo python3 EVSE.py --interface veth-evse
```

**Terminal 2 - Fuzzer**:
```bash
cd EVC_Fuzzer

# List available states
python3 unified_fuzzer.py --list-states

# Run fuzzing (reduced iterations for quick test)
sudo python3 unified_fuzzer.py --state state1 --interface veth-pev --iterations-per-element 10
```

#### Verify Results

```bash
# Check for crash reports
ls -la fuzzing_report_*.json
cat fuzzing_report_state1.json
```

### Full Protocol Test Suite

Run through all protocol states:

```bash
#!/bin/bash
# test_all_states.sh

for state in state1 state2 state3 state4 state5; do
    echo "Testing $state..."
    sudo python3 unified_fuzzer.py --state $state --interface veth-pev --iterations-per-element 5
    sleep 2
done
```

## Two VM Testing

### VM Setup

#### VM1 (EVSE):
- OS: Ubuntu 22.04
- RAM: 2GB
- Network: Bridged adapter
- IP: Configure IPv6 link-local

#### VM2 (PEV/Fuzzer):
- OS: Ubuntu 22.04
- RAM: 2GB
- Network: Bridged adapter (same network as VM1)
- IP: Configure IPv6 link-local

### Network Configuration

**On both VMs**:
```bash
# Enable IPv6
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0

# Configure network interface (replace eth0 with your interface)
sudo ip -6 addr add fe80::1/64 dev eth0 scope link
sudo ip link set eth0 up
```

### Test Execution

**VM1 - EVSE**:
```bash
cd EVC_Simulator
sudo python3 EVSE.py --interface eth0
```

**VM2 - Fuzzer**:
```bash
cd EVC_Fuzzer
sudo python3 unified_fuzzer.py --state state3 --interface eth0 --iterations-per-element 50
```

### Monitoring

**On VM1**:
```bash
# Monitor network traffic
sudo tcpdump -i eth0 -w evse_capture.pcap
```

**On VM2**:
```bash
# Monitor fuzzing progress
tail -f fuzzing_state_state3.json
```

## Physical Two-Host Testing

### Hardware Setup

#### Host 1 (EVSE):
- Raspberry Pi 4 or x86 Linux machine
- Ethernet connection to network switch
- Optional: Devolo Green PHY board

#### Host 2 (PEV/Fuzzer):
- Raspberry Pi 4 or x86 Linux machine
- Ethernet connection to same network switch
- Optional: Devolo Green PHY board

### Network Configuration

**Host 1**:
```bash
# Configure static IPv6 link-local
sudo ip -6 addr add fe80::1:1/64 dev eth0
sudo ip link set eth0 up
```

**Host 2**:
```bash
# Configure static IPv6 link-local
sudo ip -6 addr add fe80::2:1/64 dev eth0
sudo ip link set eth0 up
```

### Connectivity Test

```bash
# From Host 2, ping Host 1
ping6 -I eth0 fe80::1:1%eth0
```

### Full Test Sequence

**Host 1**:
```bash
cd EVC_Simulator
sudo python3 EVSE.py --interface eth0 --source-ip fe80::1:1
```

**Host 2**:
```bash
cd EVC_Fuzzer
# Run comprehensive fuzzing
sudo python3 unified_fuzzer.py \
    --state state1 \
    --interface eth0 \
    --source-ip fe80::2:1 \
    --iterations-per-element 100
```

## Cross-Platform Testing

### Test Matrix

| EVSE Platform | PEV Platform | Network Type | Expected Result |
|---------------|--------------|--------------|-----------------|
| Ubuntu 22.04  | Ubuntu 22.04 | Virtual      | Pass            |
| Ubuntu 22.04  | RPi OS       | Physical     | Pass            |
| RPi OS        | Ubuntu 20.04 | Physical     | Pass            |
| Debian 11     | Debian 12    | Virtual      | Pass            |

### Platform-Specific Tests

#### Raspberry Pi Hardware Test

```bash
# Test GPIO control (if hardware connected)
cd EVC_Simulator
sudo python3 -c "from EmulatorCore import set_relay_state; set_relay_state(1, True)"
```

#### Ubuntu Performance Test

```bash
# High-speed fuzzing test
cd EVC_Fuzzer
time sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 1000
```

## Test Validation

### Automated Test Suite

Create `run_tests.sh`:

```bash
#!/bin/bash
# Automated test suite

echo "=== EVC Fuzzing Project Test Suite ==="

# Test 1: Environment check
echo -n "Test 1 - Environment: "
python3 install_scripts/test_environment.py > /dev/null 2>&1
if [ $? -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi

# Test 2: Virtual network
echo -n "Test 2 - Virtual Network: "
sudo ip link add test-veth type veth peer name test-veth-peer 2>/dev/null
if [ $? -eq 0 ]; then 
    sudo ip link delete test-veth 2>/dev/null
    echo "PASS"
else 
    echo "FAIL"
fi

# Test 3: EXI Decoder
echo -n "Test 3 - EXI Decoder: "
cd shared/java_decoder
timeout 5 java -jar V2Gdecoder-jar-with-dependencies.jar -h > /dev/null 2>&1
if [ $? -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
cd ../..

# Test 4: Simulator import
echo -n "Test 4 - Simulator Import: "
cd EVC_Simulator
python3 -c "import EVSE, PEV, XMLBuilder" 2>/dev/null
if [ $? -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
cd ..

# Test 5: Fuzzer import
echo -n "Test 5 - Fuzzer Import: "
cd EVC_Fuzzer
python3 -c "import unified_fuzzer" 2>/dev/null
if [ $? -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
cd ..

echo "=== Test Suite Complete ==="
```

### Manual Validation Checklist

- [ ] Virtual interfaces can be created
- [ ] IPv6 link-local addresses assigned
- [ ] EVSE simulator starts without errors
- [ ] PEV simulator establishes connection
- [ ] Fuzzer generates mutations
- [ ] Crash reports are generated
- [ ] Network traffic visible in tcpdump

## Performance Testing

### Fuzzing Performance Benchmark

```bash
#!/bin/bash
# benchmark.sh

echo "Starting performance benchmark..."

for iterations in 10 50 100 500 1000; do
    echo -n "Testing $iterations iterations: "
    start_time=$(date +%s)
    
    sudo python3 EVC_Fuzzer/unified_fuzzer.py \
        --state state1 \
        --iterations-per-element $iterations \
        > /dev/null 2>&1
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    rate=$((iterations / duration))
    
    echo "$duration seconds ($rate iterations/sec)"
done
```

### Expected Performance

| Platform      | Iterations/sec | Notes                    |
|---------------|----------------|--------------------------|
| Ubuntu x86_64 | 50-100        | Desktop/laptop           |
| RPi 4         | 20-40         | Depends on cooling       |
| VM            | 30-60         | Depends on host resources|

## Troubleshooting Tests

### Network Connectivity Test

```bash
# test_connectivity.sh
#!/bin/bash

echo "Testing network connectivity..."

# Check IPv6
if [ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) -eq 0 ]; then
    echo "[✓] IPv6 enabled"
else
    echo "[✗] IPv6 disabled"
fi

# Check interfaces
if ip link show | grep -q "veth"; then
    echo "[✓] Virtual interfaces available"
else
    echo "[✗] No virtual interfaces found"
fi

# Check link-local addresses
if ip -6 addr | grep -q "fe80::"; then
    echo "[✓] Link-local addresses configured"
else
    echo "[✗] No link-local addresses"
fi
```

### Process Monitoring

```bash
# Monitor EVSE simulator
ps aux | grep EVSE.py

# Monitor fuzzer memory usage
while true; do
    ps -o pid,vsz,rss,comm -p $(pgrep -f unified_fuzzer)
    sleep 5
done
```

### Debug Mode Testing

```bash
# Enable debug output
export V2G_DEBUG=1

# Run with verbose logging
sudo python3 EVSE.py --interface veth-evse --debug

# Capture detailed logs
sudo python3 unified_fuzzer.py --state state1 2>&1 | tee fuzzer_debug.log
```

## Test Reports

### Generate Test Report

```bash
#!/bin/bash
# generate_report.sh

echo "EVC Fuzzing Test Report" > test_report.txt
echo "======================" >> test_report.txt
echo "Date: $(date)" >> test_report.txt
echo "Platform: $(uname -a)" >> test_report.txt
echo "" >> test_report.txt

# Add test results
echo "Test Results:" >> test_report.txt
./run_tests.sh >> test_report.txt

# Add fuzzing statistics
echo "" >> test_report.txt
echo "Fuzzing Statistics:" >> test_report.txt
if [ -f fuzzing_report_state1.json ]; then
    python3 -c "
import json
with open('fuzzing_report_state1.json') as f:
    data = json.load(f)
    print(f'Total attempts: {data.get(\"total_attempts\", 0)}')
    print(f'Crashes found: {data.get(\"total_crashes\", 0)}')
" >> test_report.txt
fi
```

## Next Steps

After completing tests:

1. Review crash reports for vulnerabilities
2. Analyze network captures for protocol issues
3. Document any platform-specific behaviors
4. Submit test results with bug reports
5. Consider contributing test improvements