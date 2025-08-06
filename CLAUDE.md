# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## EVC Fuzzing Project Overview

This project provides tools for testing and fuzzing Electric Vehicle Charging Controller (EVCC) and Supply Equipment Communications Controller (SECC) implementations. It contains two main components:

- **EVC_Simulator**: Emulates EVSE and PEV devices for communications testing
- **EVC_Fuzzer**: Extends the simulator with fuzzing capabilities for security testing

## Project Architecture

### Core Components

**Main Emulator Classes:**
- `EVSE.py`: Electric Vehicle Supply Equipment emulator
- `PEV.py`: Plug-in Electric Vehicle emulator  
- `EXIProcessor.py`: Python wrapper for Java-based EXI encoding/decoding
- `XMLBuilder.py` (Simulator) / `XMLFormat.py` (Fuzzer): XML message construction
- `EmulatorEnum.py`: Enumerations for protocols, states, and modes

**Protocol Stack:**
- Layer 1: Physical signaling (J1772 control pilot/proximity pilot)
- Layer 2: HomePlug GreenPHY (HPGP) via custom Scapy layers
- Layer 3: IPv6 link-local networking, UDP SECC Discovery, TCP V2G messaging
- Layer 4: ISO 15118 / DIN 70121 XML messaging via EXI encoding

**External Dependencies:**
- `external_libs/HomePlugPWN/`: Custom Scapy layers for HomePlug protocols
- `external_libs/V2GInjector/`: V2G protocol injection tools
- `external_libs/RISE-V2G/`: Java-based V2G implementation
- `external_libs/V2Gdecoder/`: EXI encoder/decoder
- `java_decoder/`: Standalone Java EXI processing JAR files

### Fuzzing Architecture (EVC_Fuzzer)

**Unified Fuzzer (UPDATED):**
- `unified_fuzzer.py`: Single parameterized fuzzer targeting all V2G protocol states
- Replaces individual `state1_fuzz.py` through `state10_fuzz.py` files
- Uses `XMLFormat.PacketHandler` to create malformed XML messages
- State-specific configuration via `STATE_CONFIG` dictionary
- Fuzzing parameters controlled via `--iterations-per-element` argument

**Legacy State-based Fuzzing Scripts (DEPRECATED):**
- `state1_fuzz.py` through `state10_fuzz.py`: Individual state-specific fuzzers
- **NOTE**: These are now deprecated in favor of the unified fuzzer

**Key Differences from Simulator:**
- Uses `XMLFormat.py` instead of `XMLBuilder.py` for packet manipulation
- Implements iterative fuzzing with configurable mutation parameters
- Includes state-specific targeting for protocol vulnerabilities

## Development Commands

### Python Environment Setup
```bash
# Install required Python dependencies
pip install scapy tqdm smbus requests
```

### Java EXI Decoder Setup
```bash
# Run EXI decoder as web service (required for operation)
cd java_decoder
java -jar V2Gdecoder-jar-with-dependencies.jar -w

# Or for single message decoding
java -jar V2Gdecoder-jar-with-dependencies.jar -e -s <hex_string>
```

### Running Emulators
```bash
# Step 1: Start EXI decoder server (required for all operations)
cd shared/java_decoder
java -jar V2Gdecoder-jar-with-dependencies.jar -w

# Step 2: Run emulators (in separate terminals)
# EVSE emulator
cd EVC_Simulator
python3 EVSE.py --interface eth1 --mode 0

# PEV emulator  
cd EVC_Simulator
python3 PEV.py --interface eth1 --mode 0

# Unified Fuzzing (RECOMMENDED)
cd EVC_Fuzzer
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 100

# Legacy individual fuzzer (DEPRECATED)
# sudo python3 state1_fuzz.py --iterations-per-element 100
```

### Unified Fuzzing Workflow (UPDATED)

**Complete Demo Setup (2 Terminals Required):**

1. **Install dependencies**: `pip install scapy tqdm smbus requests`
2. **Setup virtual network**: 
   ```bash
   sudo ip link add veth-pev type veth peer name veth-evse
   sudo ip link set veth-pev up
   sudo ip link set veth-evse up
   ```
3. **Terminal 1 - Start EVSE target**: `cd EVC_Simulator && sudo python3 EVSE.py --interface veth-evse`
   *Note: EVSE automatically starts its own EXI decoder server*
4. **Terminal 2 - Run fuzzing**: `cd EVC_Fuzzer && sudo python3 unified_fuzzer.py --state [state1-10] --interface veth-pev --iterations-per-element [count]`
   *Note: Fuzzer also automatically starts its own EXI decoder server*  
5. **Analyze results**: Check `fuzzing_report_[state].json` for crash analysis

### Unified Fuzzer Usage Examples
```bash
# List all available fuzzing states
python3 unified_fuzzer.py --list-states

# Fuzz SupportedAppProtocol (state1) with 50 iterations per element
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 50

# Fuzz ServiceDiscovery (state3) on specific interface
sudo python3 unified_fuzzer.py --state state3 --interface veth-pev --iterations-per-element 100

# Get help
python3 unified_fuzzer.py --help
```

### Schema Management
The project supports multiple V2G protocol versions:
- `schemas/`: ISO 15118-2:2010 (current)
- `schemas_din/`: DIN 70121 specification  
- `schemas_15118-2013/`: ISO 15118-2:2013

## Hardware Configuration

The project is designed for specific hardware setup:
- Raspberry Pi 4 controller
- Devolo dLAN Green PHY evaluation boards (PEV and EVSE variants)
- 4-channel relay for J1772 state emulation
- PWM generation circuit for EVSE control pilot signaling

## Network Configuration

**IPv6 Link-Local Addressing Required:**
- Configure network interfaces for IPv6 link-local addressing
- Default interface: eth1
- PEV default: `fe80::21e:c0ff:fef2:6ca1`  
- EVSE default: `fe80::21e:c0ff:fef2:6ca0`

## Testing and Fuzzing

**Fuzzing Methodology:**
- State-based approach targeting specific V2G protocol states
- XML element mutation with configurable iteration counts
- Network-level protocol fuzzing via HomePlug and IPv6 layers

**Supported Protocols:**
- DIN 70121 (primary, well-tested)
- ISO 15118-2:2010 (included, limited testing)
- ISO 15118-2:2015 and ISO 15118-20 (planned)

## Important Notes

**Java Dependency:** The EXI processor requires a running Java web server on localhost:9000. This is automatically managed by `EXIProcessor.py` but requires Java runtime.

**Hardware Coupling:** The emulators expect specific GPIO and I2C hardware configurations for J1772 signaling. Software-only testing may require modification of hardware control code.

**Protocol Limitations:** Currently focused on DIN 70121. ISO implementations are included but not extensively tested. TLS and Plug-and-Charge features are not implemented.

**Security Focus:** This is a defensive security testing tool. Fuzzing capabilities are intended for vulnerability research and testing of EV charging infrastructure security.