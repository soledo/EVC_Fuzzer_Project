# EVC Fuzzing Project

A comprehensive testing and fuzzing framework for Electric Vehicle Charging Controller (EVCC) and Supply Equipment Communications Controller (SECC) implementations using ISO 15118 and DIN 70121 protocols.

## Overview

This project provides tools for security testing and protocol validation of EV charging infrastructure:

- **EVC_Simulator**: Emulates EVSE (charging station) and PEV (electric vehicle) for communications testing
- **EVC_Fuzzer**: Advanced fuzzing capabilities for vulnerability discovery in V2G protocols

### Key Features

- Complete V2G protocol stack implementation (DIN 70121, ISO 15118)
- State-based fuzzing targeting specific protocol vulnerabilities
- Hardware-in-the-loop testing support via Raspberry Pi
- Flexible deployment: single host, multiple VMs, or distributed systems
- Comprehensive crash detection and reporting

## Quick Start

### Prerequisites

- Linux-based OS (Ubuntu 20.04/22.04, Debian 11/12, or Raspberry Pi OS)
- Python 3.8 or higher
- Java 8 or higher (for EXI encoder/decoder)
- Network interface with IPv6 support

### Installation

1. Clone the repository:
   ```bash
   git clone --recurse-submodules <repository-url>
   cd EVC_Fuzzing_Project
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. For detailed installation instructions, see [INSTALLATION.md](INSTALLATION.md)

### Basic Usage

#### Single Host Testing (Virtual Network)

1. Create virtual network interfaces:
   ```bash
   sudo ip link add veth-pev type veth peer name veth-evse
   sudo ip link set veth-pev up
   sudo ip link set veth-evse up
   ```

2. Terminal 1 - Start EVSE simulator:
   ```bash
   cd EVC_Simulator
   sudo python3 EVSE.py --interface veth-evse
   ```

3. Terminal 2 - Run fuzzer:
   ```bash
   cd EVC_Fuzzer
   sudo python3 unified_fuzzer.py --state state1 --interface veth-pev --iterations-per-element 100
   ```

For more testing scenarios, see [TESTING.md](TESTING.md)

## Project Structure

```
EVC_Fuzzing_Project/
├── EVC_Simulator/          # EVSE and PEV emulators
│   ├── EVSE.py            # Charging station emulator
│   ├── PEV.py             # Electric vehicle emulator
│   └── XMLBuilder.py      # V2G message construction
├── EVC_Fuzzer/            # Fuzzing tools
│   ├── unified_fuzzer.py  # Main fuzzing engine
│   └── XMLFormat.py       # Message mutation engine
├── shared/                # Shared resources
│   ├── external_libs/     # Third-party dependencies
│   └── java_decoder/      # EXI encoder/decoder
└── docs/                  # Additional documentation
```

## Tested Environments

### Fully Tested
- Ubuntu 22.04 LTS (x86_64)
- Raspberry Pi OS (Bullseye) on RPi 4
- Debian 11 (Bullseye)

### Partially Tested
- Ubuntu 20.04 LTS
- Debian 12 (Bookworm)

## Documentation

- [INSTALLATION.md](INSTALLATION.md) - Detailed setup instructions
- [TESTING.md](TESTING.md) - Testing scenarios and guides
- [EVC_Simulator/README.md](EVC_Simulator/README.md) - Simulator details
- [EVC_Fuzzer/README.md](EVC_Fuzzer/README.md) - Fuzzer documentation

## Hardware Support

The project supports both software-only and hardware-in-the-loop testing:

- **Software-only**: Virtual network interfaces for protocol testing
- **Hardware**: Raspberry Pi with Devolo Green PHY boards for physical layer testing

See hardware setup details in the simulator documentation.

## Security Notice

This tool is designed for **defensive security testing only**. Use it to:
- Test robustness of EV charging infrastructure
- Identify vulnerabilities in V2G implementations
- Validate protocol compliance

Do NOT use this tool on systems you don't own or without explicit permission.

## Contributing

When contributing:
1. Follow existing code conventions
2. Test changes on at least one supported platform
3. Update documentation as needed
4. Submit pull requests with clear descriptions

## License

[Specify your license here]

## Support

For issues and questions:
- Check [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- Review existing issues
- Create new issues with detailed descriptions

## Acknowledgments

This project builds upon:
- [HomePlugPWN](https://github.com/FlUxIuS/HomePlugPWN) - HomePlug protocol layers
- [V2Gdecoder](https://github.com/FlUxIuS/V2Gdecoder) - EXI encoding/decoding
- [RISE-V2G](https://github.com/SwitchEV/RISE-V2G) - V2G reference implementation