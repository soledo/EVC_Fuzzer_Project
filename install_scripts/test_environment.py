#!/usr/bin/env python3
"""
EVC Fuzzing Project - Environment Validation Script
Tests system configuration and dependencies
"""

import sys
import os
import subprocess
import socket
import importlib
import json
from pathlib import Path

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header():
    """Print script header"""
    print("\n" + "="*60)
    print("EVC Fuzzing Project - Environment Validation")
    print("="*60 + "\n")

def check_mark(success):
    """Return colored check mark or X"""
    return f"{GREEN}[✓]{RESET}" if success else f"{RED}[✗]{RESET}"

def print_result(test_name, success, details=""):
    """Print test result with formatting"""
    mark = check_mark(success)
    print(f"{mark} {test_name}")
    if details:
        print(f"    {BLUE}→{RESET} {details}")

def check_python_version():
    """Check Python version meets requirements"""
    version = sys.version_info
    success = version.major == 3 and version.minor >= 8
    details = f"Python {version.major}.{version.minor}.{version.micro}"
    print_result("Python version", success, details)
    return success

def check_java():
    """Check if Java is installed and accessible"""
    try:
        result = subprocess.run(['java', '-version'], 
                              capture_output=True, 
                              text=True)
        if result.returncode == 0:
            # Java version info is printed to stderr
            version_line = result.stderr.split('\n')[0]
            print_result("Java installation", True, version_line)
            return True
    except FileNotFoundError:
        pass
    
    print_result("Java installation", False, "Java not found in PATH")
    return False

def check_python_packages():
    """Check required Python packages"""
    packages = {
        'scapy': 'scapy',
        'tqdm': 'tqdm',
        'requests': 'requests',
        'smbus': 'smbus',
        'colorama': 'colorama'
    }
    
    all_success = True
    print(f"\n{BLUE}Checking Python packages:{RESET}")
    
    for display_name, import_name in packages.items():
        try:
            importlib.import_module(import_name)
            print(f"  {check_mark(True)} {display_name}")
        except ImportError:
            print(f"  {check_mark(False)} {display_name} - Not installed")
            all_success = False
    
    return all_success

def check_ipv6():
    """Check if IPv6 is enabled"""
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as f:
            disabled = int(f.read().strip())
            success = disabled == 0
            status = "Enabled" if success else "Disabled"
            print_result("IPv6 support", success, status)
            return success
    except:
        print_result("IPv6 support", False, "Unable to check IPv6 status")
        return False

def check_network_interfaces():
    """Check available network interfaces"""
    try:
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, 
                              text=True)
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and not line.startswith(' '):
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        iface = parts[1].split('@')[0]
                        if iface not in ['lo']:  # Skip loopback
                            interfaces.append(iface)
            
            success = len(interfaces) > 0
            details = f"Found: {', '.join(interfaces)}" if interfaces else "No interfaces found"
            print_result("Network interfaces", success, details)
            return success
    except:
        pass
    
    print_result("Network interfaces", False, "Unable to list interfaces")
    return False

def check_virtual_interface_support():
    """Check if virtual interfaces can be created"""
    try:
        # Try to create a test veth pair
        result = subprocess.run(['sudo', 'ip', 'link', 'add', 'test-veth-env', 
                               'type', 'veth', 'peer', 'name', 'test-veth-env-peer'],
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            # Clean up
            subprocess.run(['sudo', 'ip', 'link', 'delete', 'test-veth-env'],
                         capture_output=True)
            print_result("Virtual interface support", True, "veth module available")
            return True
        else:
            print_result("Virtual interface support", False, 
                        "Cannot create virtual interfaces (need sudo or veth module)")
            return False
    except:
        print_result("Virtual interface support", False, "Test failed")
        return False

def check_exi_decoder():
    """Check if EXI decoder is accessible"""
    # Look for the JAR file
    jar_paths = [
        Path("../shared/java_decoder/V2Gdecoder-jar-with-dependencies.jar"),
        Path("shared/java_decoder/V2Gdecoder-jar-with-dependencies.jar"),
        Path("java_decoder/V2Gdecoder-jar-with-dependencies.jar")
    ]
    
    jar_found = None
    for jar_path in jar_paths:
        if jar_path.exists():
            jar_found = jar_path
            break
    
    if jar_found:
        # Try to run it
        try:
            result = subprocess.run(['java', '-jar', str(jar_found), '-h'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print_result("EXI decoder", True, f"Found at {jar_found}")
                return True
        except:
            pass
    
    print_result("EXI decoder", False, "JAR file not found or not executable")
    return False

def check_project_structure():
    """Check if project directories exist"""
    directories = [
        ("EVC_Simulator", "../EVC_Simulator"),
        ("EVC_Fuzzer", "../EVC_Fuzzer"),
        ("Shared libraries", "../shared"),
        ("External libs", "../shared/external_libs")
    ]
    
    all_exist = True
    print(f"\n{BLUE}Checking project structure:{RESET}")
    
    for name, path in directories:
        exists = Path(path).exists()
        print(f"  {check_mark(exists)} {name}")
        if not exists:
            all_exist = False
    
    return all_exist

def check_permissions():
    """Check if user has necessary permissions"""
    # Check if we can use sudo
    try:
        result = subprocess.run(['sudo', '-n', 'true'], 
                              capture_output=True)
        has_sudo = result.returncode == 0
        
        if has_sudo:
            print_result("Sudo access", True, "Passwordless sudo available")
        else:
            print_result("Sudo access", False, 
                        "Sudo requires password (needed for network operations)")
        return has_sudo
    except:
        print_result("Sudo access", False, "Sudo not available")
        return False

def check_raspberry_pi_specific():
    """Check Raspberry Pi specific features"""
    is_pi = False
    results = []
    
    # Check if running on Pi
    try:
        with open('/proc/device-tree/model', 'r') as f:
            model = f.read().strip()
            is_pi = 'raspberry pi' in model.lower()
            if is_pi:
                print(f"\n{BLUE}Raspberry Pi specific checks:{RESET}")
                print(f"  Model: {model}")
    except:
        pass
    
    if is_pi:
        # Check I2C
        try:
            result = subprocess.run(['i2cdetect', '-l'], 
                                  capture_output=True, text=True)
            i2c_available = result.returncode == 0
            results.append(("I2C interface", i2c_available))
        except:
            results.append(("I2C interface", False))
        
        # Check GPIO
        try:
            import RPi.GPIO
            results.append(("GPIO library", True))
        except:
            results.append(("GPIO library", False))
        
        # Print results
        for test, success in results:
            print(f"  {check_mark(success)} {test}")
    
    return is_pi, all(r[1] for r in results) if results else True

def generate_report():
    """Generate a summary report"""
    results = {
        "timestamp": subprocess.run(['date'], capture_output=True, text=True).stdout.strip(),
        "platform": subprocess.run(['uname', '-a'], capture_output=True, text=True).stdout.strip(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "tests_passed": 0,
        "tests_failed": 0
    }
    
    # Save to file
    report_path = Path("environment_report.json")
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    return report_path

def main():
    """Run all environment checks"""
    print_header()
    
    # Track overall success
    all_tests_passed = True
    
    # Basic checks
    print(f"{BLUE}Basic requirements:{RESET}")
    all_tests_passed &= check_python_version()
    all_tests_passed &= check_java()
    all_tests_passed &= check_python_packages()
    
    # Network checks
    print(f"\n{BLUE}Network configuration:{RESET}")
    all_tests_passed &= check_ipv6()
    all_tests_passed &= check_network_interfaces()
    all_tests_passed &= check_virtual_interface_support()
    
    # Project checks
    print(f"\n{BLUE}Project components:{RESET}")
    all_tests_passed &= check_exi_decoder()
    all_tests_passed &= check_project_structure()
    
    # Permission checks
    print(f"\n{BLUE}System permissions:{RESET}")
    check_permissions()  # Don't fail on this, just warn
    
    # Platform specific
    is_pi, pi_checks_passed = check_raspberry_pi_specific()
    if is_pi:
        all_tests_passed &= pi_checks_passed
    
    # Summary
    print("\n" + "="*60)
    if all_tests_passed:
        print(f"{GREEN}✓ All critical checks passed!{RESET}")
        print("The environment is ready for EVC Fuzzing Project.")
    else:
        print(f"{RED}✗ Some checks failed.{RESET}")
        print("Please install missing dependencies and fix issues.")
        print("See INSTALLATION.md for detailed instructions.")
    
    # Generate report
    report_path = generate_report()
    print(f"\nDetailed report saved to: {report_path}")
    
    # Return exit code
    return 0 if all_tests_passed else 1

if __name__ == "__main__":
    sys.exit(main())