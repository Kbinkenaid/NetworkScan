#!/usr/bin/env python3
"""
Interactive Nmap Script - Simplifies nmap usage through guided questions
A defensive security tool for network reconnaissance and vulnerability assessment.

Enhancements:
- Conditional host discovery (-Pn only when appropriate)
- Privilege awareness (auto-switch -sS to -sT when not root; warnings)
- Non-interactive mode via argparse (usable in automation)
- Robust subprocess handling (concurrent stdout/stderr reading)
- Results saved to files (-oA) with timestamped directory
- XML parsing for structured, reliable results display
- Improved local network detection (tries to get real CIDR; falls back to /24)
- Optional emoji output toggle
- Legal/ethical reminder before execution
"""

import subprocess
import sys
import re
import random
import ipaddress
import socket
import threading
import time
import os
import argparse
from datetime import datetime
try:
    import xml.etree.ElementTree as ET
except Exception:
    ET = None

# Global toggle for emojis in output
USE_EMOJI = True

def emojify(text_with_emoji, text_plain):
    return text_with_emoji if USE_EMOJI else text_plain

def get_local_network():
    """Get the local network CIDR, return (cidr, local_ip). Try to detect mask, fallback to /24."""
    try:
        # Determine local IP by opening a UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Try to determine netmask using netifaces if available
        cidr = None
        try:
            import netifaces  # type: ignore
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for a in addrs:
                    if a.get('addr') == local_ip and 'netmask' in a:
                        netmask = a['netmask']
                        network = ipaddress.IPv4Network((local_ip, netmask), strict=False)
                        cidr = str(network)
                        break
                if cidr:
                    break
        except Exception:
            cidr = None

        if not cidr:
            # Fallback: assume /24 network
            parts = local_ip.split('.')
            cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        return cidr, local_ip
    except Exception:
        return None, None

def validate_ip(ip):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        try:
            # Check if it's a valid hostname/domain
            socket.gethostbyname(ip)
            return True
        except socket.gaierror:
            return False

def get_target():
    """Get target - either specific IP or local network scan"""
    network, local_ip = get_local_network()
    
    print("\n[1] Select scan target:")
    print("1. Scan specific IP address or hostname")
    if network:
        print(f"2. Scan local network ({network}) - Discover all devices")
        print(f"   Your IP: {local_ip}")
    else:
        print("2. Scan local network (auto-detect failed)")
    
    while True:
        choice = input("Select option (1-2): ").strip()
        
        if choice == "1":
            # Get specific target
            while True:
                target = input("Enter target IP address or hostname: ").strip()
                if target:
                    if validate_ip(target):
                        return target, "single"
                    else:
                        print("❌ Invalid IP address or hostname. Please try again.")
                else:
                    print("❌ Please enter a target IP address or hostname.")
                    
        elif choice == "2":
            if network:
                return network, "network"
            else:
                print("❌ Could not detect local network. Please use option 1.")
                
        else:
            print("❌ Please enter 1 or 2.")

def ask_firewall():
    """Ask about firewall presence and return evasion options + whether to skip host discovery (-Pn)."""
    print("\n[2] Firewall Detection:")
    print("1. No firewall expected")
    print("2. Firewall might be present (use light evasion)")
    print("3. Strong firewall expected (maximum evasion)")
    
    while True:
        choice = input("Select option (1-3): ").strip()
        if choice == "1":
            return {"opts": [], "skip_discovery": False}
        elif choice == "2":
            return {"opts": ["-f", "--randomize-hosts", "-D", "RND:10"], "skip_discovery": True}
        elif choice == "3":
            return {"opts": ["-f", "-f", "--randomize-hosts", "-D", "RND:20", "--data-length", str(random.randint(10, 50))], "skip_discovery": True}
        else:
            print("❌ Please enter 1, 2, or 3.")

def ask_scan_type(scan_mode):
    """Ask what information user needs from scan"""
    print("\n[3] Select scan type:")
    
    if scan_mode == "network":
        print("1. Network Discovery (ping sweep + ARP)")
        print("2. Basic Network Scan (discovery + top ports)")
        print("3. Service Detection (versions + banners)")
        print("4. OS Fingerprinting (TCP/IP stack analysis)")
        print("5. Advanced Device Discovery (OS + services + MAC vendors)")
        print("6. Stealth SYN Scan (half-open connections)")
        print("7. UDP Scan (common UDP services)")
        print("8. Comprehensive Network Audit (all techniques)")
    else:
        print("1. TCP SYN Scan (stealth port scan)")
        print("2. TCP Connect Scan (full connection)")
        print("3. UDP Scan (UDP services)")
        print("4. FIN Scan (firewall evasion)")
        print("5. NULL Scan (advanced evasion)")
        print("6. XMAS Scan (FIN+PSH+URG flags)")
        print("7. ACK Scan (firewall rule detection)")
        print("8. Window Scan (advanced fingerprinting)")
        print("9. Maimon Scan (BSD-specific)")
        print("10. Idle Scan (zombie host)")
        print("11. Service Version Detection")
        print("12. OS Detection")
        print("13. Script Scan (NSE vulnerabilities)")
        print("14. Comprehensive Target Audit")
    
    max_choice = 8 if scan_mode == "network" else 14
    while True:
        choice = input(f"Select option (1-{max_choice}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= max_choice:
            return choice
        else:
            print(f"❌ Please enter a number between 1 and {max_choice}.")

def ask_timing():
    """Ask about scan timing and additional options"""
    print("\n[4] Scan timing and options:")
    print("1. Insane (-T5) - Fastest, very aggressive")
    print("2. Aggressive (-T4) - Fast, may trigger IDS")
    print("3. Normal (-T3) - Default timing")
    print("4. Polite (-T2) - Slower, less bandwidth")
    print("5. Sneaky (-T1) - Very slow, IDS evasion")
    print("6. Paranoid (-T0) - Extremely slow, maximum stealth")
    print("7. Custom timing (manual configuration)")
    
    while True:
        choice = input("Select option (1-7): ").strip()
        if choice == "1":
            return ["-T5"]
        elif choice == "2":
            return ["-T4"]
        elif choice == "3":
            return ["-T3"]
        elif choice == "4":
            return ["-T2"]
        elif choice == "5":
            return ["-T1"]
        elif choice == "6":
            return ["-T0"]
        elif choice == "7":
            return get_custom_timing()
        else:
            print("❌ Please enter 1, 2, 3, 4, 5, 6, or 7.")

def get_custom_timing():
    """Get custom timing options"""
    options = []
    
    print("\n🔧 Custom Timing Configuration:")
    
    # Host timeout
    timeout = input("Host timeout in seconds (default 30): ").strip()
    if timeout and timeout.isdigit():
        options.extend(["--host-timeout", f"{timeout}s"])
    
    # Scan delay
    delay = input("Scan delay between probes in ms (0 for none): ").strip()
    if delay and delay.isdigit() and int(delay) > 0:
        options.extend(["--scan-delay", f"{delay}ms"])
    
    # Max retries
    retries = input("Max retries per port (default 3): ").strip()
    if retries and retries.isdigit():
        options.extend(["--max-retries", retries])
    
    # Parallel scans
    parallel = input("Max parallel host scans (default 50): ").strip()
    if parallel and parallel.isdigit():
        options.extend(["--max-hostgroup", parallel])
    
    return options

def build_nmap_command(target, scan_mode, firewall_profile, scan_type, timing_opts, skip_discovery=False, no_dns=False, ports=None, top_ports=None, scripts=None, script_args=None, udp=False, all_ports=False, save_outputs=True, output_base=None):
    """Build the complete nmap command.
    Returns (cmd_list, output_paths_dict)
    """
    cmd = ["nmap"]

    # Host discovery control: only add -Pn if skipping discovery and not a discovery scan
    if skip_discovery and not (scan_mode == "network" and scan_type == "1"):
        cmd.append("-Pn")

    # Add firewall evasion options
    cmd.extend(firewall_profile.get("opts", []))

    # DNS control
    if no_dns:
        cmd.append("-n")

    # Add timing options
    cmd.extend(timing_opts)

    # Ports selection overrides
    if all_ports:
        cmd.append("-p-")
    elif top_ports:
        cmd.extend(["--top-ports", str(top_ports)])
    elif ports:
        cmd.extend(["-p", str(ports)])

    # UDP toggle (for simple inclusion)
    if udp and "-sU" not in cmd:
        cmd.append("-sU")

    # Add scan type specific options
    if scan_mode == "network":
        if scan_type == "1":  # Network Discovery
            cmd.extend(["-sn", "-PR", "-PE", "--traceroute"])
        elif scan_type == "2":  # Basic Network Scan
            cmd.extend(["-F", "-sV"])  # fast top ports + version
        elif scan_type == "3":  # Service Detection
            cmd.extend(["-sV", "-sC", "-F", "--version-all"])
        elif scan_type == "4":  # OS Fingerprinting
            cmd.extend(["-O", "-F", "--osscan-guess", "--osscan-limit"])
        elif scan_type == "5":  # Advanced Device Discovery
            cmd.extend(["-sV", "-O", "-F", "--script=default,discovery,broadcast", "--osscan-guess", "--traceroute"])
        elif scan_type == "6":  # Stealth SYN Scan
            cmd.extend(["-sS", "-F"])
        elif scan_type == "7":  # UDP Scan
            if "-sU" not in cmd:
                cmd.append("-sU")
            cmd.extend(["--top-ports", "100"])
        elif scan_type == "8":  # Comprehensive Network Audit (balanced)
            # Use -A which implies -sV -O -sC --traceroute
            cmd.extend(["-A", "--top-ports", "1000"])  # avoid full -p- by default
    else:  # Single target
        if scan_type == "1":  # TCP SYN Scan
            cmd.extend(["-sS", "-F"])
        elif scan_type == "2":  # TCP Connect Scan
            cmd.extend(["-sT", "-F"])
        elif scan_type == "3":  # UDP Scan
            if "-sU" not in cmd:
                cmd.append("-sU")
            cmd.extend(["--top-ports", "100"])
        elif scan_type == "4":  # FIN Scan
            cmd.extend(["-sF", "-F"])
        elif scan_type == "5":  # NULL Scan
            cmd.extend(["-sN", "-F"])
        elif scan_type == "6":  # XMAS Scan
            cmd.extend(["-sX", "-F"])
        elif scan_type == "7":  # ACK Scan
            cmd.extend(["-sA", "-F"])
        elif scan_type == "8":  # Window Scan
            cmd.extend(["-sW", "-F"])
        elif scan_type == "9":  # Maimon Scan
            cmd.extend(["-sM", "-F"])
        elif scan_type == "10":  # Idle Scan
            zombie = input("Enter zombie host IP: ").strip()
            if zombie and validate_ip(zombie):
                cmd.extend(["-sI", zombie, "-F"])
            else:
                print("Invalid zombie IP, using TCP Connect scan instead (-sT)")
                cmd.extend(["-sT", "-F"])
        elif scan_type == "11":  # Service Version Detection
            cmd.extend(["-sV", "-F", "--version-all", "--version-trace"])
        elif scan_type == "12":  # OS Detection
            cmd.extend(["-O", "-F", "--osscan-guess", "--osscan-limit"])
        elif scan_type == "13":  # Script Scan
            # avoid exploit by default; can be added via scripts arg
            cmd.extend(["-sC", "-F", "--script=default,vuln"])
        elif scan_type == "14":  # Comprehensive Target Audit
            # -A implies -sV -O -sC --traceroute
            cmd.extend(["-A", "-p-"])

    # Allow user-provided scripts and script args
    if scripts:
        cmd.extend(["--script", scripts])
    if script_args:
        cmd.extend(["--script-args", script_args])

    # Always add these useful options (except for pure discovery scans)
    if not (scan_mode == "network" and scan_type == "1"):
        cmd.append("--open")

    # Add verbose option
    cmd.append("-v")

    # Add reason flag for detailed output
    cmd.append("--reason")

    # Output files
    outputs = {}
    if save_outputs:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = output_base or os.path.join("results", f"scan-{timestamp}")
        os.makedirs(os.path.dirname(base), exist_ok=True)
        cmd.extend(["-oA", base])
        outputs = {
            "base": base,
            "xml": base + ".xml",
            "nmap": base + ".nmap",
            "gnmap": base + ".gnmap",
        }

    # Add target last
    cmd.append(target)

    return cmd, outputs

def progress_tracker():
    """Display progress animation while scan is running"""
    chars = ["●", "○", "●", "○"]
    idx = 0
    while not progress_tracker.stop:
        prompt = emojify("\r🔍 Scanning ", "\rScanning ")
        symbol = chars[idx % len(chars)] if USE_EMOJI else "."
        print(f"{prompt}{symbol} ", end="", flush=True)
        idx += 1
        time.sleep(0.5)

progress_tracker.stop = False

def run_nmap(cmd):
    """Execute nmap command with progress tracking and concurrent stderr reading"""
    print("\n" + emojify("🚀 Running:", "Running:") + f" {' '.join(cmd)}")
    print("=" * 60)

    # Start progress tracker in background
    progress_tracker.stop = False
    progress_thread = threading.Thread(target=progress_tracker, daemon=True)
    progress_thread.start()

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        stdout_lines = []
        stderr_lines = []

        def read_stderr():
            for line in iter(process.stderr.readline, ''):
                if line:
                    stderr_lines.append(line.rstrip())
        
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            stdout_lines.append(line.strip())
            if "Nmap scan report" in line:
                progress_tracker.stop = True
                print("\r" + emojify("🎯 Found host:", "Found host:") + f" {line.split('for')[1].strip() if 'for' in line else 'target'}")
                progress_tracker.stop = False
            elif "open" in line and ("tcp" in line or "udp" in line):
                progress_tracker.stop = True
                print("\r" + emojify("🔓 Found service:", "Found service:") + f" {line.strip()}")
                progress_tracker.stop = False
        
        # Stop progress tracker
        progress_tracker.stop = True
        print("\r" + " " * 40 + "\r", end="")

        returncode = process.wait()
        stderr_thread.join(timeout=2)

        if returncode == 0:
            print(emojify("✅ Scan completed successfully!", "Scan completed successfully."))
            print("\n" + emojify("📊 Results:", "Results:") )
            print("-" * 40)

            # Prefer XML parsing if available (from -oA), else fallback to stdout parsing
            xml_path = None
            if "-oA" in cmd:
                idx = cmd.index("-oA")
                if idx + 1 < len(cmd):
                    xml_path = cmd[idx + 1] + ".xml"
            if xml_path and ET and os.path.exists(xml_path):
                try:
                    display_organized_results_xml(xml_path)
                except Exception as e:
                    print(f"XML parse error ({e}), falling back to raw parsing.")
                    full_output = "\n".join(stdout_lines)
                    display_organized_results(full_output)
            else:
                full_output = "\n".join(stdout_lines)
                display_organized_results(full_output)
        else:
            print(emojify("❌ Scan failed!", "Scan failed!"))
            if stderr_lines:
                print("Error:")
                print("\n".join(stderr_lines))
    except FileNotFoundError:
        progress_tracker.stop = True
        print(emojify("\r❌ nmap not found. Please install nmap first:", "nmap not found. Please install nmap first:"))
        print("   - macOS: brew install nmap")
        print("   - Ubuntu/Debian: sudo apt-get install nmap")
        print("   - CentOS/RHEL: sudo yum install nmap")
    except Exception as e:
        progress_tracker.stop = True
        print(emojify(f"\r❌ Error running scan: {e}", f"Error running scan: {e}"))

def display_organized_results(output):
    """Display nmap results in an organized format by parsing human-readable output (fallback)."""
    lines = output.split('\n')
    current_host = None
    
    for line in lines:
        line = line.strip()
        
        if "Nmap scan report for" in line:
            if current_host:
                print("-" * 40)
            current_host = line.split("for", 1)[1].strip() if "for" in line else "target"
            print(f"{emojify('💻 Host:', 'Host:')} {current_host}")
            
        elif "Host is up" in line:
            latency = line.split("(", 1)[1].split(")")[0] if "(" in line else "unknown"
            print(f"   {emojify('🟢 Online', 'Online')} (latency: {latency})")
            
        elif "MAC Address:" in line:
            mac_info = line.split("MAC Address:", 1)[1].strip()
            print(f"   MAC: {mac_info}")
            
        elif "Running:" in line:
            os_info = line.split("Running:", 1)[1].strip()
            print(f"   OS: {os_info}")
            
        elif "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                print(f"   {emojify('🔓', '-') } {port} - {service} {version}")
                
        elif "/udp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                print(f"   {emojify('📡', '-') } {port} - {service} (UDP)")
    
    print("-" * 40)
    print("\n" + emojify("📄 Raw Output:", "Raw Output:") )
    print("-" * 20)
    print(output)

def display_organized_results_xml(xml_path):
    """Parse Nmap XML output and display structured results."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for host in root.findall('host'):
        status = host.find('status')
        addr = host.find("address[@addrtype='ipv4']") or host.find("address[@addrtype='ipv6']")
        hostname_el = host.find('hostnames/hostname')
        addr_text = addr.get('addr') if addr is not None else 'unknown'
        hostname = hostname_el.get('name') if hostname_el is not None else None
        title = hostname or addr_text
        print(f"{emojify('💻 Host:', 'Host:')} {title}")
        if status is not None and status.get('state') == 'up':
            print(f"   {emojify('🟢 Online', 'Online')}")
        # OS
        osmatch = host.find('os/osmatch')
        if osmatch is not None:
            print(f"   OS: {osmatch.get('name')}")
        # MAC
        mac = host.find("address[@addrtype='mac']")
        if mac is not None:
            vendor = mac.get('vendor') or ''
            print(f"   MAC: {mac.get('addr')} {('('+vendor+')') if vendor else ''}")
        # Ports
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                service = port.find('service')
                name = service.get('name') if service is not None else 'unknown'
                product = service.get('product') if service is not None else ''
                version = service.get('version') if service is not None else ''
                extrainfo = service.get('extrainfo') if service is not None else ''
                details = " ".join([x for x in [product, version, extrainfo] if x])
                print(f"   {emojify('🔓', '-') } {port.get('portid')}/{port.get('protocol')} - {name} {details}")
        print("-" * 40)

def display_help():
    """Display comprehensive help information about nmap parameters"""
    print("\n" + emojify("📚 Comprehensive Nmap Parameters Guide:", "Nmap Parameters Guide:") )
    print("=" * 50)
    
    print("\n🔍 SCAN TECHNIQUES:")
    print("-sS: TCP SYN scan (stealth, default)")
    print("-sT: TCP connect scan (full connection)")
    print("-sU: UDP scan")
    print("-sN: TCP NULL scan (no flags)")
    print("-sF: TCP FIN scan")
    print("-sX: TCP XMAS scan (FIN+PSH+URG)")
    print("-sA: TCP ACK scan (firewall rules)")
    print("-sW: TCP Window scan")
    print("-sM: TCP Maimon scan")
    print("-sI: Idle scan (zombie host)")
    print("-sn: Ping scan (no port scan)")
    
    print("\n👁️ HOST DISCOVERY:")
    print("-PE: ICMP echo discovery")
    print("-PP: ICMP timestamp discovery")
    print("-PM: ICMP netmask discovery")
    print("-PS: TCP SYN discovery")
    print("-PA: TCP ACK discovery")
    print("-PU: UDP discovery")
    print("-PR: ARP discovery (local network)")
    print("-Pn: Skip host discovery")
    
    print("\n🔎 PORT SPECIFICATION:")
    print("-p-: Scan all 65535 ports")
    print("-F: Fast scan (top 1000 ports)")
    print("-p 22,80,443: Specific ports")
    print("-p 1-100: Port range")
    print("--top-ports 100: Most common ports")
    
    print("\n📊 SERVICE/VERSION DETECTION:")
    print("-sV: Version detection")
    print("-sC: Default scripts")
    print("-A: Aggressive scan (OS+version+scripts)")
    print("--version-all: Try all version probes")
    print("--version-trace: Show version detection")
    
    print("\n🖥️ OS DETECTION:")
    print("-O: Enable OS detection")
    print("--osscan-guess: Aggressive OS guessing")
    print("--osscan-limit: Limit to promising targets")
    
    print("\n🙈 FIREWALL/IDS EVASION:")
    print("-f: Fragment packets")
    print("-D: Decoy scan with fake IPs")
    print("-S: Source IP spoofing")
    print("--data-length: Random data padding")
    print("--scan-delay: Delay between probes")
    print("--randomize-hosts: Random target order")
    
    print("\n⏱️ TIMING TEMPLATES:")
    print("-T0: Paranoid (5min delays)")
    print("-T1: Sneaky (15sec delays)")
    print("-T2: Polite (0.4sec delays)")
    print("-T3: Normal (default)")
    print("-T4: Aggressive (faster)")
    print("-T5: Insane (very fast)")
    
    print("\n📝 OUTPUT OPTIONS:")
    print("-v: Verbose output")
    print("-vv: Very verbose")
    print("--open: Show only open ports")
    print("--reason: Show port state reasons")
    print("--traceroute: Trace network path")
    
    print("\n📜 SCRIPTS (NSE):")
    print("--script=default: Default scripts")
    print("--script=vuln: Vulnerability detection")
    print("--script=exploit: Safe exploits")
    print("--script=discovery: Host discovery")
    print("--script=broadcast: Broadcast scripts")

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Non-POSIX: assume not root
        return False

def adjust_for_privileges(cmd):
    """If not root, replace -sS with -sT and warn; note OS detection may be less reliable."""
    if not is_root() and "-sS" in cmd:
        print("Note: Not running as root, switching -sS (SYN) to -sT (TCP connect). Consider using sudo for SYN scans.")
        idx = cmd.index("-sS")
        cmd[idx] = "-sT"
    if not is_root() and ("-O" in cmd or "-A" in cmd):
        print("Note: OS detection may be less accurate without root privileges.")
    return cmd

def parse_cidr_hostcount(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.num_addresses
    except Exception:
        return None

def main():
    """Main function"""
    global USE_EMOJI

    parser = argparse.ArgumentParser(description="Interactive/CLI Nmap wrapper with smart defaults")
    parser.add_argument("--target", help="Target IP/hostname or CIDR")
    parser.add_argument("--mode", choices=["single", "network"], help="Scan mode")
    parser.add_argument("--scan-type", dest="scan_type", help="Scan type number (from menu)")
    parser.add_argument("--timing", choices=["T0","T1","T2","T3","T4","T5"], help="Timing template")
    parser.add_argument("--firewall", choices=["0","1","2"], help="Firewall profile: 0=None, 1=Moderate, 2=Strong")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip host discovery (-Pn)")
    parser.add_argument("--ports", help="Port list/range for -p")
    parser.add_argument("--top-ports", type=int, help="Use --top-ports N")
    parser.add_argument("--udp", action="store_true", help="Include UDP (-sU)")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports (-p-)")
    parser.add_argument("--scripts", help="NSE scripts (e.g., default,vuln)")
    parser.add_argument("--script-args", dest="script_args", help="NSE script args")
    parser.add_argument("--output-dir", help="Directory to save results")
    parser.add_argument("--no-confirm", action="store_true", help="Do not ask to confirm before running")
    parser.add_argument("--no-emoji", action="store_true", help="Disable emoji output")
    parser.add_argument("--no-dns", action="store_true", help="Disable reverse DNS (-n)")
    parser.add_argument("--no-save", action="store_true", help="Do not save -oA outputs")

    args = parser.parse_args()
    USE_EMOJI = not args.no_emoji

    print(emojify("🔍 Nmap Scanner", "Nmap Scanner"))
    print("=" * 40)
    print("This tool helps you perform network reconnaissance with guided questions or CLI flags.")

    # If fully interactive (no target provided), optionally show help
    if not args.target:
        show_help = input("\nWould you like to see nmap parameters guide first? (y/n): ").lower().strip()
        if show_help == 'y':
            display_help()

    try:
        # Determine parameters either from CLI args or interactive prompts
        if args.target:
            target = args.target
            scan_mode = args.mode or ("network" if "/" in target else "single")
            firewall_profile = {"opts": []}
            if args.firewall == "1":
                firewall_profile = {"opts": ["-f", "--randomize-hosts", "-D", "RND:10"]}
            elif args.firewall == "2":
                firewall_profile = {"opts": ["-f", "-f", "--randomize-hosts", "-D", "RND:20", "--data-length", str(random.randint(10, 50))]}
            scan_type = args.scan_type or ("1" if scan_mode == "network" else "1")
            timing_opts = ["-" + args.timing] if args.timing else ["-T3"]
            skip_discovery = args.skip_discovery
        else:
            target, scan_mode = get_target()
            fw = ask_firewall()
            firewall_profile = {"opts": fw["opts"]}
            skip_discovery = fw["skip_discovery"]
            scan_type = ask_scan_type(scan_mode)
            timing_opts = ask_timing()

        # Build command
        output_base = None
        if args.output_dir:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_base = os.path.join(args.output_dir, f"scan-{ts}")

        nmap_cmd, outputs = build_nmap_command(
            target=target,
            scan_mode=scan_mode,
            firewall_profile=firewall_profile,
            scan_type=scan_type,
            timing_opts=timing_opts,
            skip_discovery=args.skip_discovery if args.target else skip_discovery,
            no_dns=args.no_dns,
            ports=args.ports,
            top_ports=args.top_ports,
            scripts=args.scripts,
            script_args=args.script_args,
            udp=args.udp,
            all_ports=args.all_ports,
            save_outputs=not args.no_save,
            output_base=output_base,
        )

        # Adjust for privileges
        nmap_cmd = adjust_for_privileges(nmap_cmd)

        # Display command and summary
        print(f"\n{emojify('📋 Generated command:', 'Command:')} {' '.join(nmap_cmd)}")

        if scan_mode == "network":
            print(f"{emojify('🏠 Scanning local/network range:', 'Scanning range:')} {target}")
            print(emojify("⚠️  Only scan hosts you are authorized to test.", "WARNING: Only scan hosts you are authorized to test."))
        else:
            print(f"{emojify('🎯 Scanning single target:', 'Scanning target:')} {target}")
            print(emojify("⚠️  Only scan systems you are authorized to test.", "WARNING: Only scan systems you are authorized to test."))

        # Show estimated time
        estimate_scan_time(nmap_cmd, scan_mode)

        # Confirm before running
        if args.no_confirm:
            confirm = 'y'
        else:
            confirm = input("\nRun this scan? (y/n): ").lower().strip()
        if confirm == 'y':
            run_nmap(nmap_cmd)
        else:
            print("Scan cancelled.")

    except KeyboardInterrupt:
        progress_tracker.stop = True
        print("\n\n" + emojify("👋 Scan interrupted by user.", "Scan interrupted by user."))
        sys.exit(0)
    except Exception as e:
        progress_tracker.stop = True
        print("\n" + emojify(f"❌ Unexpected error: {e}", f"Unexpected error: {e}"))
        sys.exit(1)

def estimate_scan_time(cmd, scan_mode):
    """Provide scan time estimates"""
    print("\n" + emojify("⏱️ Estimated scan time:", "Estimated scan time:") )

    timing_map = {
        "-T5": ("⚡ Very fast (seconds to few minutes)", "Very fast"),
        "-T4": ("🚀 Fast (1-10 minutes)", "Fast"),
        "-T3": ("📊 Normal (5-30 minutes)", "Normal"),
        "-T2": ("🐢 Slow (15-60 minutes)", "Slow"),
        "-T1": ("🐌 Very slow (30+ minutes)", "Very slow"),
        "-T0": ("🐌🐌 Extremely slow (hours)", "Extremely slow"),
    }
    selected = None
    for key, txt in timing_map.items():
        if key in cmd:
            selected = txt[0] if USE_EMOJI else txt[1]
            break
    if selected:
        print(selected)

    # Estimate host count
    target = cmd[-1] if cmd else ""
    hostcount = parse_cidr_hostcount(target)
    if scan_mode == "network" and hostcount:
        approx = hostcount
        print(emojify(f"🏠 Range includes ~{approx} addresses", f"Range includes ~{approx} addresses"))

    # Ports heuristic
    if "-p-" in cmd:
        print(emojify("⚠️ Full port scan will take significantly longer", "WARNING: Full port scan is longer"))
    elif "--top-ports" in cmd:
        try:
            idx = cmd.index("--top-ports")
            n = cmd[idx+1]
            print(f"Top ports: {n}")
        except Exception:
            pass
    elif "-F" in cmd:
        print("Fast scan of top 1000 TCP ports")

    if "-sU" in cmd:
        print(emojify("📡 UDP scanning adds significant time", "UDP scanning adds significant time"))

if __name__ == "__main__":
    main()