# Nmap.py

An interactive and CLI-friendly wrapper around nmap that streamlines common scans, adds smart defaults, saves results automatically, and can present structured results from XML output.

## Features
- Guided interactive mode or fully non-interactive CLI mode
- Smart host discovery control (only uses `-Pn` when appropriate)
- Privilege awareness (auto-switches `-sS` to `-sT` when not root; warns for OS detection)
- Robust subprocess handling and progress display
- Automatic output saving with `-oA` to timestamped files (XML, greppable, and normal)
- XML parsing for reliable, structured results (falls back to parsing stdout)
- Improved local network detection (attempts true CIDR; falls back to `/24`)
- Simple UX toggles like `--no-emoji`, `--no-confirm`, `--no-dns`, `--no-save`

## Requirements
- Python 3.8+
- nmap installed on your system
  - macOS: `brew install nmap`
  - Ubuntu/Debian: `sudo apt-get install nmap`
  - CentOS/RHEL: `sudo yum install nmap`
- Optional: `netifaces` for more accurate local network detection
  - `pip install netifaces`

## Installation
No installation required. Place `Nmap.py` anywhere on your system. Example:

```bash
# optional: create a Python virtual environment
python3 -m venv .venv && source .venv/bin/activate

# optional: better local network detection
pip install netifaces
```

## Usage
You can run the script in two ways: interactive (guided prompts) or non-interactive (CLI flags).

### Interactive mode
```bash
python3 Nmap.py
```
You will be asked to select a target (single host or local network), a firewall profile, a scan type, and timing. The script shows an estimated duration, asks for confirmation, then runs the scan and saves results.

### Non-interactive CLI mode
Provide flags to skip prompts. Minimal example:
```bash
python3 Nmap.py --target 192.168.1.10 --mode single --scan-type 1 --timing T4 --no-confirm
```

#### CLI options
- `--target` Target IP/hostname or CIDR (e.g., `192.168.1.0/24`)
- `--mode` `single` or `network` (defaults to `network` if CIDR is provided, else `single`)
- `--scan-type` Menu number for scan type (see below)
- `--timing` One of `T0`..`T5` (defaults to `T3`)
- `--firewall` `0` (none), `1` (moderate), `2` (strong); adds light/strong evasion options
- `--skip-discovery` Skip host discovery (`-Pn`) when appropriate
- `--ports` Custom port list/range for `-p` (e.g., `22,80,443` or `1-1024`)
- `--top-ports` Use `--top-ports N`
- `--udp` Include UDP scan (`-sU`)
- `--all-ports` Scan all ports (`-p-`)
- `--scripts` NSE scripts (e.g., `default,vuln`)
- `--script-args` NSE script arguments
- `--output-dir` Directory to save result files (default: `results/scan-YYYYmmdd-HHMMSS`)
- `--no-confirm` Run without interactive confirmation
- `--no-emoji` Disable emoji in output
- `--no-dns` Disable reverse DNS (`-n`) to speed up scans
- `--no-save` Do not save `-oA` outputs

#### Scan types (menu numbers)
Network mode:
1. Network Discovery (ping sweep + ARP)
2. Basic Network Scan (discovery + top ports + version)
3. Service Detection (versions + banners)
4. OS Fingerprinting (TCP/IP stack analysis)
5. Advanced Device Discovery (OS + services + MAC vendors)
6. Stealth SYN Scan (half-open)
7. UDP Scan (common UDP services)
8. Comprehensive Network Audit (balanced, uses `-A` with top ports)

Single target mode:
1. TCP SYN Scan (stealth)
2. TCP Connect Scan (full connection)
3. UDP Scan
4. FIN Scan
5. NULL Scan
6. XMAS Scan
7. ACK Scan
8. Window Scan
9. Maimon Scan
10. Idle Scan (zombie host)
11. Service Version Detection
12. OS Detection
13. Script Scan (default,vuln)
14. Comprehensive Target Audit (`-A -p-`)

## Examples
- Quick single-host SYN scan with faster timing:
  ```bash
  python3 Nmap.py --target 192.168.1.10 --mode single --scan-type 1 --timing T4 --no-confirm
  ```
- Discover hosts on local network:
  ```bash
  python3 Nmap.py --target 192.168.1.0/24 --mode network --scan-type 1 --no-confirm --no-dns
  ```
- UDP top 200 ports on a host with output saved to `scans/`:
  ```bash
  python3 Nmap.py --target 10.0.0.5 --mode single --scan-type 3 --udp --top-ports 200 --no-confirm --output-dir scans
  ```
- Comprehensive single-host audit:
  ```bash
  python3 Nmap.py --target example.com --mode single --scan-type 14 --timing T4 --no-confirm
  ```

## Output files
By default, results are saved with `-oA` to `results/scan-YYYYmmdd-HHMMSS`:
- `scan-*.nmap` Human-readable output
- `scan-*.gnmap` Greppable output
- `scan-*.xml` XML output (used for reliable structured parsing in the script)

You can change the destination using `--output-dir`, or disable saving with `--no-save`.

## Privileges
- Some scans (e.g., SYN `-sS`, parts of OS detection, UDP behaviors) require root for best results.
- If not running as root, the script will automatically switch `-sS` to `-sT` and warn you. OS detection may be less accurate.

## Host discovery and DNS
- The script only applies `-Pn` (skip discovery) when explicitly requested (via `--skip-discovery` or high firewall profile) and when it won’t defeat a pure discovery scan.
- Use `--no-dns` (adds `-n`) to speed up scans by disabling reverse DNS lookups.


## Troubleshooting
- `nmap not found`: Install nmap (see Requirements) and ensure it is in your PATH.
- Empty/partial results: Try `--timing T4` or remove `--skip-discovery`. Consider running with elevated privileges for SYN/OS detection.
- Slow scans: Avoid `-p-` or large UDP scans; use `--top-ports` or `-F` and `--no-dns`.
- XML parsing error: The script will fall back to parsing stdout. You can inspect the corresponding `.xml` in the results folder.

