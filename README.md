# THM Recon Tool 🚩

> Fast nmap automation for **TryHackMe** CTF rooms — optimised for speed when every second counts.

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- 🖥️ **Desktop GUI** (`thm_gui.py`) — dark-themed Tkinter window, no browser needed, built into Python
- ⚡ **Two-phase scanning** — quick top-1000 port scan first so you see open ports *immediately*, then a deep full-port scan in the background
- 📁 **Auto-creates output folder** named `BoxName_IP/` so results are always organised
- 💾 **Saves all nmap formats** — `.nmap` (readable), `.xml` (for tools), `.gnmap` (grep-friendly)
- 🔍 **Service & version detection** (`-sV -sC`)
- 🖥️ **OS fingerprinting** (`-O`)
- 🐛 **NSE Vulnerability scripts** (`--script=vuln`)
- 🎨 **Colourful terminal output** via `rich` (with plain ANSI fallback — no hard dependency)
- 🪟 Works on **Windows** and **Linux**

---

## Requirements

- **Python 3.7+**
- **nmap** installed and in your PATH

### Install nmap

**Linux (Debian/Ubuntu)**
```bash
sudo apt update && sudo apt install nmap -y
```

**Linux (Fedora/CentOS)**
```bash
sudo yum install nmap
```

**Windows**
Download from: https://nmap.org/download.html
(Make sure to tick *"Add to PATH"* during install)

### Install Python dependencies (optional but recommended)

```bash
pip install -r requirements.txt
```

> Without `rich`, the tool still works — output just uses plain ANSI colours.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/thm-scan-tool.git
cd thm-scan-tool
pip install -r requirements.txt
```

---

## GUI (Recommended)

Launch the dark-themed desktop app — no command line needed:

```bash
python thm_gui.py
```

Fill in the Target IP and Box Name, pick your scan mode, and hit **Start Scan**. Open ports appear live in the Output tab and are automatically collected in the **Open Ports** tab as a clean table.

---

## CLI Usage

```bash
# Basic scan — quick scan first, then full deep scan
python thm_scan.py <IP> <BoxName>

# Quick scan only (fastest — good for getting started immediately)
python thm_scan.py <IP> <BoxName> --quick-only

# Scan specific ports only
python thm_scan.py <IP> <BoxName> --ports 22,80,443,8080

# Skip vuln scripts (faster deep scan, still gets service versions + OS)
python thm_scan.py <IP> <BoxName> --skip-vuln

# Change timing (0=slowest, 5=insane, default=4)
python thm_scan.py <IP> <BoxName> --timing 3
```

### Linux — full OS detection (requires root)

```bash
sudo python3 thm_scan.py 10.10.10.10 mybox
```

### Windows — full OS detection (requires Administrator)

Run your terminal as **Administrator**, then:
```
python thm_scan.py 10.10.10.10 mybox
```

---

## Example

```
$ python thm_scan.py 10.10.123.45 retro --skip-vuln

╔════════════════════════════════════════════╗
║         THM RECON TOOL                     ║
║   TryHackMe Fast Scanner — CTF Edition     ║
╚════════════════════════════════════════════╝

[+] Target  : 10.10.123.45
[+] Box Name: retro

── PHASE 1 — Quick Scan (Top 1000 Ports) ──────────────────
[+] Command: nmap -sV -sC --open -T4 -oA retro_10.10.123.45/quick_scan 10.10.123.45

  80/tcp   open  http     Microsoft IIS httpd 10.0
  3389/tcp open  ms-wbt-server

┌─────────── ⚡ Quick Scan — Open Ports ────────────────┐
│ PORT/PROTO  STATE  SERVICE      VERSION               │
│ 80/tcp      open   http         Microsoft IIS 10.0    │
│ 3389/tcp    open   ms-wbt-server                      │
└───────────────────────────────────────────────────────┘

── PHASE 2 — Deep Scan (All Ports + OS + Services) ────────
...
```

### Output folder structure

```
retro_10.10.123.45/
├── quick_scan.nmap     ← human-readable
├── quick_scan.xml      ← import into Metasploit / other tools
├── quick_scan.gnmap    ← grep-friendly
├── deep_scan.nmap
├── deep_scan.xml
└── deep_scan.gnmap
```

---

## Options Reference

| Flag | Description |
|------|-------------|
| `ip` | Target IP address |
| `box_name` | Room/box name (used for folder name) |
| `--quick-only` | Run only the top-1000 quick scan |
| `--ports PORTS` | Comma-separated ports (e.g. `22,80,443`) |
| `--skip-vuln` | Skip `--script=vuln` (faster) |
| `--timing T` | Nmap timing template 0–5 (default: `4`) |

---

## Tips for CTF

1. **Start here** — run the quick scan first and immediately start investigating open web ports (80, 443, 8080) while the deep scan runs
2. **Gobuster / ffuf** — use open HTTP ports to start directory brute-forcing in parallel
3. **XML output** — import `deep_scan.xml` into Metasploit with `db_import` for easy service tracking
4. **Grep the gnmap** — `grep "open" retro_10.10.123.45/quick_scan.gnmap` for a clean port list

---

## Disclaimer

This tool is intended for use on **machines you own or have explicit permission to test**, such as TryHackMe and HackTheBox lab environments. Unauthorised scanning is illegal.

---

## License

MIT
