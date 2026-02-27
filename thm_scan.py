#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════╗
║          THM RECON TOOL - TryHackMe CTF Scanner        ║
║      Fast nmap automation for Capture The Flag         ║
╚════════════════════════════════════════════════════════╝

Usage:
    python thm_scan.py <IP> <BoxName>
    python thm_scan.py <IP> <BoxName> --quick-only
    python thm_scan.py <IP> <BoxName> --ports 80,443,8080
    python thm_scan.py <IP> <BoxName> --skip-vuln

GitHub: https://github.com/YOUR_USERNAME/thm-scan-tool
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

# ── Optional rich import (graceful fallback to plain output) ──────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

# ── Colours for fallback (ANSI) ───────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# On Windows, ANSI codes need enabling
if sys.platform == "win32":
    os.system("")   # enables ANSI escape codes in Windows terminal


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    if RICH:
        console.print(Panel.fit(
            "[bold cyan]THM RECON TOOL[/bold cyan]\n"
            "[dim]TryHackMe Fast Scanner — CTF Edition[/dim]",
            border_style="cyan"
        ))
    else:
        print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}{BOLD}  THM RECON TOOL — TryHackMe Fast Scanner{RESET}")
        print(f"{CYAN}{BOLD}{'='*60}{RESET}\n")


def info(msg):
    if RICH:
        console.print(f"[bold green][+][/bold green] {msg}")
    else:
        print(f"{GREEN}[+]{RESET} {msg}")


def warn(msg):
    if RICH:
        console.print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        print(f"{YELLOW}[!]{RESET} {msg}")


def error(msg):
    if RICH:
        console.print(f"[bold red][✗][/bold red] {msg}")
    else:
        print(f"{RED}[✗]{RESET} {msg}")


def section(title):
    if RICH:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}")
        print(f"{CYAN}{BOLD}  {title}{RESET}")
        print(f"{CYAN}{BOLD}{'─'*60}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Core functions
# ─────────────────────────────────────────────────────────────────────────────

def check_nmap() -> bool:
    """Verify nmap is available in PATH."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=10
        )
        version_line = result.stdout.splitlines()[0] if result.stdout else "nmap found"
        info(f"Found: {version_line}")
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def create_output_dir(box_name: str, ip: str) -> Path:
    """Create and return the output directory for this box."""
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in box_name)
    dir_name = f"{safe_name}_{ip}"
    path = Path(dir_name)
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_nmap(ip: str, output_base: Path, nmap_args: list, label: str):
    """
    Run nmap, stream output live, save to file, and return (returncode, full_output).
    output_base is the path prefix used for -oA (no extension).
    """
    cmd = ["nmap"] + nmap_args + ["-oA", str(output_base), ip]

    info(f"Command: {' '.join(cmd)}\n")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        collected = []
        for line in process.stdout:
            # Strip trailing newline for rich; re-add for plain
            stripped = line.rstrip()
            if RICH:
                # Highlight open ports in green
                if "open" in stripped and ("/tcp" in stripped or "/udp" in stripped):
                    console.print(f"  [bold green]{stripped}[/bold green]")
                elif stripped.startswith("Nmap scan report"):
                    console.print(f"  [cyan]{stripped}[/cyan]")
                elif stripped.startswith("PORT") or stripped.startswith("Host is"):
                    console.print(f"  [bold]{stripped}[/bold]")
                else:
                    console.print(f"  {stripped}")
            else:
                if "open" in stripped and ("/tcp" in stripped or "/udp" in stripped):
                    print(f"  {GREEN}{stripped}{RESET}")
                else:
                    print(f"  {stripped}")
            collected.append(line)

        process.wait()
        return process.returncode, "".join(collected)

    except FileNotFoundError:
        error("nmap not found — is it installed and in your PATH?")
        sys.exit(1)


def parse_open_ports(nmap_output: str) -> list:
    """Extract open port lines from nmap output."""
    ports = []
    for line in nmap_output.splitlines():
        if ("open" in line) and ("/tcp" in line or "/udp" in line):
            ports.append(line.strip())
    return ports


def print_port_summary(ports: list, title: str = "Open Ports Summary"):
    if not ports:
        warn("No open ports found in this scan phase.")
        return

    if RICH:
        table = Table(title=title, border_style="cyan", header_style="bold cyan")
        table.add_column("Port/Proto", style="bold green", no_wrap=True)
        table.add_column("State",      style="green",      no_wrap=True)
        table.add_column("Service",    style="yellow")
        table.add_column("Version",    style="dim")

        for line in ports:
            parts = line.split(None, 3)
            port    = parts[0] if len(parts) > 0 else ""
            state   = parts[1] if len(parts) > 1 else ""
            service = parts[2] if len(parts) > 2 else ""
            version = parts[3] if len(parts) > 3 else ""
            table.add_row(port, state, service, version)

        console.print(table)
    else:
        print(f"\n{GREEN}{BOLD}  {title}{RESET}")
        print(f"  {'─'*50}")
        for p in ports:
            print(f"  {GREEN}{p}{RESET}")
        print(f"  {'─'*50}")


def check_root_warning(args_list: list):
    """Warn if OS detection is requested but we're not root/admin."""
    needs_root = "-O" in args_list or "--osscan-guess" in args_list
    if needs_root:
        if sys.platform == "win32":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                warn("OS detection (-O) requires Administrator privileges on Windows.")
                warn("Run this script as Administrator for full results.")
        else:
            if os.geteuid() != 0:
                warn("OS detection (-O) requires root privileges on Linux.")
                warn("Run with: sudo python3 thm_scan.py ...")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="THM Recon Tool — Fast nmap scanner for TryHackMe CTF rooms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python thm_scan.py 10.10.10.10 mybox
  python thm_scan.py 10.10.10.10 mybox --quick-only
  python thm_scan.py 10.10.10.10 mybox --ports 80,443,8080
  python thm_scan.py 10.10.10.10 mybox --skip-vuln
  sudo python3 thm_scan.py 10.10.10.10 mybox           (Linux, full OS detect)
"""
    )
    parser.add_argument("ip",        help="Target IP address")
    parser.add_argument("box_name",  help="Box / room name (used to name the output folder)")
    parser.add_argument("--quick-only",  action="store_true",
                        help="Only run the quick scan, skip the deep scan")
    parser.add_argument("--ports",   metavar="PORTS",
                        help="Comma-separated ports to scan instead of defaults (e.g. 22,80,443)")
    parser.add_argument("--skip-vuln", action="store_true",
                        help="Skip NSE vulnerability scripts (faster deep scan)")
    parser.add_argument("--timing",  metavar="T", type=int, default=4, choices=range(0, 6),
                        help="Nmap timing template 0-5 (default: 4 = aggressive)")
    args = parser.parse_args()

    # ── Banner ────────────────────────────────────────────────────────────────
    banner()
    start_time = datetime.now()

    if RICH:
        console.print(f"  [bold]Target  :[/bold] [cyan]{args.ip}[/cyan]")
        console.print(f"  [bold]Box Name:[/bold] [cyan]{args.box_name}[/cyan]")
        console.print(f"  [bold]Started :[/bold] {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    else:
        print(f"  Target  : {args.ip}")
        print(f"  Box Name: {args.box_name}")
        print(f"  Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── Check nmap ────────────────────────────────────────────────────────────
    section("Checking Requirements")
    if not check_nmap():
        error("nmap not found! Install it first:")
        error("  Linux : sudo apt install nmap   /  sudo yum install nmap")
        error("  Windows: https://nmap.org/download.html")
        sys.exit(1)

    # ── Create output directory ───────────────────────────────────────────────
    output_dir = create_output_dir(args.box_name, args.ip)
    info(f"Output folder: {output_dir.resolve()}")

    # ── PHASE 1: Quick scan ───────────────────────────────────────────────────
    section("PHASE 1 — Quick Scan  (Top 1000 Ports)")

    quick_base  = output_dir / "quick_scan"
    quick_flags = [
        "-sV", "-sC",
        "--open",
        f"-T{args.timing}",
    ]
    if args.ports:
        quick_flags += ["-p", args.ports]

    _, quick_text = run_nmap(args.ip, quick_base, quick_flags, "Quick Scan")

    quick_ports = parse_open_ports(quick_text)
    print_port_summary(quick_ports, "⚡ Quick Scan — Open Ports")

    if args.quick_only:
        info("Quick scan complete (--quick-only). Skipping deep scan.")
        info(f"Results saved to: {output_dir.resolve()}")
        return

    # ── PHASE 2: Deep scan ────────────────────────────────────────────────────
    section("PHASE 2 — Deep Scan  (All Ports + OS + Services + Vulns)")

    check_root_warning(["-O"])   # warn before we start

    deep_base  = output_dir / "deep_scan"
    deep_flags = [
        "-sV", "-sC",
        "-O",
        "-p-",          # all 65535 ports
        "--open",
        f"-T{args.timing}",
    ]
    if not args.skip_vuln:
        deep_flags += ["--script=vuln"]

    _, deep_text = run_nmap(args.ip, deep_base, deep_flags, "Deep Scan")

    deep_ports = parse_open_ports(deep_text)
    print_port_summary(deep_ports, "🔍 Deep Scan — Open Ports")

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed = datetime.now() - start_time
    section("SCAN COMPLETE")

    if RICH:
        summary = Table(show_header=False, border_style="green", padding=(0, 1))
        summary.add_column(style="bold green")
        summary.add_column(style="cyan")
        summary.add_row("Box Name",    args.box_name)
        summary.add_row("Target IP",   args.ip)
        summary.add_row("Elapsed",     str(elapsed).split(".")[0])
        summary.add_row("Output dir",  str(output_dir.resolve()))
        summary.add_row("Files",
            "quick_scan.nmap / .xml / .gnmap\n"
            "deep_scan.nmap  / .xml / .gnmap"
        )
        console.print(summary)
        console.print("\n[bold green]Happy hacking! 🚩[/bold green]\n")
    else:
        print(f"\n  Box Name  : {args.box_name}")
        print(f"  Target IP : {args.ip}")
        print(f"  Elapsed   : {str(elapsed).split('.')[0]}")
        print(f"  Output    : {output_dir.resolve()}")
        print(f"\n  Files saved:")
        print(f"    quick_scan.nmap / .xml / .gnmap")
        print(f"    deep_scan.nmap  / .xml / .gnmap")
        print(f"\n{GREEN}Happy hacking! 🚩{RESET}\n")


if __name__ == "__main__":
    main()
