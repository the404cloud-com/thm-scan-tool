#!/usr/bin/env python3
"""
THM Recon Tool — Tkinter GUI
Dark-themed desktop launcher for the TryHackMe nmap scanner.

Usage:
    python thm_gui.py
    (or double-click it in Windows Explorer / Linux file manager)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import sys
import os
from pathlib import Path
from datetime import datetime

# ── Colour palette (dark hacker theme) ───────────────────────────────────────
BG          = "#0d1117"   # main background
BG2         = "#161b22"   # panel/frame background
BORDER      = "#30363d"   # border colour
GREEN       = "#39d353"   # primary accent / open ports
CYAN        = "#58a6ff"   # headings / labels
YELLOW      = "#e3b341"   # warnings
RED         = "#f85149"   # errors
DIM         = "#8b949e"   # secondary text
WHITE       = "#e6edf3"   # normal text
BTN_BG      = "#238636"   # start button bg
BTN_HOVER   = "#2ea043"   # start button hover
BTN_STOP_BG = "#da3633"   # stop button bg

FONT_MONO   = ("Consolas", 10)
FONT_LABEL  = ("Segoe UI", 10)
FONT_TITLE  = ("Segoe UI", 14, "bold")
FONT_SMALL  = ("Segoe UI", 9)

# ── Well-known port → service name lookup ─────────────────────────────────────
KNOWN_PORTS = {
    "20": "ftp-data",    "21": "ftp",          "22": "ssh",
    "23": "telnet",      "25": "smtp",          "53": "dns",
    "67": "dhcp",        "68": "dhcp",          "69": "tftp",
    "80": "http",        "88": "kerberos",      "110": "pop3",
    "111": "rpcbind",    "119": "nntp",         "123": "ntp",
    "135": "msrpc",      "137": "netbios-ns",   "138": "netbios-dgm",
    "139": "netbios-ssn","143": "imap",         "161": "snmp",
    "389": "ldap",       "443": "https",        "445": "smb",
    "465": "smtps",      "500": "ike",          "514": "syslog",
    "587": "smtp-sub",   "636": "ldaps",        "873": "rsync",
    "902": "vmware",     "993": "imaps",        "995": "pop3s",
    "1080": "socks",     "1194": "openvpn",     "1433": "mssql",
    "1521": "oracle",    "1723": "pptp",        "2049": "nfs",
    "2222": "ssh-alt",   "2375": "docker",      "2376": "docker-tls",
    "3000": "dev-server","3306": "mysql",       "3389": "rdp",
    "3690": "svn",       "4000": "http-alt",    "4443": "https-alt",
    "4444": "shell",     "4505": "salt",        "5000": "flask",
    "5432": "postgresql","5555": "adb",         "5601": "kibana",
    "5800": "vnc-http",  "5900": "vnc",         "5985": "winrm-http",
    "5986": "winrm-https","6379": "redis",      "6443": "k8s-api",
    "7001": "weblogic",  "8000": "http-alt",    "8080": "http-proxy",
    "8081": "http-alt",  "8443": "https-alt",   "8888": "http-alt",
    "9000": "php-fpm",   "9090": "http-alt",    "9200": "elasticsearch",
    "9300": "elasticsearch","10000": "webmin",  "11211": "memcached",
    "27017": "mongodb",  "27018": "mongodb",    "50000": "db2",
}


class THMScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("THM Recon Tool 🚩")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(780, 620)

        # Center on screen
        self.geometry("900x700")
        self._center_window()

        self._scan_process = None
        self._scan_thread  = None
        self._scanning     = False
        self._port_count   = 0
        self._port_rows    = {}   # port_str -> treeview iid, for live updates

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _center_window(self):
        self.update_idletasks()
        w, h = 900, 700
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - w) // 2
        y  = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Title bar ─────────────────────────────────────────────────────────
        title_frame = tk.Frame(self, bg=BG2, pady=10)
        title_frame.pack(fill="x", padx=0)

        tk.Label(
            title_frame, text="🚩  THM RECON TOOL",
            font=FONT_TITLE, fg=CYAN, bg=BG2
        ).pack(side="left", padx=20)

        tk.Label(
            title_frame, text="TryHackMe CTF Scanner",
            font=FONT_SMALL, fg=DIM, bg=BG2
        ).pack(side="left", padx=4)

        # nmap version label (top right)
        self._nmap_var = tk.StringVar(value="checking nmap…")
        tk.Label(
            title_frame, textvariable=self._nmap_var,
            font=FONT_SMALL, fg=DIM, bg=BG2
        ).pack(side="right", padx=20)

        # ── Input panel ───────────────────────────────────────────────────────
        input_frame = tk.Frame(self, bg=BG2, padx=20, pady=14)
        input_frame.pack(fill="x", padx=12, pady=(10, 0))

        # Row 1 — Target IP + Box Name
        row1 = tk.Frame(input_frame, bg=BG2)
        row1.pack(fill="x", pady=4)

        self._ip_var   = tk.StringVar()
        self._name_var = tk.StringVar()

        self._make_field(row1, "Target IP",  self._ip_var,   "e.g. 10.10.10.10", 0)
        self._make_field(row1, "Box Name",   self._name_var, "e.g. retro",        1)

        # Row 2 — Options
        row2 = tk.Frame(input_frame, bg=BG2)
        row2.pack(fill="x", pady=(8, 2))

        tk.Label(row2, text="Scan Mode:", font=FONT_LABEL, fg=WHITE, bg=BG2).grid(
            row=0, column=0, sticky="w", padx=(0, 10))

        self._mode_var = tk.StringVar(value="full")
        modes = [("Quick (top 1000)", "quick"), ("Full (all ports)", "full")]
        for i, (label, val) in enumerate(modes):
            rb = tk.Radiobutton(
                row2, text=label, variable=self._mode_var, value=val,
                font=FONT_LABEL, fg=WHITE, bg=BG2,
                selectcolor=BG, activebackground=BG2, activeforeground=CYAN
            )
            rb.grid(row=0, column=i+1, padx=8, sticky="w")

        # Checkboxes
        self._skip_vuln_var = tk.BooleanVar(value=False)
        self._skip_os_var   = tk.BooleanVar(value=False)

        tk.Checkbutton(
            row2, text="Skip vuln scripts (faster)",
            variable=self._skip_vuln_var,
            font=FONT_LABEL, fg=DIM, bg=BG2,
            selectcolor=BG, activebackground=BG2, activeforeground=WHITE
        ).grid(row=0, column=3, padx=16, sticky="w")

        tk.Checkbutton(
            row2, text="Skip OS detection",
            variable=self._skip_os_var,
            font=FONT_LABEL, fg=DIM, bg=BG2,
            selectcolor=BG, activebackground=BG2, activeforeground=WHITE
        ).grid(row=0, column=4, padx=4, sticky="w")

        # Timing
        tk.Label(row2, text="Timing:", font=FONT_LABEL, fg=WHITE, bg=BG2).grid(
            row=0, column=5, padx=(20, 6), sticky="w")
        self._timing_var = tk.StringVar(value="4")
        timing_cb = ttk.Combobox(
            row2, textvariable=self._timing_var,
            values=["0 (paranoid)", "1 (sneaky)", "2 (polite)", "3 (normal)", "4 (aggressive)", "5 (insane)"],
            width=16, state="readonly", font=FONT_SMALL
        )
        timing_cb.grid(row=0, column=6, padx=4, sticky="w")
        self._style_combobox(timing_cb)

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=BG, pady=10)
        btn_frame.pack(fill="x", padx=12)

        self._start_btn = tk.Button(
            btn_frame, text="▶  START SCAN",
            font=("Segoe UI", 11, "bold"),
            fg=WHITE, bg=BTN_BG, activeforeground=WHITE,
            activebackground=BTN_HOVER, relief="flat",
            padx=24, pady=6, cursor="hand2",
            command=self._start_scan
        )
        self._start_btn.pack(side="left", padx=(0, 10))

        self._stop_btn = tk.Button(
            btn_frame, text="⏹  STOP",
            font=("Segoe UI", 11, "bold"),
            fg=WHITE, bg=BTN_STOP_BG, activeforeground=WHITE,
            activebackground="#b91c1c", relief="flat",
            padx=20, pady=6, cursor="hand2",
            command=self._stop_scan, state="disabled"
        )
        self._stop_btn.pack(side="left")

        self._clear_btn = tk.Button(
            btn_frame, text="🗑  Clear",
            font=FONT_LABEL, fg=DIM, bg=BG2,
            activeforeground=WHITE, activebackground=BORDER,
            relief="flat", padx=16, pady=6, cursor="hand2",
            command=self._clear_output
        )
        self._clear_btn.pack(side="left", padx=10)

        # Status label
        self._status_var = tk.StringVar(value="Ready")
        tk.Label(
            btn_frame, textvariable=self._status_var,
            font=FONT_SMALL, fg=DIM, bg=BG
        ).pack(side="right", padx=10)

        # ── Progress bar + ETA ────────────────────────────────────────────────
        prog_frame = tk.Frame(self, bg=BG, padx=12)
        prog_frame.pack(fill="x", pady=(0, 4))

        style = ttk.Style()
        style.configure("scan.Horizontal.TProgressbar",
            troughcolor=BG2, background=GREEN, bordercolor=BG, lightcolor=GREEN, darkcolor=GREEN)

        self._progress_var = tk.DoubleVar(value=0)
        self._progressbar  = ttk.Progressbar(
            prog_frame, variable=self._progress_var,
            maximum=100, mode="determinate", length=200,
            style="scan.Horizontal.TProgressbar"
        )
        self._progressbar.pack(side="left", fill="x", expand=True, padx=(0, 12))

        self._eta_var = tk.StringVar(value="")
        tk.Label(
            prog_frame, textvariable=self._eta_var,
            font=FONT_SMALL, fg=YELLOW, bg=BG, width=28, anchor="w"
        ).pack(side="left")

        # ── Output area ───────────────────────────────────────────────────────
        out_frame = tk.Frame(self, bg=BG, padx=12, pady=4)
        out_frame.pack(fill="both", expand=True, padx=0)

        # Tabs: Output | Open Ports
        self._notebook = ttk.Notebook(out_frame)
        self._notebook.pack(fill="both", expand=True)
        self._style_notebook()

        # Tab 1 — Full output
        output_tab = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(output_tab, text="  Output  ")

        self._output = scrolledtext.ScrolledText(
            output_tab, bg=BG2, fg=WHITE, font=FONT_MONO,
            insertbackground=WHITE, relief="flat",
            wrap="none", state="disabled"
        )
        self._output.pack(fill="both", expand=True, padx=2, pady=2)

        # Tag colours for output highlighting
        self._output.tag_config("green",  foreground=GREEN)
        self._output.tag_config("cyan",   foreground=CYAN)
        self._output.tag_config("yellow", foreground=YELLOW)
        self._output.tag_config("red",    foreground=RED)
        self._output.tag_config("dim",    foreground=DIM)
        self._output.tag_config("bold",   font=("Consolas", 10, "bold"), foreground=WHITE)

        # Tab 2 — Open ports summary
        ports_tab = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(ports_tab, text="  Open Ports  ")

        cols = ("Port", "State", "Service", "Version")
        self._tree = ttk.Treeview(ports_tab, columns=cols, show="headings",
                                   selectmode="browse")
        for col in cols:
            self._tree.heading(col, text=col)
        self._tree.column("Port",    width=110, anchor="w")
        self._tree.column("State",   width=70,  anchor="w")
        self._tree.column("Service", width=130, anchor="w")
        self._tree.column("Version", width=400, anchor="w")
        self._style_treeview()

        vsb = ttk.Scrollbar(ports_tab, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        # ── Status bar ────────────────────────────────────────────────────────
        status_bar = tk.Frame(self, bg=BG2, pady=4)
        status_bar.pack(fill="x", side="bottom")

        self._elapsed_var = tk.StringVar(value="")
        tk.Label(
            status_bar, textvariable=self._elapsed_var,
            font=FONT_SMALL, fg=DIM, bg=BG2
        ).pack(side="right", padx=12)

        self._output_dir_var = tk.StringVar(value="")
        tk.Label(
            status_bar, textvariable=self._output_dir_var,
            font=FONT_SMALL, fg=DIM, bg=BG2
        ).pack(side="left", padx=12)

        # Kick off nmap version check
        threading.Thread(target=self._check_nmap, daemon=True).start()

    # ── Styling helpers ───────────────────────────────────────────────────────

    def _make_field(self, parent, label, var, placeholder, col):
        frame = tk.Frame(parent, bg=BG2)
        frame.grid(row=0, column=col, sticky="ew", padx=(0, 20))
        parent.columnconfigure(col, weight=1)

        tk.Label(frame, text=label, font=FONT_LABEL, fg=CYAN, bg=BG2).pack(anchor="w")

        entry = tk.Entry(
            frame, textvariable=var,
            font=FONT_MONO, fg=WHITE, bg=BG,
            insertbackground=WHITE, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=CYAN
        )
        entry.pack(fill="x", ipady=5)

        # Placeholder behaviour
        var.set(placeholder)
        entry.config(fg=DIM)
        entry.bind("<FocusIn>",  lambda e: (var.set(""), entry.config(fg=WHITE))
                                            if var.get() == placeholder else None)
        entry.bind("<FocusOut>", lambda e: (var.set(placeholder), entry.config(fg=DIM))
                                            if not var.get() else None)
        return entry

    def _style_combobox(self, cb):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TCombobox",
            fieldbackground=BG, background=BG,
            foreground=WHITE, selectbackground=BG2,
            selectforeground=WHITE, bordercolor=BORDER)

    def _style_notebook(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",       background=BG,  borderwidth=0)
        style.configure("TNotebook.Tab",   background=BG2, foreground=DIM,
                        padding=[12, 4],   font=FONT_LABEL)
        style.map("TNotebook.Tab",
            background=[("selected", BG)],
            foreground=[("selected", CYAN)])

    def _style_treeview(self):
        style = ttk.Style()
        style.configure("Treeview",
            background=BG2, foreground=WHITE,
            fieldbackground=BG2, rowheight=24, font=FONT_MONO)
        style.configure("Treeview.Heading",
            background=BG, foreground=CYAN,
            font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("Treeview",
            background=[("selected", BORDER)],
            foreground=[("selected", WHITE)])

    # ── Logic ─────────────────────────────────────────────────────────────────

    def _check_nmap(self):
        try:
            r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10)
            ver = r.stdout.splitlines()[0] if r.stdout else "nmap found"
            self.after(0, lambda: self._nmap_var.set(f"✓ {ver}"))
        except FileNotFoundError:
            self.after(0, lambda: self._nmap_var.set("✗ nmap not found!"))
            self.after(0, lambda: messagebox.showerror(
                "nmap not found",
                "nmap is not installed or not in your PATH.\n\n"
                "Linux:   sudo apt install nmap\n"
                "Windows: https://nmap.org/download.html"
            ))

    def _get_ip(self):
        placeholders = {"e.g. 10.10.10.10", ""}
        v = self._ip_var.get().strip()
        return "" if v in placeholders else v

    def _get_name(self):
        placeholders = {"e.g. retro", ""}
        v = self._name_var.get().strip()
        return "" if v in placeholders else v

    def _start_scan(self):
        ip   = self._get_ip()
        name = self._get_name()

        if not ip:
            messagebox.showwarning("Missing input", "Please enter a Target IP.")
            return
        if not name:
            messagebox.showwarning("Missing input", "Please enter a Box Name.")
            return

        self._scanning    = True
        self._port_count  = 0
        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._status_var.set("Scanning…")
        self._start_time = datetime.now()

        # Reset progress widgets
        self._progress_var.set(0)
        self._eta_var.set("")
        self._port_rows = {}
        self._notebook.tab(1, text="  Open Ports  ")

        # Clear previous results
        self._clear_output(keep_header=True)
        for row in self._tree.get_children():
            self._tree.delete(row)

        # Build nmap command
        timing = self._timing_var.get().split()[0]   # just the digit
        mode   = self._mode_var.get()
        skip_v = self._skip_vuln_var.get()
        skip_o = self._skip_os_var.get()

        flags = ["-sV", "-sC", "--open", f"-T{timing}", "-v", "--stats-every", "5s"]
        if mode == "full":
            flags.append("-p-")
        if not skip_o:
            flags.append("-O")
        if not skip_v and mode == "full":
            flags.append("--script=vuln")

        # Output directory
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        out_dir = Path(f"{safe}_{ip}")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_base = out_dir / ("quick_scan" if mode == "quick" else "full_scan")

        cmd = ["nmap"] + flags + ["-oA", str(out_base), ip]

        self._output_dir_var.set(f"Output: {out_dir.resolve()}")
        self._log(f"{'='*60}\n", "dim")
        self._log(f"  Target  : {ip}\n", "cyan")
        self._log(f"  Box     : {name}\n", "cyan")
        self._log(f"  Mode    : {'Quick (top 1000)' if mode=='quick' else 'Full (all ports)'}\n", "cyan")
        self._log(f"  Command : {' '.join(cmd)}\n", "dim")
        self._log(f"  Started : {self._start_time.strftime('%H:%M:%S')}\n", "dim")
        self._log(f"{'='*60}\n\n", "dim")

        # Run in background thread
        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(cmd,), daemon=True
        )
        self._scan_thread.start()

        # Start elapsed timer
        self._update_elapsed()

    def _run_scan(self, cmd):
        try:
            self._scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in self._scan_process.stdout:
                self.after(0, self._process_line, line)
            self._scan_process.wait()
        except FileNotFoundError:
            self.after(0, self._log, "\n[✗] nmap not found.\n", "red")
        finally:
            self.after(0, self._scan_done)

    def _process_line(self, line: str):
        import re
        stripped = line.rstrip()
        if not stripped:
            self._log("\n")
            return

        # ── ETA / progress lines (suppress from main output, show in bar) ────
        # e.g. "SYN Stealth Scan Timing: About 15.00% done; ETC: 20:52 (0:03:10 remaining)"
        eta_match = re.search(r"About\s+([\d.]+)%\s+done.*?(\d+:\d+:\d+)\s+remaining", stripped)
        if eta_match:
            pct       = float(eta_match.group(1))
            remaining = eta_match.group(2)
            self._progress_var.set(pct)
            self._eta_var.set(f"⏱ {pct:.1f}%  —  ETA: {remaining} remaining")
            return  # don't clutter the output log with raw stats lines

        # Also catch the "Stats:" summary line silently
        if stripped.startswith("Stats:") and "undergoing" in stripped:
            return

        # ── Colour rules ──────────────────────────────────────────────────────
        if "open" in stripped and ("/tcp" in stripped or "/udp" in stripped):
            self._log(f"  {stripped}\n", "green")
            if stripped.startswith("Discovered open port"):
                # Verbose discovery line: "Discovered open port 445/tcp on 127.0.0.1"
                self._add_discovered_port(stripped)
            else:
                # Service scan result: "80/tcp   open  http   Apache 2.4.41"
                self._add_service_port(stripped)
        elif stripped.startswith("Nmap scan report"):
            self._log(f"{stripped}\n", "cyan")
        elif stripped.startswith("PORT") or "STATE" in stripped:
            self._log(f"  {stripped}\n", "bold")
        elif "WARNING" in stripped or "Warning" in stripped:
            self._log(f"  {stripped}\n", "yellow")
        elif stripped.startswith("Host is up"):
            self._log(f"  {stripped}\n", "green")
        else:
            self._log(f"  {stripped}\n")

    def _add_discovered_port(self, line: str):
        """Handle verbose discovery line: 'Discovered open port 445/tcp on 127.0.0.1'"""
        parts    = line.split()
        port_str = parts[3] if len(parts) > 3 else ""   # e.g. "445/tcp"
        port_num = port_str.split("/")[0]
        service  = KNOWN_PORTS.get(port_num, "")

        if port_str in self._port_rows:
            return  # already have this port, skip duplicate
        iid = self._tree.insert("", "end", values=(port_str, "open", service, "scanning…"))
        self._port_rows[port_str] = iid
        self._port_count += 1
        self._notebook.tab(1, text=f"  Open Ports ({self._port_count})  ")

    def _add_service_port(self, line: str):
        """Handle service scan result: '80/tcp   open  http   Apache httpd 2.4.41'"""
        parts   = line.split(None, 3)
        port    = parts[0] if len(parts) > 0 else ""
        state   = parts[1] if len(parts) > 1 else ""
        service = parts[2] if len(parts) > 2 else ""
        version = parts[3] if len(parts) > 3 else ""

        if port in self._port_rows:
            # Update the existing row with full service/version info
            iid = self._port_rows[port]
            self._tree.item(iid, values=(port, state, service, version))
        else:
            # Port wasn't in discovery phase — add it fresh
            iid = self._tree.insert("", "end", values=(port, state, service, version))
            self._port_rows[port] = iid
            self._port_count += 1
            self._notebook.tab(1, text=f"  Open Ports ({self._port_count})  ")

    def _scan_done(self):
        self._scanning = False
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")

        elapsed = datetime.now() - self._start_time
        elapsed_str = str(elapsed).split(".")[0]

        port_count = len(self._tree.get_children())
        self._progress_var.set(100)
        self._eta_var.set(f"✓ Complete in {elapsed_str}")
        self._status_var.set(f"Done — {port_count} open port(s) found")
        self._elapsed_var.set(f"Elapsed: {elapsed_str}")

        self._log(f"\n{'='*60}\n", "dim")
        self._log(f"  ✓ Scan complete  |  {port_count} open port(s)  |  {elapsed_str}\n", "green")
        self._log(f"{'='*60}\n", "dim")

    def _stop_scan(self):
        if self._scan_process:
            try:
                self._scan_process.terminate()
            except Exception:
                pass
        self._status_var.set("Stopped")
        self._scanning = False
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._log("\n[!] Scan stopped by user.\n", "yellow")

    def _clear_output(self, keep_header=False):
        self._output.config(state="normal")
        self._output.delete("1.0", "end")
        self._output.config(state="disabled")
        if not keep_header:
            self._status_var.set("Ready")
            self._elapsed_var.set("")
            self._output_dir_var.set("")
            for row in self._tree.get_children():
                self._tree.delete(row)

    def _log(self, text: str, tag: str = ""):
        self._output.config(state="normal")
        if tag:
            self._output.insert("end", text, tag)
        else:
            self._output.insert("end", text)
        self._output.see("end")
        self._output.config(state="disabled")

    def _update_elapsed(self):
        if self._scanning:
            elapsed = datetime.now() - self._start_time
            self._elapsed_var.set(f"Elapsed: {str(elapsed).split('.')[0]}")
            self.after(1000, self._update_elapsed)

    def _on_close(self):
        if self._scanning:
            if messagebox.askyesno("Quit", "A scan is running. Stop it and quit?"):
                self._stop_scan()
                self.destroy()
        else:
            self.destroy()


if __name__ == "__main__":
    app = THMScannerApp()
    app.mainloop()
