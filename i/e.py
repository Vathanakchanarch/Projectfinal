"""
antivirus_full.py
Full Antivirus-style GUI (Option C) — Tkinter implementation
Single-file app. Edit the default paths below or change them in Settings inside the app.
"""

import os
import sys
import json
import csv
import shutil
import hashlib
import threading
import queue
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_DIR = Path.home() / ".simple_antivirus"
APP_DIR.mkdir(parents=True, exist_ok=True)

# Defaults — change if you like
DEFAULT_VIRUS_HASH_FILE = APP_DIR / "virusHash.txt"
DEFAULT_VIRUS_INFO_FILE = APP_DIR / "virusinfo.txt"
DEFAULT_QUARANTINE_DIR = APP_DIR / "quarantine"
SCAN_HISTORY_FILE = APP_DIR / "scan_history.json"

DEFAULT_QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
if not (DEFAULT_VIRUS_HASH_FILE.exists() and DEFAULT_VIRUS_INFO_FILE.exists()):
    # create empty sample DB files to avoid errors; user should populate them
    DEFAULT_VIRUS_HASH_FILE.touch(exist_ok=True)
    DEFAULT_VIRUS_INFO_FILE.touch(exist_ok=True)


# ----------------------------
# Core malware detection logic
# ----------------------------
class MalwareDetection:
    """Loads virus DB once and offers file-checking."""
    def __init__(self, virus_hash_path=DEFAULT_VIRUS_HASH_FILE, virus_info_path=DEFAULT_VIRUS_INFO_FILE):
        self.virus_hash_path = Path(virus_hash_path)
        self.virus_info_path = Path(virus_info_path)
        self.virus_hashes = []
        self.virus_info = []
        self._load_db()

    def _load_db(self):
        """Load hashes and info from files; keep parallel lists and truncate to smallest length."""
        hashes = []
        info = []
        if self.virus_hash_path.exists():
            with open(self.virus_hash_path, "r", encoding="utf-8", errors="ignore") as f:
                hashes = [line.strip() for line in f if line.strip()]
        if self.virus_info_path.exists():
            with open(self.virus_info_path, "r", encoding="utf-8", errors="ignore") as f:
                info = [line.strip() for line in f if line.strip()]
        minlen = min(len(hashes), len(info))
        self.virus_hashes = hashes[:minlen]
        self.virus_info = info[:minlen]

    def reload_db(self, virus_hash_path=None, virus_info_path=None):
        if virus_hash_path:
            self.virus_hash_path = Path(virus_hash_path)
        if virus_info_path:
            self.virus_info_path = Path(virus_info_path)
        self._load_db()

    def get_file_hash(self, path: Path):
        """Compute SHA-256 in streaming fashion."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            # propagate exception to caller; caller will show error and continue
            raise

    def check_file(self, path: Path):
        """Return virus name if found, else None."""
        file_hash = self.get_file_hash(path)
        try:
            idx = self.virus_hashes.index(file_hash)
            return self.virus_info[idx]
        except ValueError:
            return None


# ----------------------------
# Scanner worker (background)
# ----------------------------
class ScannerThread(threading.Thread):
    """
    Scans a path (file or directory) in background and communicates through a queue.
    Events posted to q:
      ('start', total_files)
      ('progress', scanned_count)
      ('infected', filepath, virusname)
      ('error', message)
      ('done', scanned, infected)
    """
    def __init__(self, target_path: Path, detector: MalwareDetection, q: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.target_path = Path(target_path)
        self.detector = detector
        self.q = q
        self.stop_event = stop_event

    def _count_files(self):
        if self.target_path.is_file():
            return 1
        total = 0
        for _root, _dirs, files in os.walk(self.target_path):
            total += len(files)
        return total

    def run(self):
        try:
            total = self._count_files()
            self.q.put(('start', total))
            scanned = 0
            infected = 0

            if self.target_path.is_file():
                files_iter = [self.target_path]
            else:
                # generator that yields full paths
                def gen():
                    for root, _, files in os.walk(self.target_path):
                        for f in files:
                            yield Path(root) / f
                files_iter = gen()

            for p in files_iter:
                if self.stop_event.is_set():
                    break
                scanned += 1
                try:
                    virus = self.detector.check_file(p)
                except Exception as e:
                    self.q.put(('error', f"Error reading {p}: {e}"))
                    self.q.put(('progress', scanned))
                    continue

                self.q.put(('progress', scanned))
                if virus:
                    infected += 1
                    self.q.put(('infected', str(p), virus))

            self.q.put(('done', scanned, infected))
        except Exception as e:
            self.q.put(('error', str(e)))
            self.q.put(('done', 0, 0))


# ----------------------------
# Persistence: scan history
# ----------------------------
def load_scan_history():
    if not SCAN_HISTORY_FILE.exists():
        return []
    try:
        with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def append_scan_history(entry):
    data = load_scan_history()
    data.insert(0, entry)  # newest first
    # limit history to last 200 scans
    data = data[:200]
    with open(SCAN_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ----------------------------
# GUI application
# ----------------------------
class AntivirusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Antivirus — Full Interface (Option C)")
        self.geometry("1000x640")
        self.minsize(900, 560)

        # App state and components
        self.detector = MalwareDetection()
        self.quarantine_dir = Path(DEFAULT_QUARANTINE_DIR)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        self.current_scan_thread = None
        self.scan_queue = queue.Queue()
        self.stop_event = threading.Event()

        # runtime counters
        self._scanned = 0
        self._infected = 0
        self._total_to_scan = 0
        self.current_results = []  # list of (filepath, virusname)

        # sidebar and frames
        self._build_ui()
        self._poll_queue()
        self._refresh_dashboard()

    # ---------------------
    # UI building
    # ---------------------
    def _build_ui(self):
        # main grid: left sidebar, right content
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self, width=220, padding=8)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        logo = ttk.Label(sidebar, text="SimpleAV", font=("Segoe UI", 18, "bold"))
        logo.pack(pady=(4, 8))

        self.btn_dash = ttk.Button(sidebar, text="Dashboard", command=self.show_dashboard)
        self.btn_dash.pack(fill='x', pady=4)
        self.btn_scan = ttk.Button(sidebar, text="Scan", command=self.show_scan)
        self.btn_scan.pack(fill='x', pady=4)
        self.btn_quarantine = ttk.Button(sidebar, text="Quarantine", command=self.show_quarantine)
        self.btn_quarantine.pack(fill='x', pady=4)
        self.btn_history = ttk.Button(sidebar, text="History", command=self.show_history)
        self.btn_history.pack(fill='x', pady=4)
        self.btn_settings = ttk.Button(sidebar, text="Settings", command=self.show_settings)
        self.btn_settings.pack(fill='x', pady=4)

        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', pady=8)
        self.status_label = ttk.Label(sidebar, text="Ready", wraplength=200, foreground="gray")
        self.status_label.pack(side='bottom', pady=6)

        # right content area
        self.content = ttk.Frame(self, padding=8)
        self.content.grid(row=0, column=1, sticky="nsew")

        # panels (stack)
        self.panels = {}
        self.panels['dashboard'] = self._make_dashboard(self.content)
        self.panels['scan'] = self._make_scan_panel(self.content)
        self.panels['quarantine'] = self._make_quarantine_panel(self.content)
        self.panels['history'] = self._make_history_panel(self.content)
        self.panels['settings'] = self._make_settings_panel(self.content)

        self.show_dashboard()

    # ---------------------
    # Panels
    # ---------------------
    def _clear_content(self):
        for child in self.content.winfo_children():
            child.pack_forget()

    def show_dashboard(self):
        self._clear_content()
        self.panels['dashboard'].pack(fill='both', expand=True)
        self._refresh_dashboard()

    def show_scan(self):
        self._clear_content()
        self.panels['scan'].pack(fill='both', expand=True)

    def show_quarantine(self):
        self._clear_content()
        self.panels['quarantine'].pack(fill='both', expand=True)
        self._refresh_quarantine()

    def show_history(self):
        self._clear_content()
        self.panels['history'].pack(fill='both', expand=True)
        self._refresh_history_list()

    def show_settings(self):
        self._clear_content()
        self.panels['settings'].pack(fill='both', expand=True)

    # Dashboard
    def _make_dashboard(self, parent):
        frame = ttk.Frame(parent)
        header = ttk.Label(frame, text="Dashboard", font=("Segoe UI", 16, "bold"))
        header.pack(anchor='w')

        stats_frame = ttk.Frame(frame, padding=(6,6))
        stats_frame.pack(fill='x', pady=6)

        # cards
        self.card_total_scanned = ttk.Label(stats_frame, text="Scanned (session): 0", font=("Segoe UI", 12))
        self.card_total_scanned.grid(row=0, column=0, padx=6, pady=6, sticky='w')
        self.card_total_infected = ttk.Label(stats_frame, text="Infected (session): 0", font=("Segoe UI", 12))
        self.card_total_infected.grid(row=0, column=1, padx=6, pady=6, sticky='w')
        self.card_last_scan = ttk.Label(stats_frame, text="Last scan: -", font=("Segoe UI", 12))
        self.card_last_scan.grid(row=1, column=0, padx=6, pady=6, sticky='w')
        self.card_db_entries = ttk.Label(stats_frame, text=f"DB signatures: {len(self.detector.virus_hashes)}", font=("Segoe UI", 12))
        self.card_db_entries.grid(row=1, column=1, padx=6, pady=6, sticky='w')

        # recent infected list
        recent_frame = ttk.LabelFrame(frame, text="Recent detections")
        recent_frame.pack(fill='both', expand=True, pady=(8,0))
        self.recent_tree = ttk.Treeview(recent_frame, columns=('path','virus','time'), show='headings')
        self.recent_tree.heading('path', text='File Path')
        self.recent_tree.heading('virus', text='Virus')
        self.recent_tree.heading('time', text='Time')
        self.recent_tree.column('path', width=520)
        self.recent_tree.column('virus', width=160)
        self.recent_tree.column('time', width=120)
        self.recent_tree.pack(fill='both', expand=True, side='left')
        scroll = ttk.Scrollbar(recent_frame, command=self.recent_tree.yview)
        self.recent_tree.configure(yscroll=scroll.set)
        scroll.pack(side='left', fill='y')
        return frame

    def _refresh_dashboard(self):
        # update cards
        self.card_total_scanned.config(text=f"Scanned (session): {self._scanned}")
        self.card_total_infected.config(text=f"Infected (session): {self._infected}")
        # last scan from history
        history = load_scan_history()
        last_scan = history[0]['time'] if history else '-'
        self.card_last_scan.config(text=f"Last scan: {last_scan}")
        self.card_db_entries.config(text=f"DB signatures: {len(self.detector.virus_hashes)}")
        # refresh recent list (from history)
        for r in self.recent_tree.get_children():
            self.recent_tree.delete(r)
        history = load_scan_history()
        for rec in history[:30]:
            # rec contains keys: time, scanned, infected, items: [(path,virus)...]
            items = rec.get('items', [])
            for p, v in items[:1]:  # show only first infected file per scan to keep list short
                self.recent_tree.insert('', 'end', values=(p, v, rec.get('time')))

    # Scan panel
    def _make_scan_panel(self, parent):
        frame = ttk.Frame(parent)
        header = ttk.Label(frame, text="Scan", font=("Segoe UI", 16, "bold"))
        header.pack(anchor='w')

        controls = ttk.Frame(frame, padding=6)
        controls.pack(fill='x')

        ttk.Label(controls, text="Target path:").grid(row=0, column=0, sticky='w')
        self.path_entry_var = tk.StringVar(value=str(Path.cwd()))
        path_entry = ttk.Entry(controls, textvariable=self.path_entry_var)
        path_entry.grid(row=0, column=1, sticky='ew', padx=6)
        controls.columnconfigure(1, weight=1)
        ttk.Button(controls, text="Browse", command=self._browse_target).grid(row=0, column=2, padx=4)
        self.scan_btn = ttk.Button(controls, text="Start Scan", command=self._start_scan)
        self.scan_btn.grid(row=0, column=3, padx=4)
        ttk.Button(controls, text="Stop", command=self._stop_scan).grid(row=0, column=4, padx=4)

        # progress and stats
        progress_frame = ttk.Frame(frame, padding=6)
        progress_frame.pack(fill='x')
        self.progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', mode='determinate')
        self.progress_bar.pack(fill='x', padx=4, pady=6)
        self.scan_status_var = tk.StringVar(value="Ready")
        ttk.Label(progress_frame, textvariable=self.scan_status_var).pack(side='left', padx=4)
        self.scan_counts_var = tk.StringVar(value="Scanned: 0 | Infected: 0")
        ttk.Label(progress_frame, textvariable=self.scan_counts_var).pack(side='right', padx=4)

        # results tree
        results_frame = ttk.Frame(frame, padding=6)
        results_frame.pack(fill='both', expand=True)
        cols = ('path','virus','action')
        self.results_tree = ttk.Treeview(results_frame, columns=cols, show='headings', selectmode='extended')
        self.results_tree.heading('path', text='File Path')
        self.results_tree.heading('virus', text='Virus')
        self.results_tree.heading('action', text='Action')
        self.results_tree.column('path', width=600)
        self.results_tree.column('virus', width=200)
        self.results_tree.column('action', width=120)
        self.results_tree.pack(side='left', fill='both', expand=True)
        scroll = ttk.Scrollbar(results_frame, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scroll.set)
        scroll.pack(side='left', fill='y')

        # buttons under results
        btns = ttk.Frame(frame, padding=6)
        btns.pack(fill='x')
        ttk.Button(btns, text="Quarantine Selected", command=self._quarantine_selected).pack(side='left', padx=6)
        ttk.Button(btns, text="Quarantine All", command=self._quarantine_all).pack(side='left', padx=6)
        ttk.Button(btns, text="Export Results (CSV)", command=self._export_results_csv).pack(side='left', padx=6)
        ttk.Button(btns, text="Clear Results", command=self._clear_results).pack(side='left', padx=6)

        return frame

    # Quarantine panel
    def _make_quarantine_panel(self, parent):
        frame = ttk.Frame(parent)
        header = ttk.Label(frame, text="Quarantine", font=("Segoe UI", 16, "bold"))
        header.pack(anchor='w', pady=(0,6))

        info = ttk.Label(frame, text=f"Quarantine folder: {self.quarantine_dir}")
        info.pack(anchor='w')

        qframe = ttk.Frame(frame, padding=6)
        qframe.pack(fill='both', expand=True)
        cols = ('original','virus','time')
        self.quarantine_tree = ttk.Treeview(qframe, columns=cols, show='headings', selectmode='extended')
        self.quarantine_tree.heading('original', text='Original Path')
        self.quarantine_tree.heading('virus', text='Virus')
        self.quarantine_tree.heading('time', text='Quarantined At')
        self.quarantine_tree.column('original', width=600)
        self.quarantine_tree.column('virus', width=200)
        self.quarantine_tree.column('time', width=160)
        self.quarantine_tree.pack(side='left', fill='both', expand=True)
        scroll = ttk.Scrollbar(qframe, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscroll=scroll.set)
        scroll.pack(side='left', fill='y')

        qbtns = ttk.Frame(frame, padding=6)
        qbtns.pack(fill='x')
        ttk.Button(qbtns, text="Restore Selected", command=self._restore_selected).pack(side='left', padx=6)
        ttk.Button(qbtns, text="Delete Selected", command=self._delete_selected_quarantine).pack(side='left', padx=6)
        ttk.Button(qbtns, text="Empty Quarantine", command=self._empty_quarantine).pack(side='left', padx=6)

        return frame

    # History panel
    def _make_history_panel(self, parent):
        frame = ttk.Frame(parent)
        header = ttk.Label(frame, text="Scan History", font=("Segoe UI", 16, "bold"))
        header.pack(anchor='w')
        hf = ttk.Frame(frame, padding=6)
        hf.pack(fill='both', expand=True)
        cols = ('time','target','scanned','infected')
        self.history_tree = ttk.Treeview(hf, columns=cols, show='headings', selectmode='browse')
        for c, t in zip(cols, ("Time","Target","Scanned","Infected")):
            self.history_tree.heading(c, text=t)
            self.history_tree.column(c, width=(220 if c=='time' else 120))
        self.history_tree.pack(side='left', fill='both', expand=True)
        scroll = ttk.Scrollbar(hf, command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scroll.set)
        scroll.pack(side='left', fill='y')

        # Detail pane on right
        detail_frame = ttk.Frame(frame, padding=6)
        detail_frame.pack(fill='x')
        ttk.Button(detail_frame, text="Show Selected Details", command=self._show_selected_history_details).pack(side='left', padx=6)
        ttk.Button(detail_frame, text="Export History CSV", command=self._export_history_csv).pack(side='left', padx=6)
        ttk.Button(detail_frame, text="Clear History", command=self._clear_history).pack(side='left', padx=6)
        return frame

    # Settings panel
    def _make_settings_panel(self, parent):
        frame = ttk.Frame(parent)
        header = ttk.Label(frame, text="Settings", font=("Segoe UI", 16, "bold"))
        header.pack(anchor='w', pady=(0,6))

        f = ttk.Frame(frame, padding=6)
        f.pack(fill='x')
        ttk.Label(f, text="Virus hash file:").grid(row=0, column=0, sticky='w')
        self.hash_file_var = tk.StringVar(value=str(self.detector.virus_hash_path))
        ttk.Entry(f, textvariable=self.hash_file_var).grid(row=0, column=1, sticky='ew', padx=6)
        ttk.Button(f, text="Browse", command=self._browse_hash_file).grid(row=0, column=2, padx=4)

        ttk.Label(f, text="Virus info file:").grid(row=1, column=0, sticky='w')
        self.info_file_var = tk.StringVar(value=str(self.detector.virus_info_path))
        ttk.Entry(f, textvariable=self.info_file_var).grid(row=1, column=1, sticky='ew', padx=6)
        ttk.Button(f, text="Browse", command=self._browse_info_file).grid(row=1, column=2, padx=4)

        ttk.Label(f, text="Quarantine folder:").grid(row=2, column=0, sticky='w')
        self.quarantine_var = tk.StringVar(value=str(self.quarantine_dir))
        ttk.Entry(f, textvariable=self.quarantine_var).grid(row=2, column=1, sticky='ew', padx=6)
        ttk.Button(f, text="Browse", command=self._browse_quarantine_dir).grid(row=2, column=2, padx=4)

        f.columnconfigure(1, weight=1)
        ttk.Button(frame, text="Save & Reload DB", command=self._save_settings).pack(pady=8)

        return frame

    # ---------------------
    # Actions & helpers
    # ---------------------
    def _browse_target(self):
        # allow both file and directory selection
        p = filedialog.askopenfilename()
        if p:
            self.path_entry_var.set(p)
            return
        p = filedialog.askdirectory()
        if p:
            self.path_entry_var.set(p)

    def _start_scan(self):
        target = self.path_entry_var.get().strip()
        if not target:
            messagebox.showerror("No target", "Please choose a file or folder to scan.")
            return
        p = Path(target)
        if not p.exists():
            messagebox.showerror("Not found", "The selected path does not exist.")
            return

        # clear previous results
        self._clear_results()
        self._scanned = 0
        self._infected = 0
        self._total_to_scan = 0
        self.current_results = []
        self.scan_counts_var.set("Scanned: 0 | Infected: 0")
        self.scan_status_var.set("Scanning...")

        # prepare and start thread
        self.stop_event.clear()
        self.current_scan_thread = ScannerThread(p, self.detector, self.scan_queue, self.stop_event)
        self.current_scan_thread.start()
        self.scan_btn.config(state='disabled')
        self.status_label.config(text="Scanning...")

    def _stop_scan(self):
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            self.stop_event.set()
            self.scan_status_var.set("Stopping...")

    def _poll_queue(self):
        try:
            while True:
                evt = self.scan_queue.get_nowait()
                self._handle_scan_event(evt)
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    def _handle_scan_event(self, evt):
        kind = evt[0]
        if kind == 'start':
            total = evt[1]
            self._total_to_scan = total
            self.progress_bar['maximum'] = max(total, 1)
            self.scan_status_var.set(f"Scanning (0 / {total})")
        elif kind == 'progress':
            self._scanned = evt[1]
            self.progress_bar['value'] = self._scanned
            self.scan_status_var.set(f"Scanning ({self._scanned} / {int(self.progress_bar['maximum'])})")
            self.scan_counts_var.set(f"Scanned: {self._scanned} | Infected: {self._infected}")
        elif kind == 'infected':
            path, virus = evt[1], evt[2]
            self._infected += 1
            self.current_results.append((path, virus))
            self.results_tree.insert('', 'end', values=(path, virus, "Detected"))
            self.scan_counts_var.set(f"Scanned: {self._scanned} | Infected: {self._infected}")
        elif kind == 'error':
            msg = evt[1]
            # show a non-blocking log in status
            print("[Scan error]", msg, file=sys.stderr)
        elif kind == 'done':
            scanned, infected = evt[1], evt[2]
            self._scanned = scanned
            self._infected = infected
            self.scan_btn.config(state='normal')
            self.scan_status_var.set(f"Done — scanned {scanned}, infected {infected}")
            self.status_label.config(text=f"Last scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            # persist history
            history_entry = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": self.path_entry_var.get(),
                "scanned": scanned,
                "infected": infected,
                "items": self.current_results.copy()
            }
            append_scan_history(history_entry)
            self._refresh_dashboard()

    def _clear_results(self):
        for iid in self.results_tree.get_children():
            self.results_tree.delete(iid)
        self.current_results = []
        self.progress_bar['value'] = 0
        self.scan_counts_var.set("Scanned: 0 | Infected: 0")
        self.scan_status_var.set("Ready")

    def _quarantine_selected(self):
        sel = self.results_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select infected files in results to quarantine.")
            return
        if not messagebox.askyesno("Confirm", f"Quarantine {len(sel)} selected file(s)?"):
            return

        for iid in sel:
            path, virus, _ = self.results_tree.item(iid, 'values')
            try:
                self._move_to_quarantine(Path(path), virus)
                self.results_tree.item(iid, values=(path, virus, "Quarantined"))
                # also remove from current_results
                self.current_results = [r for r in self.current_results if r[0] != path]
            except Exception as e:
                messagebox.showwarning("Quarantine failed", f"Failed to quarantine {path}: {e}")

        # refresh counts
        children = self.results_tree.get_children()
        infected_left = sum(1 for c in children if self.results_tree.item(c, 'values')[2] != "Quarantined")
        self.scan_counts_var.set(f"Scanned: {self._scanned} | Infected: {infected_left}")

    def _quarantine_all(self):
        items = list(self.results_tree.get_children())
        if not items:
            return
        if not messagebox.askyesno("Confirm", f"Quarantine all {len(items)} infected file(s)?"):
            return

        for iid in items:
            path, virus, _ = self.results_tree.item(iid, 'values')
            try:
                self._move_to_quarantine(Path(path), virus)
                self.results_tree.item(iid, values=(path, virus, "Quarantined"))
            except Exception as e:
                messagebox.showwarning("Quarantine failed", f"Failed to quarantine {path}: {e}")

        self.scan_counts_var.set(f"Scanned: {self._scanned} | Infected: 0")

    def _move_to_quarantine(self, file_path: Path, virus_name: str):
        if not file_path.exists():
            raise FileNotFoundError(f"{file_path} not found")
        # create a unique filename in quarantine
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_name = file_path.name
        dest_name = f"{timestamp}_{safe_name}"
        dest_path = self.quarantine_dir / dest_name
        shutil.move(str(file_path), str(dest_path))
        # record metadata as .json next to quarantined file
        meta = {
            "original_path": str(file_path),
            "virus": virus_name,
            "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        with open(dest_path.with_suffix(dest_path.suffix + ".meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        # refresh quarantine view
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        # read all quarantined items (meta files)
        for iid in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(iid)
        files = sorted(self.quarantine_dir.glob("*"), key=os.path.getmtime, reverse=True)
        # pair files with meta.json if exists
        seen = set()
        for f in files:
            if f.suffix == ".json" and f.name.endswith(".meta.json"):
                # meta file; find paired actual file
                base = f.with_suffix("").with_suffix("")  # hack to remove .meta.json
                # Attempt to find the actual quarantined file with same base name
                # Simpler: read meta and determine file by scanning directory for prefixed timestamp
                try:
                    meta = json.load(open(f, "r", encoding="utf-8"))
                    original = meta.get("original_path", "")
                    virus = meta.get("virus", "")
                    qtime = meta.get("quarantined_at", "")
                    # find actual file (strip .meta.json suffix to guess file name)
                    qfile = None
                    # search for files sharing timestamp prefix of meta file name if possible
                    for candidate in self.quarantine_dir.iterdir():
                        if candidate.name.startswith(f.name.split(".meta.json")[0]) and not candidate.name.endswith(".meta.json"):
                            qfile = candidate
                            break
                    self.quarantine_tree.insert('', 'end', values=(original, virus, qtime))
                except Exception:
                    continue

    def _restore_selected(self):
        sel = self.quarantine_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select quarantined entries to restore.")
            return
        if not messagebox.askyesno("Confirm", f"Restore {len(sel)} selected item(s) to original locations?"):
            return

        restored = 0
        for iid in sel:
            original, virus, qtime = self.quarantine_tree.item(iid, 'values')
            # find matching file in quarantine with meta referencing this original
            restored_any = False
            for meta_file in self.quarantine_dir.glob("*.meta.json"):
                try:
                    meta = json.load(open(meta_file, "r", encoding="utf-8"))
                    if meta.get("original_path") == original:
                        # paired file: meta filename minus .meta.json
                        base = meta_file.name.rsplit(".meta.json", 1)[0]
                        # find file starting with base
                        for candidate in self.quarantine_dir.iterdir():
                            if candidate.name.startswith(base) and not candidate.name.endswith(".meta.json"):
                                dest = Path(original)
                                dest_parent = dest.parent
                                dest_parent.mkdir(parents=True, exist_ok=True)
                                shutil.move(str(candidate), str(dest))
                                meta_file.unlink(missing_ok=True)
                                restored += 1
                                restored_any = True
                                break
                        if restored_any:
                            break
                except Exception as e:
                    print("Restore error", e, file=sys.stderr)
            if not restored_any:
                messagebox.showwarning("Restore failed", f"Could not find quarantined file for {original}")

        self._refresh_quarantine()
        messagebox.showinfo("Restore", f"Restored {restored} file(s).")

    def _delete_selected_quarantine(self):
        sel = self.quarantine_tree.selection()
        if not sel:
            return
        if not messagebox.askyesno("Confirm", f"Delete {len(sel)} selected quarantined items permanently?"):
            return
        deleted = 0
        for iid in sel:
            original, virus, qtime = self.quarantine_tree.item(iid, 'values')
            # find matching meta and file and delete both
            for meta_file in self.quarantine_dir.glob("*.meta.json"):
                try:
                    meta = json.load(open(meta_file, "r", encoding="utf-8"))
                    if meta.get("original_path") == original:
                        base = meta_file.name.rsplit(".meta.json", 1)[0]
                        for candidate in list(self.quarantine_dir.iterdir()):
                            if candidate.name.startswith(base):
                                try:
                                    if candidate.is_file():
                                        candidate.unlink(missing_ok=True)
                                    elif candidate.is_dir():
                                        shutil.rmtree(candidate, ignore_errors=True)
                                except Exception:
                                    pass
                        try:
                            meta_file.unlink(missing_ok=True)
                        except Exception:
                            pass
                        deleted += 1
                        break
                except Exception:
                    continue
        self._refresh_quarantine()
        messagebox.showinfo("Delete", f"Deleted {deleted} quarantined item(s).")

    def _empty_quarantine(self):
        if not messagebox.askyesno("Confirm", "Delete ALL quarantined files permanently?"):
            return
        count = 0
        for p in list(self.quarantine_dir.iterdir()):
            try:
                if p.is_file():
                    p.unlink(missing_ok=True)
                elif p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                count += 1
            except Exception:
                pass
        self._refresh_quarantine()
        messagebox.showinfo("Empty", f"Removed {count} items from quarantine.")

    # History functions
    def _refresh_history_list(self):
        for r in self.history_tree.get_children():
            self.history_tree.delete(r)
        history = load_scan_history()
        for rec in history:
            self.history_tree.insert('', 'end', values=(rec.get('time'), rec.get('target'), rec.get('scanned'), rec.get('infected')))

    def _show_selected_history_details(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a history record to view details.")
            return
        item = self.history_tree.item(sel[0], 'values')
        time = item[0]
        # load matching history entry by time
        history = load_scan_history()
        rec = next((r for r in history if r.get('time') == time), None)
        if not rec:
            messagebox.showinfo("Not found", "Could not find details for the selected entry.")
            return
        # show a simple dialog listing infected files
        items = rec.get('items', [])
        if not items:
            messagebox.showinfo("Details", "No infected files in this scan.")
            return
        detail_text = "\n".join(f"{p}  —  {v}" for p, v in items)
        dlg = tk.Toplevel(self)
        dlg.title(f"Scan details — {time}")
        txt = tk.Text(dlg, wrap='none', width=120, height=30)
        txt.pack(fill='both', expand=True)
        txt.insert('1.0', detail_text)
        txt.config(state='disabled')

    def _export_history_csv(self):
        hist = load_scan_history()
        if not hist:
            messagebox.showinfo("No history", "No history to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["time","target","scanned","infected","infected_file","virus"])
                for rec in hist:
                    for p, v in rec.get('items', []):
                        writer.writerow([rec.get('time'), rec.get('target'), rec.get('scanned'), rec.get('infected'), p, v])
            messagebox.showinfo("Export", f"History exported to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _clear_history(self):
        if not messagebox.askyesno("Confirm", "Clear all scan history?"):
            return
        try:
            if SCAN_HISTORY_FILE.exists():
                SCAN_HISTORY_FILE.unlink()
            messagebox.showinfo("Clear", "History cleared.")
            self._refresh_history_list()
        except Exception as e:
            messagebox.showerror("Failed", str(e))

    # Settings actions
    def _browse_hash_file(self):
        p = filedialog.askopenfilename(title="Select virus hash file")
        if p:
            self.hash_file_var.set(p)

    def _browse_info_file(self):
        p = filedialog.askopenfilename(title="Select virus info file")
        if p:
            self.info_file_var.set(p)

    def _browse_quarantine_dir(self):
        p = filedialog.askdirectory(title="Select quarantine folder")
        if p:
            self.quarantine_var.set(p)

    def _save_settings(self):
        # apply and reload DB
        try:
            self.detector.reload_db(self.hash_file_var.get(), self.info_file_var.get())
            self.quarantine_dir = Path(self.quarantine_var.get())
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            messagebox.showinfo("Settings", "Settings saved and DB reloaded.")
            self._refresh_dashboard()
        except Exception as e:
            messagebox.showerror("Settings error", str(e))

    # Export scan results
    def _export_results_csv(self):
        if not self.current_results:
            messagebox.showinfo("No results", "There are no scan results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline='', encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["file_path","virus"])
                for p, v in self.current_results:
                    w.writerow([p, v])
            messagebox.showinfo("Export", f"Results exported to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))


# ----------------------------
# Run the app
# ----------------------------
def main():
    app = AntivirusApp()
    app.mainloop()

if __name__ == "__main__":
    main()
