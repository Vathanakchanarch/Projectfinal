import os
import hashlib
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --------------------
# Malware detection core
# --------------------
class MalwareDetection:
    def __init__(self, virus_hash_file, virus_info_file):
        self.virus_hash_file = virus_hash_file
        self.virus_info_file = virus_info_file

        self.virus_hashes, self.virus_info = self._load_virus_database()
        # instance results
        self.detected_malware = []
        self.file_count = 0

    def _load_virus_database(self):
        hashes, info = [], []
        try:
            with open(self.virus_hash_file, "r") as v_hash:
                hashes = [line.strip() for line in v_hash if line.strip()]
        except FileNotFoundError:
            # empty DB if file missing (UI should warn)
            pass

        try:
            with open(self.virus_info_file, "r") as v_info:
                info = [line.strip() for line in v_info if line.strip()]
        except FileNotFoundError:
            pass

        # ensure parallel lists
        if len(hashes) != len(info):
            # if mismatch, truncate to shortest
            min_len = min(len(hashes), len(info))
            hashes, info = hashes[:min_len], info[:min_len]
        return hashes, info

    def get_file_hash(self, file_path):
        # compute SHA-256
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def check_file_virus(self, file_path):
        file_hash = self.get_file_hash(file_path)
        if file_hash in self.virus_hashes:
            idx = self.virus_hashes.index(file_hash)
            return self.virus_info[idx]
        return None

# --------------------
# Worker scanning thread
# --------------------
class ScannerWorker(threading.Thread):
    """
    Scans path (file or directory) in background and reports events via queue.
    Events sent to queue:
      ('start', total_files)
      ('progress', scanned_count)
      ('infected', file_path, virus_name)
      ('done', total_scanned, total_infected)
      ('error', message)
    """
    def __init__(self, path, detector: MalwareDetection, out_queue: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.path = path
        self.detector = detector
        self.q = out_queue
        self.stop_event = stop_event

    def count_files(self):
        if os.path.isfile(self.path):
            return 1
        total = 0
        for root, dirs, files in os.walk(self.path):
            total += len(files)
        return total

    def run(self):
        try:
            total = self.count_files()
            self.q.put(('start', total))
            scanned = 0
            infected = 0

            if os.path.isfile(self.path):
                files_iter = [self.path]
            else:
                files_iter = (os.path.join(root, f) for root, _, files in os.walk(self.path) for f in files)

            for file_path in files_iter:
                if self.stop_event.is_set():
                    break

                scanned += 1
                try:
                    virus = self.detector.check_file_virus(file_path)
                except Exception as e:
                    # if a file can't be read, send an error but continue
                    self.q.put(('error', f"Failed to read {file_path}: {e}"))
                    self.q.put(('progress', scanned))
                    continue

                self.q.put(('progress', scanned))
                if virus:
                    infected += 1
                    self.q.put(('infected', file_path, virus))

            self.q.put(('done', scanned, infected))
        except Exception as e:
            self.q.put(('error', str(e)))
            self.q.put(('done', 0, 0))

# --------------------
# GUI
# --------------------
class AntivirusGUI:
    def __init__(self, root, virus_hash_file, virus_info_file):
        self.root = root
        self.root.title("Simple Antivirus Scanner — Advanced GUI")
        self.root.geometry("800x520")

        # Detector (loads DB files once)
        self.detector = MalwareDetection(virus_hash_file, virus_info_file)

        # Queue & thread control
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None

        # Selected path (file or folder)
        self.target_path = tk.StringVar(value=os.getcwd())

        self._build_ui()
        self._poll_queue()

        # If DB empty, warn
        if not self.detector.virus_hashes:
            messagebox.showwarning("Virus DB missing", "Virus hash file not found or empty. Scans will not detect anything until DB is populated.")

    def _build_ui(self):
        # Top frame: path selection + buttons
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill='x')

        ttk.Label(top, text="Scan Path:").pack(side='left')
        entry = ttk.Entry(top, textvariable=self.target_path)
        entry.pack(side='left', fill='x', expand=True, padx=6)

        ttk.Button(top, text="Browse", command=self.browse).pack(side='left', padx=4)
        self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side='left', padx=4)
        ttk.Button(top, text="Stop", command=self.stop_scan).pack(side='left', padx=4)

        # Middle: Treeview for infected files and progress
        mid = ttk.Frame(self.root, padding=8)
        mid.pack(fill='both', expand=True)

        cols = ('#1', '#2')
        self.tree = ttk.Treeview(mid, columns=cols, show='headings', selectmode='extended')
        self.tree.heading('#1', text='File Path')
        self.tree.heading('#2', text='Virus Name')
        self.tree.column('#1', width=520, anchor='w')
        self.tree.column('#2', width=220, anchor='w')
        self.tree.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(mid, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='left', fill='y')

        # Right-side controls
        right = ttk.Frame(self.root, padding=8)
        right.pack(fill='x')

        btn_row = ttk.Frame(right)
        btn_row.pack(fill='x', pady=(6,0))
        self.remove_btn = ttk.Button(btn_row, text="Remove Selected", command=self.remove_selected)
        self.remove_btn.pack(side='left', padx=6)
        ttk.Button(btn_row, text="Remove All", command=self.remove_all).pack(side='left', padx=6)
        ttk.Button(btn_row, text="Clear Results", command=self.clear_results).pack(side='left', padx=6)

        # Progress and status
        status_frame = ttk.Frame(self.root, padding=8)
        status_frame.pack(fill='x', side='bottom')

        self.progress = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate')
        self.progress.pack(fill='x', side='top', padx=4, pady=4)

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side='left')

        self.count_var = tk.StringVar(value="Scanned: 0 | Infected: 0")
        ttk.Label(status_frame, textvariable=self.count_var).pack(side='right')

    def browse(self):
        # let user pick file or folder
        choice = filedialog.askopenfilename()
        if choice:
            self.target_path.set(choice)
            return
        choice = filedialog.askdirectory()
        if choice:
            self.target_path.set(choice)

    def start_scan(self):
        path = self.target_path.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Invalid path", "Please select a valid file or directory to scan.")
            return

        # reset previous results
        self.clear_results()
        self.stop_event.clear()

        # create a fresh detector instance for this scan (keeps DB loaded)
        detector = self.detector

        self.worker = ScannerWorker(path, detector, self.q, self.stop_event)
        self.worker.start()
        self.scan_btn.config(state='disabled')
        self.status_var.set("Scanning...")
        self.progress['value'] = 0
        self.count_var.set("Scanned: 0 | Infected: 0")

    def stop_scan(self):
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            self.status_var.set("Stopping...")

    def _poll_queue(self):
        # called periodically in main thread to process worker events
        try:
            while True:
                event = self.q.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll_queue)

    def _handle_event(self, event):
        etype = event[0]
        if etype == 'start':
            total = event[1]
            self.progress['maximum'] = max(total, 1)
            self.status_var.set(f"Scanning (0 / {total})")
            self._scanned = 0
            self._infected = 0
        elif etype == 'progress':
            self._scanned = event[1]
            self.progress['value'] = self._scanned
            self.status_var.set(f"Scanning ({self._scanned} / {int(self.progress['maximum'])})")
            self.count_var.set(f"Scanned: {self._scanned} | Infected: {getattr(self, '_infected', 0)}")
        elif etype == 'infected':
            file_path, virus_name = event[1], event[2]
            self._infected = getattr(self, '_infected', 0) + 1
            self.tree.insert('', 'end', values=(file_path, virus_name))
            self.count_var.set(f"Scanned: {getattr(self,'_scanned',0)} | Infected: {self._infected}")
        elif etype == 'error':
            message = event[1]
            # show as non-blocking status update
            print("ERROR:", message)
        elif etype == 'done':
            scanned, infected = event[1], event[2]
            self.scan_btn.config(state='normal')
            self.status_var.set(f"Done — scanned {scanned}, infected {infected}")
            self.progress['value'] = self.progress['maximum']
        else:
            print("Unknown event:", event)

    def remove_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("No selection", "Please select one or more infected files to remove.")
            return
        if not messagebox.askyesno("Confirm remove", f"Delete {len(selected)} selected file(s)? This cannot be undone."):
            return

        removed = 0
        for iid in selected:
            file_path, virus_name = self.tree.item(iid, 'values')
            try:
                os.remove(file_path)
                removed += 1
                self.tree.delete(iid)
            except Exception as e:
                messagebox.showwarning("Remove failed", f"Failed to remove {file_path}: {e}")

        # update infected count in label
        current_infected = sum(1 for _ in self.tree.get_children())
        self.count_var.set(f"Scanned: {getattr(self,'_scanned',0)} | Infected: {current_infected}")
        messagebox.showinfo("Remove complete", f"Removed {removed} file(s).")

    def remove_all(self):
        items = self.tree.get_children()
        if not items:
            return
        if not messagebox.askyesno("Confirm remove all", f"Delete all {len(items)} infected files? This cannot be undone."):
            return

        removed = 0
        for iid in list(items):
            file_path, virus_name = self.tree.item(iid, 'values')
            try:
                os.remove(file_path)
                removed += 1
                self.tree.delete(iid)
            except Exception as e:
                messagebox.showwarning("Remove failed", f"Failed to remove {file_path}: {e}")

        self.count_var.set(f"Scanned: {getattr(self,'_scanned',0)} | Infected: 0")
        messagebox.showinfo("Remove complete", f"Removed {removed} file(s).")

    def clear_results(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.progress['value'] = 0
        self.status_var.set("Ready")
        self.count_var.set("Scanned: 0 | Infected: 0")
        self._scanned = 0
        self._infected = 0

# --------------------
# Run app
# --------------------
if __name__ == "__main__":
    # Replace these with the paths to your virus DB files:
    VIRUS_HASH_FILE = r"D:\Y2\T1\PYTHON FOR CYBER\project\DatabaseVirus\virusHash.txt"
    VIRUS_INFO_FILE = r"D:\Y2\T1\PYTHON FOR CYBER\project\DatabaseVirus\virusInfo.txt"

    root = tk.Tk()
    app = AntivirusGUI(root, VIRUS_HASH_FILE, VIRUS_INFO_FILE)
    root.mainloop()
