from __future__ import annotations
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from .pe import PEImage, PEFormatError
from .scanner import scan_all
from .signatures import load_signatures
from .exporters import export_json, export_cpp

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BO6 Offset Scanner - Offline PE Analyzer")
        self.geometry("1100x700")
        self.minsize(880, 560)
        self.image = None
        self.results = []
        self.meta = {}
        self.exe_var = tk.StringVar()
        self.sig_var = tk.StringVar(value=str(Path("config") / "signatures.example.json"))
        self.status_var = tk.StringVar(value="Select a PE file and signature database.")
        self._build()

    def _build(self):
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)

        warning = ttk.Label(root, text="Offline/static analysis only — scans a selected PE file; does not attach to the BO6 process.")
        warning.pack(anchor="w", pady=(0, 8))

        files = ttk.Frame(root)
        files.pack(fill="x")
        ttk.Label(files, text="BO6 PE / dump:", width=18).grid(row=0, column=0, sticky="w")
        ttk.Entry(files, textvariable=self.exe_var).grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(files, text="Browse…", command=self.pick_exe).grid(row=0, column=2)
        ttk.Label(files, text="Signatures JSON:", width=18).grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(files, textvariable=self.sig_var).grid(row=1, column=1, sticky="ew", padx=5, pady=(5, 0))
        ttk.Button(files, text="Browse…", command=self.pick_sig).grid(row=1, column=2, pady=(5, 0))
        files.columnconfigure(1, weight=1)

        actions = ttk.Frame(root)
        actions.pack(fill="x", pady=10)
        self.scan_btn = ttk.Button(actions, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(actions, text="Export JSON", command=self.save_json).pack(side="left", padx=5)
        ttk.Button(actions, text="Export C++ Header", command=self.save_cpp).pack(side="left")

        cols = ("status", "name", "rva", "previous", "delta", "matches", "section")
        self.tree = ttk.Treeview(root, columns=cols, show="headings")
        headings = {
            "status": "Status", "name": "Symbol", "rva": "Resolved RVA", "previous": "Previous RVA",
            "delta": "Delta", "matches": "Matches", "section": "Section"
        }
        widths = {"status": 90, "name": 280, "rva": 130, "previous": 130, "delta": 100, "matches": 80, "section": 80}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.pack(fill="both", expand=True)

        ttk.Label(root, textvariable=self.status_var).pack(fill="x", pady=(8, 0))

    def pick_exe(self):
        p = filedialog.askopenfilename(title="Select BO6 executable or PE dump", filetypes=[("PE files", "*.exe *.dll *.bin"), ("All files", "*.*")])
        if p: self.exe_var.set(p)

    def pick_sig(self):
        p = filedialog.askopenfilename(title="Select signatures JSON", filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if p: self.sig_var.set(p)

    def start_scan(self):
        if not self.exe_var.get().strip() or not self.sig_var.get().strip():
            messagebox.showerror("Missing input", "Choose both a PE file and signatures JSON file.")
            return
        self.scan_btn.config(state="disabled")
        self.status_var.set("Scanning…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            image = PEImage(self.exe_var.get().strip())
            meta, sigs = load_signatures(self.sig_var.get().strip())
            results = scan_all(image, sigs)
            self.after(0, lambda: self._show_results(image, meta, results))
        except (OSError, ValueError, PEFormatError) as exc:
            self.after(0, lambda: self._scan_error(str(exc)))

    def _show_results(self, image, meta, results):
        self.image, self.meta, self.results = image, meta, results
        for x in self.tree.get_children(): self.tree.delete(x)
        for r in results:
            rva = "" if r.resolved_rva is None else f"0x{r.resolved_rva:X}"
            prev = "" if r.previous_rva is None else f"0x{r.previous_rva:X}"
            delta = "" if r.delta is None else (f"+0x{r.delta:X}" if r.delta >= 0 else f"-0x{-r.delta:X}")
            self.tree.insert("", "end", values=(r.status, r.name, rva, prev, delta, r.match_count, r.section or "*"))
        ok = sum(r.status == "resolved" for r in results)
        missing = sum(r.status == "missing" for r in results)
        ambiguous = sum(r.status == "ambiguous" for r in results)
        errors = sum(r.status == "error" for r in results)
        self.status_var.set(f"SHA256 {image.sha256[:16]}… | resolved {ok} | missing {missing} | ambiguous {ambiguous} | errors {errors}")
        self.scan_btn.config(state="normal")

    def _scan_error(self, msg):
        self.scan_btn.config(state="normal")
        self.status_var.set("Scan failed.")
        messagebox.showerror("Scan failed", msg)

    def save_json(self):
        if not self.image:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], initialfile="bo6-offsets.json")
        if p:
            export_json(p, self.image, self.results, self.meta)
            self.status_var.set(f"Exported {p}")

    def save_cpp(self):
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".hpp", filetypes=[("C++ header", "*.hpp *.h")], initialfile="bo6_offsets.hpp")
        if p:
            export_cpp(p, self.results)
            self.status_var.set(f"Exported {p}")

def main():
    App().mainloop()
