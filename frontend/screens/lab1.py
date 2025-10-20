import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from backend.variants import VARIANTS
from backend.config import SEQ_FILE, CESARO_REPORT_FILE
from backend.rng import LCG, estimate_period_from_state, cesaro_pi_from_iterable
from backend.storage import write_int_sequence, read_int_sequence, write_text_report
from backend.rng.system_rng import system_range
from backend.validation import InputValidator, ValidationError
from backend.validation.validators import validate_all_inputs

logger = logging.getLogger("lab_suite.ui.lab1")

class Lab1Frame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="TFrame", padding=12)
        self.card_gen = None
        self.card_ces = None
        self.current_sequence = None
        self._build()

    def _build(self):
        container = ttk.Frame(self, style="TFrame")
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container, style="TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Lab 1 — Linear Congruential Generator", style="Title.TLabel")\
            .pack(anchor="w")
        ttk.Label(header, text="Generate a sequence, optionally estimate period, and run Cesàro test.",
                  style="Subtle.TLabel").pack(anchor="w", pady=(2, 10))

        form = ttk.Frame(container, style="Panel.TFrame", padding=10)
        form.pack(fill="x", pady=(0, 12))

        ttk.Label(form, text="Variant (1..25):").grid(row=0, column=0, padx=(0, 5), pady=6, sticky="w")
        self.variant_var = tk.StringVar(value="1")
        variant_spinbox = tk.Spinbox(form, from_=1, to=25, textvariable=self.variant_var, width=8)
        variant_spinbox.grid(row=0, column=1, padx=(0, 15), pady=6, sticky="ew")

        ttk.Label(form, text="Count n:").grid(row=0, column=2, padx=(0, 5), pady=6, sticky="w")
        self.n_var = tk.StringVar(value="1000")
        n_spinbox = tk.Spinbox(form, from_=1, to=10_000_000, textvariable=self.n_var, width=8)
        n_spinbox.grid(row=0, column=3, padx=(0, 15), pady=6, sticky="ew")

        ttk.Label(form, text="period_max_steps:").grid(row=0, column=4, padx=(0, 5), pady=6, sticky="w")
        self.steps_var = tk.StringVar(value="0")
        steps_spinbox = tk.Spinbox(form, from_=0, to=10_000_000, textvariable=self.steps_var, width=8)
        steps_spinbox.grid(row=0, column=5, padx=(0, 15), pady=6, sticky="ew")

        ttk.Label(form, text="Pairs:").grid(row=0, column=6, padx=(0, 5), pady=6, sticky="w")
        self.pairs_var = tk.StringVar(value="10000")
        pairs_spinbox = tk.Spinbox(form, from_=1, to=5_000_000, textvariable=self.pairs_var, width=8)
        pairs_spinbox.grid(row=0, column=7, padx=(0, 0), pady=6, sticky="ew")

        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)
        form.columnconfigure(5, weight=1)
        form.columnconfigure(7, weight=1)

        actions = ttk.Frame(container, style="TFrame")
        actions.pack(fill="x", pady=(0, 12))

        left = ttk.Frame(actions, style="TFrame")
        left.pack(side="left")
        ttk.Button(left, text="Generate", style="Primary.TButton",
                   command=self._on_generate).pack(side="left", padx=(0, 8))
        ttk.Button(left, text="Clear", command=self._on_clear).pack(side="left", padx=(0, 8))
        ttk.Button(left, text="Save As", command=self._on_save_as).pack(side="left", padx=(0, 8))
        ttk.Button(left, text="Cesàro test", command=self._on_cesaro).pack(side="left", padx=(0, 8))

        self.results_area = ttk.Frame(container, style="TFrame")
        self.results_area.pack(fill="both", expand=True)

    def _reset_results(self):
        if self.card_gen is not None:
            self.card_gen.destroy()
            self.card_gen = None
        if self.card_ces is not None:
            self.card_ces.destroy()
            self.card_ces = None

    def _on_clear(self):
        self._reset_results()
        self.current_sequence = None

    def _on_save_as(self):
        if self.current_sequence is None:
            messagebox.showwarning("No Data", "No sequence generated yet. Please generate a sequence first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save sequence as...",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            from pathlib import Path
            write_int_sequence(Path(file_path), self.current_sequence)
            messagebox.showinfo("Success", f"Sequence saved to {file_path}")
            logger.info(f"Sequence saved to user-selected file: {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save sequence: {e}")
            logger.error(f"Failed to save sequence to {file_path}: {e}")

    def _on_generate(self):
        try:
            v = int(self.variant_var.get())
            n = int(self.n_var.get())
            per = int(self.steps_var.get())
            
            validate_all_inputs(v, n, per)
            
            if v not in VARIANTS: 
                raise ValueError("Variant must be in 1..25")
                
        except ValidationError as e:
            messagebox.showerror("Validation Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Input Error", str(e))
            return

        try:
            m, a, c, seed = VARIANTS[v]
            logger.info("UI: generating v=%d n=%d per_steps=%d", v, n, per)
            
            lcg = LCG(m, a, c, seed)
            seq = list(lcg.stream(n))
            
            self.current_sequence = seq
            
            write_int_sequence(SEQ_FILE, seq)

            self._reset_results()
            
            result_frame = ttk.LabelFrame(self.results_area, text="Generation Result", padding=10)
            result_frame.pack(fill="x", pady=(0, 10))
            
            ttk.Label(result_frame, text=f"Sequence file: {SEQ_FILE}").pack(anchor="w")
            ttk.Label(result_frame, text=f"Parameters: m={m}, a={a}, c={c}, seed={seed}").pack(anchor="w")
            ttk.Label(result_frame, text=f"Generated n: {n}").pack(anchor="w")
            
            if per > 0:
                try:
                    period = estimate_period_from_state(a, c, m, seed, per)
                    ttk.Label(result_frame, text=f"Estimated period: {period}").pack(anchor="w")
                except Exception as e:
                    ttk.Label(result_frame, text=f"Period estimation: Failed: {e}").pack(anchor="w")
            
            ttk.Label(result_frame, text="All Generated Numbers:").pack(anchor="w", pady=(5, 2))
            numbers_text = tk.Text(result_frame, height=8, width=60, wrap="word", font=("Consolas", 9))
            numbers_text.pack(fill="x", pady=(0, 5))
            numbers_text.insert(tk.END, str(seq))
            numbers_text.config(state="disabled")
            
            self.card_gen = result_frame
            
        except Exception as e:
            messagebox.showerror("Generation Error", f"Failed to generate sequence: {e}")
            logger.error(f"Generation failed: {e}")
            return

    def _on_cesaro(self):
        try:
            pairs = int(self.pairs_var.get())
            
            InputValidator.validate_pairs_count(pairs)
            
        except ValidationError as e:
            messagebox.showerror("Validation Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Input Error", str(e))
            return

        try:
            seq = read_int_sequence(SEQ_FILE)
        except FileNotFoundError:
            messagebox.showerror("File Error", f"{SEQ_FILE} not found. Generate sequence first.")
            return
        except Exception as e:
            messagebox.showerror("File Error", f"Failed to read sequence file: {e}")
            return

        need = 2 * pairs
        if len(seq) < need:
            messagebox.showerror("Data Error", f"{SEQ_FILE} must contain at least {need} numbers.")
            return

        try:
            pi_hat, p, cop, total = cesaro_pi_from_iterable(seq[:need], pairs)
            
            max_val = max(seq) + 1 if seq else (2**31)
            sys_nums = system_range(max_val, need)
            pi_hat_sys, p_sys, cop_sys, total_sys = cesaro_pi_from_iterable(sys_nums, pairs)

            self._reset_results()
            
            cesaro_frame = ttk.LabelFrame(self.results_area, text="Cesàro Result", padding=10)
            cesaro_frame.pack(fill="x", pady=(0, 10))
            
            ttk.Label(cesaro_frame, text=f"Pairs used (LCG): {total}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"Coprime count (LCG): {cop}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"p (LCG): {p:.8f}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"π̂ (LCG): {pi_hat:.8f}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"Pairs used (System RNG): {total_sys}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"Coprime count (System RNG): {cop_sys}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"p (System RNG): {p_sys:.8f}").pack(anchor="w")
            ttk.Label(cesaro_frame, text=f"π̂ (System RNG): {pi_hat_sys:.8f}").pack(anchor="w")
            
            self.card_ces = cesaro_frame

            write_text_report(CESARO_REPORT_FILE, [
                "Cesàro Report",
                f"pairs={pairs}", f"sequence_file={SEQ_FILE}",
                "== LCG ==", f"pairs_used={total}, coprime={cop}, p≈{p:.8f}, pi_hat≈{pi_hat:.8f}",
                "== System RNG ==", f"pairs_used={total_sys}, coprime={cop_sys}, p≈{p_sys:.8f}, pi_hat≈{pi_hat_sys:.8f}",
            ])
            logger.info("Cesàro report written successfully")
            
        except Exception as e:
            messagebox.showerror("Cesàro Error", f"Failed to perform Cesàro test: {e}")
            logger.error(f"Cesàro test failed: {e}")
            return