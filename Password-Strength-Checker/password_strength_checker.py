"""
================================================================================
 DecodeLabs Industrial Training Kit — Project 1
 Password Strength Checker (GUI Edition)
================================================================================

Author : Mustafa
Track  : Junior Analyst // Defensive Logic
Goal   : Evaluate a password's risk level (Weak / Medium / Strong / Very
         Strong) using pure string-handling and conditional logic, then
         present the result through a live, interactive desktop GUI.

Key requirements covered (per project brief):
    - Check password length                         -> _check_length()
    - Check use of numbers, symbols, uppercase       -> _check_character_classes()
    - Display password strength result               -> StrengthMeter widget
Bonus features added (per "Conclusion" slide suggestions):
    - Leaked / common password detection             -> COMMON_PASSWORDS set
    - Character variety scoring                       -> calculate_strength()
    - Shannon-style entropy + estimated crack time     -> _estimate_crack_time()
    - Secure password generator                       -> generate_password()

Design notes (matching the "Computational Efficiency" slide):
    - All character-class checks use any(...) generator expressions instead
      of manual for/break loops -> single O(n) linear scan, short-circuited.
    - No external dependencies. Pure standard library (tkinter, secrets,
      string, math, re) so it runs anywhere Python 3 + Tk is installed.
================================================================================
"""

import math
import re
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox


# ------------------------------------------------------------------------- #
# 1. CORE LOGIC (kept UI-independent so it can be unit-tested / reused)
# ------------------------------------------------------------------------- #

# A small, representative sample of the most commonly leaked / breached
# passwords (per "Have I Been Pwned" / RockYou style top-lists). Real-world
# tools check against millions of entries; this local set demonstrates the
# same defensive principle without needing a network call or huge file.
COMMON_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "12345", "12345678",
    "111111", "1234567", "sunshine", "iloveyou", "admin", "welcome",
    "monkey", "login", "abc123", "starwars", "123123", "dragon",
    "passw0rd", "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "letmein", "football", "baseball", "superman", "batman",
    "shadow", "michael", "jennifer", "jordan", "hunter", "buster",
    "soccer", "harley", "ranger", "iloveyou1", "password1", "password123",
    "1q2w3e4r", "000000", "1qaz2wsx", "zaq12wsx", "asdfgh", "qwertyuiop",
}

SYMBOL_CHARS = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~"


def _check_length(password: str) -> bool:
    """Length gate. <8 characters is an immediate fail (exponential
    brute-force risk, per project brief)."""
    return len(password) >= 8


def _check_character_classes(password: str) -> dict:
    """Single O(n) pass per class using any() — short-circuits as soon as
    a match is found, avoiding manual index loops (Pythonic Elegance)."""
    return {
        "lower": any(char.islower() for char in password),
        "upper": any(char.isupper() for char in password),
        "digit": any(char.isdigit() for char in password),
        "symbol": any(char in SYMBOL_CHARS for char in password),
    }


def _is_common_password(password: str) -> bool:
    """Case-insensitive lookup against the known-leaked password set."""
    return password.lower() in COMMON_PASSWORDS


def _charset_size(classes: dict) -> int:
    """Approximate the search-space size (alphabet size) an attacker
    would have to brute-force, based on which character classes appear."""
    size = 0
    if classes["lower"]:
        size += 26
    if classes["upper"]:
        size += 26
    if classes["digit"]:
        size += 10
    if classes["symbol"]:
        size += len(SYMBOL_CHARS)
    return size or 1  # avoid log(0) for an empty password


def _estimate_entropy_bits(password: str, classes: dict) -> float:
    """Shannon-style entropy estimate: bits = length * log2(charset_size)."""
    if not password:
        return 0.0
    charset = _charset_size(classes)
    return len(password) * math.log2(charset)


def _estimate_crack_time(entropy_bits: float) -> str:
    """Rough offline brute-force estimate assuming 10^10 guesses/second
    (a realistic modern GPU cracking rig), averaging half the keyspace."""
    guesses_per_second = 10 ** 10
    total_guesses = 2 ** entropy_bits
    seconds = total_guesses / guesses_per_second / 2

    if seconds < 1:
        return "instantly"
    intervals = (
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    )
    for name, count in intervals:
        value = seconds / count
        if value >= 1:
            if value > 1_000_000:
                return f"{value:.2e} {name}"
            return f"{value:,.1f} {name}"
    return "instantly"


def calculate_strength(password: str) -> dict:
    """
    Master evaluation function. Returns a dict with everything the GUI
    needs to render: pass/fail checklist, numeric score, label, color,
    entropy, and estimated crack time.
    """
    classes = _check_character_classes(password)
    length_ok = _check_length(password)
    is_common = _is_common_password(password) if password else False
    variety_count = sum(classes.values())

    # --- Scoring model (0-100) ---------------------------------------- #
    length_score = min(len(password), 20) / 20 * 40          # up to 40 pts
    variety_score = variety_count / 4 * 40                     # up to 40 pts
    bonus = 0
    if len(password) >= 12:
        bonus += 10
    if len(password) >= 16:
        bonus += 10
    score = min(100, round(length_score + variety_score + bonus))

    # --- Immediate-fail gates ------------------------------------------ #
    reason = None
    if not password:
        score = 0
    elif is_common:
        score = min(score, 15)
        reason = "This password appears in known data-breach / leak lists."
    elif not length_ok:
        score = min(score, 30)
        reason = "Password is shorter than the required 8 characters."

    # --- Classification -------------------------------------------------#
    if not password:
        label, color = "—", "#6c7086"
    elif score < 40:
        label, color = "Weak", "#f38ba8"
    elif score < 70:
        label, color = "Medium", "#f9e2af"
    elif score < 90:
        label, color = "Strong", "#a6e3a1"
    else:
        label, color = "Very Strong", "#94e2d5"

    entropy_bits = _estimate_entropy_bits(password, classes)

    return {
        "length_ok": length_ok,
        "classes": classes,
        "is_common": is_common,
        "variety_count": variety_count,
        "score": score,
        "label": label,
        "color": color,
        "reason": reason,
        "entropy_bits": entropy_bits,
        "crack_time": _estimate_crack_time(entropy_bits) if password else "—",
    }


def generate_password(length: int = 16) -> str:
    """Cryptographically secure password generator (uses `secrets`, not
    `random`). Guarantees at least one char from every required class."""
    length = max(8, length)
    pools = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        SYMBOL_CHARS,
    ]
    # Guarantee one of each class first...
    chars = [secrets.choice(pool) for pool in pools]
    # ...then fill the rest randomly from the combined pool.
    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]
    # Shuffle so the guaranteed characters aren't always in the same spot.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ------------------------------------------------------------------------- #
# 2. GUI LAYER (Tkinter)
# ------------------------------------------------------------------------- #

BG = "#1e1e2e"
BG_PANEL = "#181825"
FG = "#cdd6f4"
FG_DIM = "#a6adc8"
ACCENT = "#89b4fa"
ENTRY_BG = "#313244"
BORDER = "#45475a"


class PasswordCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DecodeLabs · Password Strength Checker")
        self.geometry("560x640")
        self.minsize(520, 620)
        self.configure(bg=BG)

        self.show_password = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self._on_password_changed)

        self._build_style()
        self._build_header()
        self._build_input_row()
        self._build_meter()
        self._build_checklist()
        self._build_stats()
        self._build_actions()
        self._build_footer()

        self._on_password_changed()  # initialize UI in empty state

    # -- styling ----------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Gen.TButton",
            background=ACCENT, foreground="#1e1e2e",
            font=("Segoe UI", 10, "bold"), padding=8, borderwidth=0,
        )
        style.map("Gen.TButton", background=[("active", "#74a8f5")])
        style.configure(
            "Copy.TButton",
            background=ENTRY_BG, foreground=FG,
            font=("Segoe UI", 10), padding=8, borderwidth=0,
        )
        style.map("Copy.TButton", background=[("active", BORDER)])
        style.configure(
            "Len.Horizontal.TScale", background=BG, troughcolor=ENTRY_BG,
        )

    # -- header -------------------------------------------------------------
    def _build_header(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(22, 6))
        tk.Label(
            frame, text="🔐 Password Strength Checker", bg=BG, fg=FG,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")
        tk.Label(
            frame, text="DecodeLabs Industrial Kit · Project 1 · Defensive Logic",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 10),
        ).pack(anchor="w")

    # -- password entry row --------------------------------------------------
    def _build_input_row(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(18, 4))

        entry_wrap = tk.Frame(frame, bg=ENTRY_BG, highlightthickness=1,
                               highlightbackground=BORDER, highlightcolor=ACCENT)
        entry_wrap.pack(fill="x")

        self.entry = tk.Entry(
            entry_wrap, textvariable=self.password_var, show="•",
            bg=ENTRY_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 14), bd=0,
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(12, 4))
        self.entry.focus_set()

        self.toggle_btn = tk.Button(
            entry_wrap, text="Show", command=self._toggle_visibility,
            bg=ENTRY_BG, fg=ACCENT, relief="flat", bd=0,
            font=("Segoe UI", 9, "bold"), activebackground=ENTRY_BG,
            activeforeground="#74a8f5", cursor="hand2",
        )
        self.toggle_btn.pack(side="right", padx=10)

    def _toggle_visibility(self):
        self.show_password.set(not self.show_password.get())
        if self.show_password.get():
            self.entry.config(show="")
            self.toggle_btn.config(text="Hide")
        else:
            self.entry.config(show="•")
            self.toggle_btn.config(text="Show")

    # -- strength meter -------------------------------------------------------
    def _build_meter(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(18, 4))

        top_row = tk.Frame(frame, bg=BG)
        top_row.pack(fill="x")
        self.strength_label = tk.Label(
            top_row, text="—", bg=BG, fg=FG_DIM, font=("Segoe UI", 13, "bold"),
        )
        self.strength_label.pack(side="left")
        self.score_label = tk.Label(
            top_row, text="", bg=BG, fg=FG_DIM, font=("Segoe UI", 10),
        )
        self.score_label.pack(side="right")

        self.meter_canvas = tk.Canvas(
            frame, height=14, bg=ENTRY_BG, highlightthickness=0,
        )
        self.meter_canvas.pack(fill="x", pady=(8, 0))
        self.meter_canvas.bind("<Configure>", lambda e: self._redraw_meter())

        self.reason_label = tk.Label(
            frame, text="", bg=BG, fg="#f38ba8", font=("Segoe UI", 9),
            wraplength=500, justify="left",
        )
        self.reason_label.pack(anchor="w", pady=(6, 0))

    def _redraw_meter(self):
        self.meter_canvas.delete("all")
        w = self.meter_canvas.winfo_width()
        h = self.meter_canvas.winfo_height()
        result = calculate_strength(self.password_var.get())
        pct = result["score"] / 100
        # background track (rounded look via simple rect, kept simple/robust)
        self.meter_canvas.create_rectangle(0, 0, w, h, fill=ENTRY_BG, width=0)
        if pct > 0:
            self.meter_canvas.create_rectangle(
                0, 0, max(2, w * pct), h, fill=result["color"], width=0
            )

    # -- requirement checklist -------------------------------------------------
    def _build_checklist(self):
        frame = tk.LabelFrame(
            self, text=" Requirements ", bg=BG, fg=FG_DIM, bd=1,
            labelanchor="nw", relief="flat", font=("Segoe UI", 9, "bold"),
            highlightbackground=BORDER, highlightthickness=1,
        )
        frame.pack(fill="x", padx=24, pady=(20, 4), ipady=4)

        self.check_labels = {}
        rules = [
            ("length", "At least 8 characters"),
            ("upper", "Contains an uppercase letter (A-Z)"),
            ("lower", "Contains a lowercase letter (a-z)"),
            ("digit", "Contains a number (0-9)"),
            ("symbol", "Contains a symbol (!@#$%...)"),
            ("common", "Not found in leaked-password lists"),
        ]
        for key, text in rules:
            row = tk.Frame(frame, bg=BG)
            row.pack(fill="x", padx=14, pady=3)
            mark = tk.Label(row, text="○", bg=BG, fg=FG_DIM, font=("Segoe UI", 11))
            mark.pack(side="left")
            label = tk.Label(row, text=text, bg=BG, fg=FG_DIM, font=("Segoe UI", 10))
            label.pack(side="left", padx=(8, 0))
            self.check_labels[key] = (mark, label)

    def _update_checklist(self, result: dict):
        classes = result["classes"]
        states = {
            "length": result["length_ok"],
            "upper": classes["upper"],
            "lower": classes["lower"],
            "digit": classes["digit"],
            "symbol": classes["symbol"],
            "common": not result["is_common"] if self.password_var.get() else False,
        }
        for key, ok in states.items():
            mark, label = self.check_labels[key]
            if ok:
                mark.config(text="✓", fg="#a6e3a1")
                label.config(fg=FG)
            else:
                mark.config(text="○", fg=FG_DIM)
                label.config(fg=FG_DIM)

    # -- stats (entropy / crack time) -------------------------------------------
    def _build_stats(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(16, 4))

        self.entropy_label = tk.Label(
            frame, text="Entropy: —", bg=BG, fg=FG_DIM, font=("Segoe UI", 10),
        )
        self.entropy_label.pack(side="left")

        self.crack_label = tk.Label(
            frame, text="Est. crack time: —", bg=BG, fg=FG_DIM, font=("Segoe UI", 10),
        )
        self.crack_label.pack(side="right")

    # -- action buttons -------------------------------------------------------
    def _build_actions(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(24, 6))

        gen_frame = tk.Frame(frame, bg=BG)
        gen_frame.pack(fill="x")

        tk.Label(
            gen_frame, text="Generate length:", bg=BG, fg=FG_DIM,
            font=("Segoe UI", 9),
        ).pack(side="left")

        self.gen_length = tk.IntVar(value=16)
        length_spin = tk.Spinbox(
            gen_frame, from_=8, to=64, width=4, textvariable=self.gen_length,
            bg=ENTRY_BG, fg=FG, relief="flat", buttonbackground=ENTRY_BG,
            font=("Segoe UI", 9), insertbackground=FG,
        )
        length_spin.pack(side="left", padx=8)

        btn_row = tk.Frame(frame, bg=BG)
        btn_row.pack(fill="x", pady=(10, 0))

        ttk.Button(
            btn_row, text="⚡ Generate Strong Password", style="Gen.TButton",
            command=self._on_generate,
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))

        ttk.Button(
            btn_row, text="📋 Copy", style="Copy.TButton",
            command=self._on_copy,
        ).pack(side="left", fill="x", expand=True, padx=(6, 0))

    def _on_generate(self):
        pwd = generate_password(self.gen_length.get())
        self.password_var.set(pwd)
        self.show_password.set(True)
        self.entry.config(show="")
        self.toggle_btn.config(text="Hide")

    def _on_copy(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showinfo("Nothing to copy", "There's no password to copy yet.")
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    # -- footer -----------------------------------------------------------
    def _build_footer(self):
        tk.Label(
            self,
            text="Local evaluation only — nothing is sent over the network.",
            bg=BG, fg="#585b70", font=("Segoe UI", 8),
        ).pack(side="bottom", pady=10)

    # -- reactive update ----------------------------------------------------
    def _on_password_changed(self, *_):
        password = self.password_var.get()
        result = calculate_strength(password)

        self.strength_label.config(text=result["label"], fg=result["color"])
        self.score_label.config(text=f"{result['score']}/100" if password else "")
        self._redraw_meter()
        self._update_checklist(result)

        if result["reason"]:
            self.reason_label.config(text="⚠ " + result["reason"])
        else:
            self.reason_label.config(text="")

        if password:
            self.entropy_label.config(text=f"Entropy: ~{result['entropy_bits']:.1f} bits")
            self.crack_label.config(text=f"Est. crack time: {result['crack_time']}")
        else:
            self.entropy_label.config(text="Entropy: —")
            self.crack_label.config(text="Est. crack time: —")


if __name__ == "__main__":
    app = PasswordCheckerApp()
    app.mainloop()
