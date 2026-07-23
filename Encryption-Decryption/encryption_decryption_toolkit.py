"""
================================================================================
 Encryption & Decryption Toolkit (GUI Edition)
================================================================================

Author : Mustafa
Track  : Junior Analyst // Defensive Logic
Goal   : Implement classical encryption/decryption techniques to protect
         data confidentiality, and demonstrate through a live GUI both
         how these ciphers work and why the simplest of them are breakable.

Key requirements covered (per project brief):
    - Encrypt user text using a basic logic (Caesar cipher or similar)
    - Decrypt the encrypted text
    - Display both encrypted and decrypted output
Bonus features added (per "Conclusion" slide suggestions + vulnerability
material covered in the training deck):
    - User-selectable shift key (not hardcoded)
    - A second, stronger cipher (Vigenère) built on the same primitives
    - A third classical cipher (Atbash) for variety
    - A Frequency Analysis panel that visually demonstrates *why* the
      Caesar cipher is a "lockbox, not a vault" (pattern preservation)
    - A Brute Force panel that automatically tries all 26 Caesar shifts
      and ranks them by English-likeness demonstrating the "tiny key
      space" vulnerability called out directly in the training material

Design notes (matching the "Input Logic: ASCII" and "Process Logic: The
Shift" slides):
    - Every cipher is built on the same two primitives taught in the
      deck: ord() / chr() conversion and modular arithmetic (% 26).
    - Encryption formula:  E_n(x) = (x + n) % 26
    - Decryption formula:  D_n(x) = (x - n) % 26
    - Case is preserved; non-alphabetic characters (spaces, punctuation,
      digits) pass through unchanged the "Handle Edge Cases" requirement.
    - No external dependencies. Pure standard library (tkinter, string,
      collections, re) so it runs anywhere Python 3 + Tk is installed.
================================================================================
"""

import re
import tkinter as tk
from collections import Counter
from tkinter import ttk, messagebox


# ------------------------------------------------------------------------- #
# 1. CORE CIPHER LOGIC (kept UI-independent so it can be unit-tested / reused)
# ------------------------------------------------------------------------- #

ALPHABET_SIZE = 26

# Approximate relative frequency of each letter in typical English text
# (used as a reference overlay in the Frequency Analysis panel).
ENGLISH_LETTER_FREQ = {
    'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 12.7, 'F': 2.2, 'G': 2.0,
    'H': 6.1, 'I': 7.0, 'J': 0.2, 'K': 0.8, 'L': 4.0, 'M': 2.4, 'N': 6.7,
    'O': 7.5, 'P': 1.9, 'Q': 0.1, 'R': 6.0, 'S': 6.3, 'T': 9.1, 'U': 2.8,
    'V': 1.0, 'W': 2.4, 'X': 0.2, 'Y': 2.0, 'Z': 0.1,
}

# A small set of very common English words, used only to score how
# "readable" a brute-force candidate looks this is what lets the Brute
# Force panel automatically flag the most likely correct shift.
COMMON_WORDS = {
    "the", "and", "is", "in", "to", "of", "a", "that", "it", "for", "on",
    "with", "as", "was", "are", "this", "be", "at", "by", "an", "or",
    "not", "have", "from", "but", "they", "you", "we", "he", "she", "i",
}


def _shift_char(char: str, shift: int) -> str:
    """Shift a single character by `shift` positions using modular
    arithmetic, exactly per the training material's formula:
        E_n(x) = (x + n) % 26
    Preserves case. Non-alphabetic characters are returned unchanged
    this is the O(1) building block every cipher below is composed of.
    """
    if char.isupper():
        base = ord('A')
    elif char.islower():
        base = ord('a')
    else:
        return char  # spaces, digits, punctuation pass through untouched

    return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)


# --- Caesar Cipher --------------------------------------------------------- #

def caesar_encrypt(text: str, shift: int) -> str:
    """Single O(n) linear pass over the text matches the IPO model's
    complexity constraint from the training deck."""
    shift %= ALPHABET_SIZE
    return "".join(_shift_char(char, shift) for char in text)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decryption is just encryption with the shift negated:
        D_n(x) = (x - n) % 26
    """
    return caesar_encrypt(text, -shift)


# --- Vigenère Cipher (polyalphabetic a stronger evolution of Caesar) ---- #

def _vigenere(text: str, keyword: str, encrypting: bool) -> str:
    if not keyword or not keyword.isalpha():
        raise ValueError("Vigenère keyword must contain letters only.")

    keyword = keyword.upper()
    result = []
    key_index = 0
    key_len = len(keyword)

    for char in text:
        if char.isalpha():
            key_shift = ord(keyword[key_index % key_len]) - ord('A')
            shift = key_shift if encrypting else -key_shift
            result.append(_shift_char(char, shift))
            key_index += 1  # only advances the key on alphabetic input
        else:
            result.append(char)

    return "".join(result)


def vigenere_encrypt(text: str, keyword: str) -> str:
    return _vigenere(text, keyword, encrypting=True)


def vigenere_decrypt(text: str, keyword: str) -> str:
    return _vigenere(text, keyword, encrypting=False)


# --- Atbash Cipher (mirror substitution self-inverse, no key needed) --- #

def atbash(text: str) -> str:
    """A ↔ Z, B ↔ Y, ... Self-inverse: running it twice returns the
    original text, so the same function serves as both encrypt and
    decrypt."""
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(ord('Z') - (ord(char) - ord('A'))))
        elif char.islower():
            result.append(chr(ord('z') - (ord(char) - ord('a'))))
        else:
            result.append(char)
    return "".join(result)


# --- Frequency Analysis (demonstrates the Caesar cipher's vulnerability) - #

def letter_frequency(text: str) -> dict:
    """Returns {letter: percentage} for A-Z based on alphabetic
    characters only, matching the training deck's frequency-analysis
    vulnerability slide."""
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters)
    counts = Counter(letters)
    return {
        chr(ord('A') + i): (counts.get(chr(ord('A') + i), 0) / total * 100
                             if total else 0.0)
        for i in range(ALPHABET_SIZE)
    }


# --- Brute Force Analyzer (demonstrates the "tiny key space" weakness) --- #

def _readability_score(text: str) -> int:
    """Counts whole-word matches against a small common-word list.
    Higher score = more likely to be genuine English."""
    words = re.findall(r"[a-zA-Z']+", text.lower())
    return sum(1 for word in words if word in COMMON_WORDS)


def brute_force_caesar(ciphertext: str) -> list:
    """Tries all 26 possible Caesar shifts (the entire key space) and
    returns a list of (shift, decrypted_text, score) tuples sorted by
    descending readability score the most likely correct shift floats
    to the top automatically."""
    candidates = []
    for shift in range(ALPHABET_SIZE):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = _readability_score(decrypted)
        candidates.append((shift, decrypted, score))
    return sorted(candidates, key=lambda item: item[2], reverse=True)


# ------------------------------------------------------------------------- #
# 2. GUI LAYER (Tkinter) dark theme kept consistent with Project 1
# ------------------------------------------------------------------------- #

BG = "#1e1e2e"
BG_PANEL = "#181825"
FG = "#cdd6f4"
FG_DIM = "#a6adc8"
ACCENT = "#89b4fa"
ACCENT_GREEN = "#a6e3a1"
ACCENT_RED = "#f38ba8"
ENTRY_BG = "#313244"
BORDER = "#45475a"

CIPHERS = ("Caesar Cipher", "Vigenère Cipher", "Atbash Cipher")


class CipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encryption & Decryption Toolkit")
        self.geometry("880x760")
        self.minsize(820, 700)
        self.configure(bg=BG)

        self._build_style()
        self._build_header()
        self._build_notebook()

    # -- styling ------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab", background=BG_PANEL, foreground=FG_DIM,
            padding=(16, 10), font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ENTRY_BG)],
            foreground=[("selected", FG)],
        )

        style.configure(
            "Accent.TButton", background=ACCENT, foreground="#1e1e2e",
            font=("Segoe UI", 10, "bold"), padding=8, borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", "#74a8f5")])

        style.configure(
            "Ghost.TButton", background=ENTRY_BG, foreground=FG,
            font=("Segoe UI", 9), padding=6, borderwidth=0,
        )
        style.map("Ghost.TButton", background=[("active", BORDER)])

        style.configure(
            "TCombobox", fieldbackground=ENTRY_BG, background=ENTRY_BG,
            foreground=FG, arrowcolor=FG,
        )

        style.configure(
            "Treeview", background=ENTRY_BG, fieldbackground=ENTRY_BG,
            foreground=FG, rowheight=26, borderwidth=0,
        )
        style.configure(
            "Treeview.Heading", background=BG_PANEL, foreground=FG,
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", ACCENT)])

    # -- header ---------------------------------------------------------------
    def _build_header(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(20, 8))
        tk.Label(
            frame, text="🔒 Encryption & Decryption Toolkit", bg=BG, fg=FG,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")
        tk.Label(
            frame,
            text="Project 2 · Data Confidentiality",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 10),
        ).pack(anchor="w")

    # -- notebook (tabs) --------------------------------------------------------
    def _build_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(4, 20))

        self.cipher_tab = tk.Frame(self.notebook, bg=BG)
        self.freq_tab = tk.Frame(self.notebook, bg=BG)
        self.brute_tab = tk.Frame(self.notebook, bg=BG)

        self.notebook.add(self.cipher_tab, text="🔐  Encrypt / Decrypt")
        self.notebook.add(self.freq_tab, text="📊  Frequency Analysis")
        self.notebook.add(self.brute_tab, text="🕵️  Brute Force (Caesar)")

        self._build_cipher_tab()
        self._build_frequency_tab()
        self._build_brute_force_tab()

    # ===================================================================== #
    # TAB 1 Encrypt / Decrypt
    # ===================================================================== #
    def _build_cipher_tab(self):
        tab = self.cipher_tab

        # --- cipher selector + key row ---
        control_row = tk.Frame(tab, bg=BG)
        control_row.pack(fill="x", padx=4, pady=(16, 8))

        tk.Label(control_row, text="Cipher:", bg=BG, fg=FG_DIM,
                  font=("Segoe UI", 10)).pack(side="left")

        self.cipher_var = tk.StringVar(value=CIPHERS[0])
        cipher_dropdown = ttk.Combobox(
            control_row, textvariable=self.cipher_var, values=CIPHERS,
            state="readonly", width=18, font=("Segoe UI", 10),
        )
        cipher_dropdown.pack(side="left", padx=(8, 24))
        cipher_dropdown.bind("<<ComboboxSelected>>", self._on_cipher_change)

        self.key_label = tk.Label(control_row, text="Shift (0-25):", bg=BG,
                                    fg=FG_DIM, font=("Segoe UI", 10))
        self.key_label.pack(side="left")

        self.key_var = tk.StringVar(value="3")
        self.key_entry = tk.Entry(
            control_row, textvariable=self.key_var, bg=ENTRY_BG, fg=FG,
            insertbackground=FG, relief="flat", width=18,
            font=("Consolas", 10),
        )
        self.key_entry.pack(side="left", padx=(8, 0), ipady=4)

        # --- input text ---
        tk.Label(tab, text="Input Text", bg=BG, fg=FG_DIM,
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=4, pady=(12, 2))
        self.input_text = tk.Text(
            tab, height=7, bg=ENTRY_BG, fg=FG, insertbackground=FG,
            relief="flat", font=("Consolas", 11), wrap="word",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        self.input_text.pack(fill="both", expand=False, padx=4)

        # --- action buttons ---
        btn_row = tk.Frame(tab, bg=BG)
        btn_row.pack(fill="x", padx=4, pady=10)

        ttk.Button(btn_row, text="🔒 Encrypt ▶", style="Accent.TButton",
                    command=self._on_encrypt).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="🔓 Decrypt ▶", style="Accent.TButton",
                    command=self._on_decrypt).pack(side="left", padx=6)
        ttk.Button(btn_row, text="⇄ Swap", style="Ghost.TButton",
                    command=self._on_swap).pack(side="left", padx=6)
        ttk.Button(btn_row, text="📋 Copy Result", style="Ghost.TButton",
                    command=self._on_copy).pack(side="left", padx=6)
        ttk.Button(btn_row, text="🗑 Clear", style="Ghost.TButton",
                    command=self._on_clear).pack(side="left", padx=6)

        # --- output text ---
        tk.Label(tab, text="Result", bg=BG, fg=FG_DIM,
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=4, pady=(4, 2))
        self.output_text = tk.Text(
            tab, height=7, bg=ENTRY_BG, fg=ACCENT_GREEN, insertbackground=FG,
            relief="flat", font=("Consolas", 11), wrap="word",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT, state="disabled",
        )
        self.output_text.pack(fill="both", expand=False, padx=4)

        self.status_label = tk.Label(
            tab, text="", bg=BG, fg=FG_DIM, font=("Segoe UI", 9),
        )
        self.status_label.pack(anchor="w", padx=4, pady=(8, 0))

    def _on_cipher_change(self, *_):
        cipher = self.cipher_var.get()
        if cipher == "Caesar Cipher":
            self.key_label.config(text="Shift (0-25):")
            self.key_entry.config(state="normal")
        elif cipher == "Vigenère Cipher":
            self.key_label.config(text="Keyword:")
            self.key_entry.config(state="normal")
        else:  # Atbash needs no key
            self.key_label.config(text="No key needed:")
            self.key_entry.config(state="disabled")

    def _get_input(self) -> str:
        return self.input_text.get("1.0", "end-1c")

    def _set_output(self, text: str):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.config(state="disabled")

    def _run_cipher(self, encrypting: bool):
        text = self._get_input()
        if not text:
            self.status_label.config(text="⚠ Enter some text first.", fg=ACCENT_RED)
            return
        cipher = self.cipher_var.get()

        try:
            if cipher == "Caesar Cipher":
                shift = int(self.key_var.get())
                if not (0 <= shift <= 25):
                    raise ValueError("Shift must be between 0 and 25.")
                result = (caesar_encrypt(text, shift) if encrypting
                          else caesar_decrypt(text, shift))
            elif cipher == "Vigenère Cipher":
                keyword = self.key_var.get().strip()
                result = (vigenere_encrypt(text, keyword) if encrypting
                          else vigenere_decrypt(text, keyword))
            else:  # Atbash self-inverse, same op either direction
                result = atbash(text)

            self._set_output(result)
            action = "Encrypted" if encrypting else "Decrypted"
            self.status_label.config(
                text=f"✓ {action} using {cipher} {len(text)} characters processed.",
                fg=ACCENT_GREEN,
            )
        except ValueError as exc:
            self.status_label.config(text=f"⚠ {exc}", fg=ACCENT_RED)

    def _on_encrypt(self):
        self._run_cipher(encrypting=True)

    def _on_decrypt(self):
        self._run_cipher(encrypting=False)

    def _on_swap(self):
        """Moves the result into the input box handy for chaining
        operations or double-checking a decrypt round-trip."""
        result = self.output_text.get("1.0", "end-1c")
        if not result:
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", result)

    def _on_copy(self):
        result = self.output_text.get("1.0", "end-1c")
        if not result:
            messagebox.showinfo("Nothing to copy", "There's no result to copy yet.")
            return
        self.clipboard_clear()
        self.clipboard_append(result)
        self.status_label.config(text="✓ Result copied to clipboard.", fg=ACCENT_GREEN)

    def _on_clear(self):
        self.input_text.delete("1.0", "end")
        self._set_output("")
        self.status_label.config(text="")

    # ===================================================================== #
    # TAB 2 Frequency Analysis
    # ===================================================================== #
    def _build_frequency_tab(self):
        tab = self.freq_tab

        tk.Label(
            tab,
            text="Compares the letter frequency of your current text against "
                 "typical English. A Caesar-shifted text preserves the exact "
                 "same distribution *shape* just shifted which is exactly "
                 "how frequency analysis breaks it.",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 9), wraplength=800,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(16, 8))

        btn_row = tk.Frame(tab, bg=BG)
        btn_row.pack(fill="x", padx=4, pady=(0, 8))
        ttk.Button(btn_row, text="Analyze Input Text", style="Accent.TButton",
                    command=lambda: self._draw_frequency_chart(self._get_input())
                    ).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Analyze Result Text", style="Ghost.TButton",
                    command=lambda: self._draw_frequency_chart(
                        self.output_text.get("1.0", "end-1c"))
                    ).pack(side="left")

        legend = tk.Frame(tab, bg=BG)
        legend.pack(anchor="w", padx=4, pady=(0, 4))
        tk.Label(legend, text="■", bg=BG, fg=ACCENT, font=("Segoe UI", 10)).pack(side="left")
        tk.Label(legend, text=" Your text   ", bg=BG, fg=FG_DIM, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(legend, text="■", bg=BG, fg=FG_DIM, font=("Segoe UI", 10)).pack(side="left")
        tk.Label(legend, text=" Typical English", bg=BG, fg=FG_DIM, font=("Segoe UI", 9)).pack(side="left")

        self.freq_canvas = tk.Canvas(tab, height=360, bg=BG_PANEL, highlightthickness=0)
        self.freq_canvas.pack(fill="both", expand=True, padx=4, pady=(4, 16))
        self.freq_canvas.bind("<Configure>", lambda e: self._draw_frequency_chart(
            self._get_input()))

    def _draw_frequency_chart(self, text: str):
        canvas = self.freq_canvas
        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 50 or h < 50:
            return

        freqs = letter_frequency(text) if text else {chr(65 + i): 0 for i in range(26)}
        max_val = max(max(freqs.values(), default=1), max(ENGLISH_LETTER_FREQ.values())) or 1

        margin_bottom = 30
        chart_h = h - margin_bottom
        bar_group_w = w / 26
        bar_w = bar_group_w * 0.35

        for i, letter in enumerate(sorted(freqs)):
            x0 = i * bar_group_w + bar_group_w * 0.15
            user_h = (freqs[letter] / max_val) * chart_h
            eng_h = (ENGLISH_LETTER_FREQ[letter] / max_val) * chart_h

            # reference (typical English) bar, drawn behind/beside
            canvas.create_rectangle(
                x0 + bar_w, chart_h - eng_h, x0 + 2 * bar_w, chart_h,
                fill=FG_DIM, width=0,
            )
            # user text bar
            canvas.create_rectangle(
                x0, chart_h - user_h, x0 + bar_w, chart_h,
                fill=ACCENT, width=0,
            )
            canvas.create_text(
                x0 + bar_w, h - margin_bottom / 2, text=letter,
                fill=FG_DIM, font=("Consolas", 8),
            )

    # ===================================================================== #
    # TAB 3 Brute Force (Caesar)
    # ===================================================================== #
    def _build_brute_force_tab(self):
        tab = self.brute_tab

        tk.Label(
            tab,
            text="The Caesar cipher only has 26 possible keys small enough "
                 "to try every single one instantly. This is the 'Tiny Key "
                 "Space' vulnerability: run this on any Caesar-encrypted text "
                 "below and the most English-like result is ranked to the top.",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 9), wraplength=800,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(16, 8))

        input_row = tk.Frame(tab, bg=BG)
        input_row.pack(fill="x", padx=4, pady=(0, 8))
        self.brute_input = tk.Entry(
            input_row, bg=ENTRY_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 11),
        )
        self.brute_input.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        ttk.Button(input_row, text="🕵️ Crack It", style="Accent.TButton",
                    command=self._on_brute_force).pack(side="left")
        ttk.Button(input_row, text="Use Result Text", style="Ghost.TButton",
                    command=self._load_result_into_brute_input).pack(side="left", padx=(8, 0))

        columns = ("shift", "score", "text")
        self.brute_tree = ttk.Treeview(tab, columns=columns, show="headings", height=20)
        self.brute_tree.heading("shift", text="Shift")
        self.brute_tree.heading("score", text="English Score")
        self.brute_tree.heading("text", text="Decrypted Candidate")
        self.brute_tree.column("shift", width=60, anchor="center")
        self.brute_tree.column("score", width=110, anchor="center")
        self.brute_tree.column("text", width=560, anchor="w")
        self.brute_tree.pack(fill="both", expand=True, padx=4, pady=(4, 16))

    def _load_result_into_brute_input(self):
        result = self.output_text.get("1.0", "end-1c")
        self.brute_input.delete(0, "end")
        self.brute_input.insert(0, result)

    def _on_brute_force(self):
        ciphertext = self.brute_input.get()
        for row in self.brute_tree.get_children():
            self.brute_tree.delete(row)

        if not ciphertext:
            messagebox.showinfo("Nothing to crack", "Enter some Caesar-encrypted text first.")
            return

        candidates = brute_force_caesar(ciphertext)
        top_score = candidates[0][2] if candidates else 0
        for shift, decrypted, score in candidates:
            tag = "top" if score == top_score and score > 0 else ""
            preview = decrypted if len(decrypted) <= 80 else decrypted[:77] + "..."
            self.brute_tree.insert("", "end", values=(shift, score, preview), tags=(tag,))

        self.brute_tree.tag_configure("top", background="#2d4a2f", foreground=ACCENT_GREEN)


if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()
