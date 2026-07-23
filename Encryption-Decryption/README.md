# 🔒 Encryption & Decryption Toolkit

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

A desktop GUI tool built with Python's Tkinter that implements three classical ciphers, then goes a step further by demonstrating *why* the simplest of them can be broken with a live frequency-analysis chart and an automatic brute-force cracker.

> **Project 2**
> Track: Junior Analyst // Defensive Logic Data Confidentiality

<p align="center">
  <img src="assets/screenshot_main.png" alt="Encryption & Decryption Toolkit main tab" width="420">
</p>

---

## ✨ Features

| Feature | Description |
|---|---|
| **Caesar Cipher** | Classic shift cipher with a user-selectable key (0–25), not hardcoded |
| **Vigenère Cipher** | Polyalphabetic cipher using a keyword a stronger evolution of Caesar |
| **Atbash Cipher** | Mirror-alphabet substitution (A↔Z, B↔Y…), self-inverse, no key needed |
| **Encrypt & Decrypt, side by side** | Input and result are always shown together, exactly as the brief requires |
| **Frequency Analysis panel** | Live bar chart comparing your text's letter frequency against typical English visualizes *why* Caesar-shifted text is still crackable |
| **Brute Force panel** | Automatically tries all 26 Caesar shifts and ranks them by English-likeness, demonstrating the "tiny key space" vulnerability |
| **Swap / Copy / Clear** | Quality-of-life tools for chaining operations and grabbing results |
| **Edge-case safe** | Spaces, punctuation, digits, and case are all preserved correctly |
| **No external dependencies** | Pure Python standard library nothing to `pip install` |

<p align="center">
  <img src="assets/screenshot_frequency.png" alt="Frequency Analysis tab" width="410">
  <img src="assets/screenshot_bruteforce.png" alt="Brute Force tab" width="410">
</p>

---

## 📋 Requirements

- Python **3.8+**
- Tkinter (usually bundled with Python; see [Troubleshooting](#-troubleshooting) if missing)

No third-party packages required the entire app runs on the standard library (`tkinter`, `collections`, `re`).

---

## 🚀 Getting Started

```bash
python3 encryption_decryption_toolkit.py
```

A window titled **"Encryption & Decryption Toolkit"** opens with three tabs: Encrypt/Decrypt, Frequency Analysis, and Brute Force.

---

## 🖥️ How to Use

### Encrypt / Decrypt tab
1. Choose a cipher from the dropdown: **Caesar**, **Vigenère**, or **Atbash**.
2. Enter the key a number (0–25) for Caesar, a word for Vigenère, or nothing for Atbash.
3. Type or paste your text into **Input Text**.
4. Click **🔒 Encrypt** or **🔓 Decrypt**. The result appears in the **Result** box below.
5. Use **⇄ Swap** to move the result back into the input (handy for verifying a round-trip), **📋 Copy Result** to grab it, or **🗑 Clear** to reset both boxes.

### Frequency Analysis tab
Click **Analyze Input Text** or **Analyze Result Text** to draw a bar chart comparing your text's letter frequency (blue bars) against typical English letter frequency (grey bars). Because Caesar simply *shifts* every letter by the same amount, the shape of the distribution stays identical just rotated. This is exactly what lets an attacker recover the shift without ever knowing the key.

### Brute Force tab
Paste any Caesar-encrypted text (or click **Use Result Text** to pull it from the main tab) and click **🕵️ Crack It**. All 26 possible shifts are tried and listed, ranked by how many common English words each decrypted candidate contains the most likely correct answer is highlighted at the top.

---

## 🧠 How the Ciphers Work

All three ciphers are built on the same two primitives:

```python
E_n(x) = (x + n) % 26     # Encryption: shift forward by n
D_n(x) = (x - n) % 26     # Decryption: shift backward by n
```

Text is converted to numbers with `ord()`, shifted with modular arithmetic so the alphabet "wraps around" (Z + 1 → A), and converted back with `chr()`. Case is preserved and non-alphabetic characters pass through untouched.

| Cipher | Key type | How it differs |
|---|---|---|
| **Caesar** | Single number (0–25) | Every letter shifted by the same fixed amount |
| **Vigenère** | Word/phrase | Shift amount changes per letter, cycling through the keyword's letters defeats simple frequency analysis |
| **Atbash** | None | Fixed mirror substitution; mathematically a Caesar-like reflection rather than a shift |

**Why Caesar is a "lockbox, not a vault":** it has only 26 possible keys (a *tiny key space*, instantly brute-forceable) and it preserves the letter-frequency *pattern* of the original language (just shifted), which is exactly what the Frequency Analysis and Brute Force tabs in this app are built to demonstrate.

---

## 📁 Project Structure

```
encryption_decryption_toolkit.py   # Single-file application
├── Core cipher logic (no GUI dependency)
│   ├── caesar_encrypt() / caesar_decrypt()
│   ├── vigenere_encrypt() / vigenere_decrypt()
│   ├── atbash()
│   ├── letter_frequency()
│   └── brute_force_caesar()
└── GUI layer (Tkinter)
    └── CipherApp        # window, three-tab notebook, live update binding
```

The cipher logic is intentionally independent of Tkinter, so it can be imported and reused without any GUI code running:

```python
from encryption_decryption_toolkit import caesar_encrypt, caesar_decrypt, vigenere_encrypt

ciphertext = caesar_encrypt("Attack at dawn", 7)
print(ciphertext)                        # "Haaham ha kubu"
print(caesar_decrypt(ciphertext, 7))     # "Attack at dawn"

print(vigenere_encrypt("Attack at dawn", "KEY"))
```

---

## ✅ Testing

Core logic was validated with round-trip tests (encrypt → decrypt returns the original text) for all three ciphers, plus a brute-force test confirming the cracker correctly identifies a known shift on a multi-word sentence. The script also passes `py_compile` with no syntax errors, and the GUI was smoke-tested headlessly across all three tabs to confirm it initializes and updates without exceptions.

Quick manual check:

```bash
python3 -c "
from encryption_decryption_toolkit import caesar_encrypt, caesar_decrypt, brute_force_caesar
ct = caesar_encrypt('The meeting is at midnight near the old bridge', 7)
print('Ciphertext:', ct)
print('Top brute-force guess:', brute_force_caesar(ct)[0])
"
```

---

## ⚠️ Scope & Limitations

- These are **classical, educational ciphers** Caesar, Vigenère, and Atbash are all breakable with enough ciphertext and are not suitable for real-world data protection.
- Real-world confidentiality requires modern authenticated encryption (e.g. AES-256-GCM) with securely generated and stored keys out of scope for this project, which focuses on the underlying logic of encryption/decryption and detection of weak schemes.
- The Vigenère implementation here only advances the keyword index on alphabetic characters, so spaces/punctuation don't consume a key position a deliberate design choice to keep the ciphertext's non-letter structure identical to the plaintext's.

---

## 🔧 Troubleshooting

**`ModuleNotFoundError: No module named 'tkinter'`**
```bash
# Debian / Ubuntu
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# macOS (Homebrew Python)
brew install python-tk
```

**Window doesn't appear / app hangs on a headless server**
Tkinter requires a display. Run it inside a desktop environment, over X11 forwarding (SSH `-X`), or with a virtual display such as `Xvfb`.

---

## 📄 License

Released under the [MIT License](../LICENSE) (repo root). Created as part of the DecodeLabs Industrial Training Kit (Batch 2026) for academic and portfolio purposes.
