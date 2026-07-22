# 🔐 Password Strength Checker

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

A desktop GUI tool built with Python's Tkinter that evaluates password strength in real time — going beyond a simple weak/medium/strong label to include entropy estimation, leaked-password detection, and a built-in secure password generator.

> **Project 1**
> Track: Junior Analyst // Defensive Logic

<p align="center">
  <img src="assets/screenshot.png" alt="Password Strength Checker screenshot" width="420">
</p>

---

## ✨ Features

| Feature | Description |
|---|---|
| **Live strength meter** | Colour-coded bar + label (Weak → Medium → Strong → Very Strong) that updates on every keystroke |
| **Requirement checklist** | Six live-updating checks: length, uppercase, lowercase, digit, symbol, not-leaked |
| **Leaked password detection** | Flags passwords found in a common/known-breach password list, capping the score even if character rules are met |
| **Entropy estimate** | Calculates approximate entropy in bits based on password length and character-set size |
| **Crack-time estimate** | Translates entropy into a human-readable estimated offline brute-force time |
| **Secure password generator** | Uses Python's `secrets` module (cryptographically secure) to generate strong passwords of adjustable length, guaranteeing all character classes are present |
| **Show / Hide toggle** | Reveal or mask the password field on demand |
| **Copy to clipboard** | One click to copy the current password |
| **No external dependencies** | Pure Python standard library — nothing to `pip install` |

---

## 📋 Requirements

- Python **3.8+**
- Tkinter (usually bundled with Python; see [Troubleshooting](#-troubleshooting) if missing)

No third-party packages are required — the entire app runs on the standard library (`tkinter`, `secrets`, `string`, `math`).

---

## 🚀 Getting Started

1. **Clone or download** this project folder.
2. Make sure Python 3 is installed:
   ```bash
   python3 --version
   ```
3. Run the app:
   ```bash
   python3 password_strength_checker.py
   ```
4. A window titled **"Password Strength Checker"** will open. Start typing in the password field to see live feedback.

---

## 🖥️ How to Use

1. **Type or paste a password** into the input field — the strength meter, score, requirement checklist, entropy, and estimated crack time all update instantly.
2. **Click "Show / Hide"** to toggle whether the password is masked with `•` characters.
3. **Set a generate length** (8–64) in the spinbox, then click **"⚡ Generate Strong Password"** to create a cryptographically secure password that satisfies every requirement automatically.
4. **Click "📋 Copy"** to copy the current password to your clipboard.

---

## 🧠 How Strength Is Calculated

The checker computes a score out of 100 from three components, then applies override rules:

| Component | Formula | Max Points |
|---|---|---|
| Length score | `min(length, 20) / 20 × 40` | 40 |
| Character-variety score | `(classes present / 4) × 40` | 40 |
| Length bonus | `+10` if length ≥ 12, `+10` if length ≥ 16 | 20 |

**Override rules (hard caps):**
- Password shorter than **8 characters** → score capped at **30**
- Password found in the **common/leaked password list** → score capped at **15**

**Classification thresholds:**

| Score | Label |
|---|---|
| 0–39 | Weak |
| 40–69 | Medium |
| 70–89 | Strong |
| 90–100 | Very Strong |

**Entropy** is estimated as `bits = length × log2(charset_size)`, where `charset_size` depends on which character classes (lowercase, uppercase, digits, symbols) are present. **Estimated crack time** assumes an offline attacker guessing at 10¹⁰ guesses/second, averaging over half the keyspace.

---

## 📁 Project Structure

```
password_strength_checker.py   # Single-file application
├── Core logic (no GUI dependency)
│   ├── _check_length()
│   ├── _check_character_classes()
│   ├── _is_common_password()
│   ├── _estimate_entropy_bits()
│   ├── _estimate_crack_time()
│   ├── calculate_strength()      # main evaluation entry point
│   └── generate_password()       # secure password generator
└── GUI layer (Tkinter)
    └── PasswordCheckerApp        # window, widgets, live update binding
```

The core logic is intentionally kept independent of Tkinter, so it can be imported and reused (e.g. in a CLI tool, a web backend, or unit tests) without pulling in any GUI code:

```python
from password_strength_checker import calculate_strength, generate_password

result = calculate_strength("MyP@ssw0rd123")
print(result["label"], result["score"])   # e.g. "Strong" 82

new_password = generate_password(20)
print(new_password)
```

---

## ✅ Testing

The logic was validated with sample inputs covering every classification tier and edge case (empty input, too-short input, common/leaked passwords, high-entropy passwords, and generator output). The script also passes `py_compile` with no syntax errors, and the GUI was smoke-tested to confirm it initializes and updates without exceptions.

To run a quick manual check yourself:

```bash
python3 -c "
from password_strength_checker import calculate_strength
for pwd in ['', '123', 'password', 'Password1', 'P@ssw0rd!23', 'Tr0ub4dor&3xyzLONG!']:
    r = calculate_strength(pwd)
    print(f'{pwd!r:25} -> {r[\"label\"]:12} score={r[\"score\"]}')
"
```

---

## ⚠️ Scope & Limitations

- This is a **validation-only** tool — it does not hash, store, encrypt, or transmit any password anywhere. Everything runs locally in memory.
- The leaked-password list is a small, illustrative sample (~50 entries), not a comprehensive breach database. For production use, integrate a service such as the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) (which uses k-anonymity so full passwords are never sent over the network).
- Hashing (e.g. Argon2id) and constant-time comparison (`hmac.compare_digest`) are **out of scope** for this project — they belong to the next milestone (Project 2: Hashing & Encryption) in the training track.

See the accompanying `Password_Strength_Checker_Report.docx` for full design rationale, the requirements traceability table, and detailed test results.

---

## 🔧 Troubleshooting

**`ModuleNotFoundError: No module named 'tkinter'`**
Tkinter isn't always bundled by default on Linux. Install it via your package manager:
```bash
# Debian / Ubuntu
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# macOS (Homebrew Python)
brew install python-tk
```
On Windows, Tkinter ships with the official python.org installer by default.

**Window doesn't appear / app hangs on a headless server**
Tkinter requires a display. On a headless Linux server, run it inside a desktop environment, over X11 forwarding (SSH `-X`), or with a virtual display such as `Xvfb`.

---

## 🗂️ Repository Contents

```
.
├── password_strength_checker.py          # Main application
├── README.md                             # This file
├── Password_Strength_Checker_Report.docx # Full technical/design report
├── requirements.txt                      # Dependency notes (none required)
├── LICENSE                                # MIT License
├── CHANGELOG.md                          # Version history
├── .gitignore                            # Python-focused ignore rules
├── assets/
│   └── screenshot.png                    # GUI screenshot used above
└── .github/
    └── workflows/
        └── ci.yml                        # GitHub Actions: syntax + smoke tests
```

---

## 🤝 Contributing

This is primarily a personal coursework/portfolio project, but suggestions and bug reports are welcome — feel free to open an issue or submit a pull request.

---

## 📄 License

Released under the [MIT License](LICENSE). Created as part of the DecodeLabs Industrial Training Kit (Batch 2026) for academic and portfolio purposes.
