# 🎣 Phishing Red-Flag Analyzer

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

A desktop GUI tool built with Python's Tkinter that analyzes URLs and email/message text against a library of known phishing indicators turning manual red-flag analysis into a repeatable, automated triage tool.

> **Project 3**
> Track: Junior Analyst // Defensive Logic Threat Identification

<p align="center">
  <img src="assets/screenshot_url_analyzer.png" alt="URL Analyzer tab" width="420">
</p>

---

## ✨ Features

| Feature | Description |
|---|---|
| **URL Analyzer** | Checks a single link for 11 distinct phishing indicators: IP-based URLs, the `@` trick, non-standard ports, URL shorteners, suspicious TLDs, homoglyph/punycode domains, excessive subdomains, typosquatting, combosquatting, missing HTTPS, and unusually long URLs |
| **Message Analyzer** | Scans pasted email/message text for cognitive-trigger language (urgency, authority, fear/greed, secrecy), requests for sensitive information, generic greetings, dangerous attachment extensions, sender display-name/domain mismatches, and any embedded URLs (each independently analyzed) |
| **Automatic verdict** | Every analysis ends in one of three actionable outcomes **Safe → Close**, **Suspicious → Warn User**, **Malicious → Block & Escalate** matching the triage decision tree taught in the training material |
| **Plain-English explanations** | Every flag says not just *what* was detected but *why* it's a problem directly satisfying the brief's "explain why the message is unsafe" requirement |
| **Sample Library** | Four built-in illustrative examples (credential-harvesting reset email, CEO wire-transfer fraud, prize-scam smishing-style message, and a genuinely safe internal memo) for hands-on practice |
| **100% local, no network calls** | Everything is pattern-based analysis on text you provide no live threat-intel lookups, no data leaves your machine |

<p align="center">
  <img src="assets/screenshot_message_analyzer.png" alt="Message Analyzer tab" width="410">
  <img src="assets/screenshot_sample_library.png" alt="Sample Library tab" width="410">
</p>

---

## 📋 Requirements

- Python **3.8+**
- Tkinter (usually bundled with Python; see [Troubleshooting](#-troubleshooting) if missing)

No third-party packages required the entire app runs on the standard library (`tkinter`, `re`, `ipaddress`, `unicodedata`, `urllib.parse`).

---

## 🚀 Getting Started

```bash
python3 phishing_redflag_analyzer.py
```

A window titled **"Phishing Red-Flag Analyzer"** opens with three tabs: URL Analyzer, Message Analyzer, and Sample Library.

---

## 🖥️ How to Use

### URL Analyzer tab
Paste any single URL and click **🔍 Analyze URL**. Every triggered red flag is listed with its severity and a plain-English explanation of why it matters.

### Message Analyzer tab
Paste the full body of an email or message (optionally filling in the sender's display name and email address to enable display-name/domain mismatch detection), then click **🔍 Analyze Message**. Any URLs found inside the message text are automatically extracted and analyzed too.

### Sample Library tab
Click **Load →** next to any of the four built-in examples to instantly populate the Message Analyzer and see a full breakdown a good way to calibrate your own judgment before testing real-world messages.

---

## 🧠 Red Flags Detected and Why Each One Matters

| Category | Indicators checked |
|---|---|
| **Domain deception** | IP-based links, typosquatting (edit-distance comparison against known brands), combosquatting, homoglyph/punycode domains, excessive "subdomain trap" nesting |
| **Link mechanics** | The `@` authority-hiding trick, non-standard ports, URL shorteners, missing HTTPS, unusually long URLs, suspicious/abused TLDs |
| **Psychological triggers** | Urgency ("act now", "24 hours"), authority impersonation ("IT support", "CEO"), fear/greed ("your account is suspended", "you have won"), requests for secrecy or to bypass procedure |
| **Data harvesting** | Direct requests for passwords, MFA/OTP codes, card numbers, or bank details |
| **Presentation anomalies** | Generic greetings ("Dear Customer"), sender display-name not matching the actual sending domain, dangerous attachment extensions (`.exe`, `.scr`, `.js`, `.iso`, etc.) |

Each of these maps directly to a red flag named in the training material this tool doesn't invent new heuristics, it operationalizes the ones already identified as high-value indicators.

---

## 📁 Project Structure

```
phishing_redflag_analyzer.py   # Single-file application
├── Core analysis logic (no GUI dependency)
│   ├── analyze_url()          # 11-point URL red-flag scan
│   ├── analyze_message()      # message-level scan + embedded URL analysis
│   ├── _classify()            # maps flags -> Safe / Suspicious / Malicious
│   └── SAMPLE_MESSAGES        # 4 built-in illustrative examples
└── GUI layer (Tkinter)
    └── PhishingAnalyzerApp    # window, three-tab notebook, live rendering
```

The analysis logic is intentionally independent of Tkinter, so it can be imported and reused without any GUI code running:

```python
from phishing_redflag_analyzer import analyze_url, analyze_message

flags = analyze_url("http://amaz0n.com-secure-login.info/verify")
for f in flags:
    print(f.severity, f.name, "-", f.reason)

result = analyze_message(
    "URGENT: verify your password immediately: http://bit.ly/reset",
    sender_display_name="IT Support",
    sender_email="no-reply@random-domain.net",
)
print(result["verdict"], result["action"])
```

---

## ✅ Testing

Both analyzers were validated against a mix of known-clean and known-bad inputs:
- Legitimate domains (`amazon.com`, `accounts.google.com`) correctly return **zero flags**.
- A typosquatted domain (`amaz0n.com`) is correctly flagged as a 1-character edit-distance match to `amazon.com`.
- A combosquatted domain (`paypal.com-secure-login.info`) is correctly flagged despite superficially containing the brand name.
- All four built-in sample messages classify as expected: the credential-harvesting reset and CEO fraud examples both return **Malicious**, the prize-scam message returns **Suspicious**, and the genuinely benign internal memo correctly returns **Safe** with zero false-positive flags.

The script also passes `py_compile` with no syntax errors, and the GUI was smoke-tested headlessly across all three tabs.

---

## ⚠️ Scope & Limitations

- This is a **pattern-based heuristic tool**, not a live threat-intelligence service it has no internet connection, doesn't check domain age/reputation/WHOIS data, and can't detect zero-day infrastructure it has no pattern for.
- A **"Safe" or low-flag verdict is not a guarantee** it means no *known* indicators were matched, not that a message is confirmed legitimate. Sophisticated, well-crafted spear-phishing can evade pattern matching entirely.
- The known-brand list used for typosquatting/combosquatting detection is intentionally small and illustrative; a production tool would use a continuously updated brand-protection dataset.
- This tool is a **detector only** it contains no functioning malicious links, sending capability, or evasion logic, and is intended strictly for defensive analysis and security-awareness practice.

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
