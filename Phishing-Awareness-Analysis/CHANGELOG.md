# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-07-23

### Added
- `analyze_url()` 11-point URL red-flag scanner covering IP-based links,
  the `@` authority-hiding trick, non-standard ports, URL shorteners,
  suspicious TLDs, homoglyph/punycode detection, the subdomain trap,
  typosquatting (Levenshtein distance against known brands),
  combosquatting, missing HTTPS, and excessive URL length.
- `analyze_message()` message-level scanner covering urgency/authority/
  fear-greed/secrecy language, sensitive-information requests, generic
  greetings, dangerous attachment extensions, sender display-name/domain
  mismatch, and automatic extraction + analysis of any embedded URLs.
- `_classify()`  maps detected flags onto the Safe / Suspicious /
  Malicious → Close / Warn User / Block & Escalate decision tree.
- Built-in Sample Library with four illustrative examples (credential
  harvesting, CEO wire-transfer fraud, prize-scam smishing-style lure,
  and a genuinely safe control example) for hands-on practice.
- Full three-tab Tkinter GUI (`PhishingAnalyzerApp`):
  - URL Analyzer tab
  - Message Analyzer tab with sender name/email fields
  - Sample Library tab with one-click loading
- Comprehensive written analysis report
  (`Phishing_Awareness_Analysis_Report.md`) covering threat taxonomy,
  a full red-flag reference catalogue, detailed per-sample breakdowns,
  and validation results.
- Project documentation: `README.md` with full usage guide and code
  examples.

### Notes
- This is a pattern-based heuristic detector, not a live threat-intel
  service see README > Scope & Limitations.
