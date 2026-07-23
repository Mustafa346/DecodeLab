# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-07-22

### Added
- Core cipher engine: `caesar_encrypt` / `caesar_decrypt`,
  `vigenere_encrypt` / `vigenere_decrypt`, and self-inverse `atbash`,
  all built on shared `ord()`/`chr()` + modular-arithmetic primitives.
- User-selectable Caesar shift (0–25) and Vigenère keyword — no
  hardcoded keys.
- Edge-case handling: case preservation and pass-through of
  non-alphabetic characters (spaces, digits, punctuation).
- `letter_frequency()` analysis function and a live Frequency
  Analysis chart comparing input text against typical English letter
  frequencies.
- `brute_force_caesar()` — tries all 26 shifts and ranks candidates by
  an English-likeness score, surfaced in a dedicated Brute Force tab.
- Full three-tab Tkinter GUI (`CipherApp`):
  - Encrypt/Decrypt tab with swap, copy, and clear controls
  - Frequency Analysis tab with a canvas-drawn bar chart
  - Brute Force tab with a sortable results table
- Project documentation: `README.md` with algorithm explanations and
  usage guide.

### Notes
- Ciphers implemented here are classical/educational and not suitable
  for real-world data protection — see README > Scope & Limitations.
