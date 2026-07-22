# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-07-15

### Added
- Core password evaluation engine (`calculate_strength`) with length,
  uppercase, lowercase, digit, and symbol checks.
- Weighted 0–100 scoring model with length and character-variety
  components plus a length bonus.
- Leaked/common-password detection with automatic score cap.
- Shannon-style entropy estimation and offline brute-force crack-time
  estimate.
- Cryptographically secure password generator (`generate_password`)
  using the `secrets` module, guaranteeing all character classes.
- Full Tkinter GUI (`PasswordCheckerApp`) with:
  - Live strength meter and colour-coded score label
  - Real-time requirement checklist
  - Show/Hide password toggle
  - Copy-to-clipboard button
  - Adjustable-length password generator button
  - Dark, modern visual theme
- Project documentation: `README.md` and full technical report
  (`Password_Strength_Checker_Report.docx`).

### Notes
- This release is scoped to password **validation** only. Hashing
  (Argon2id) and constant-time comparison are planned for Project 2.
