"""
================================================================================
Phishing Red-Flag Analyzer (GUI Edition)
================================================================================

Author : Mustafa
Track  : Junior Analyst // Defensive Logic
Goal   : Analyze URLs and email/message text to identify phishing attempts
        turning the written red-flag analysis required by the brief into a
        working detector built on the same indicators.

Key requirements covered (per project brief):
    - Identify suspicious links or keywords     -> analyze_url() / analyze_message()
    - List red flags found in phishing messages -> Flag objects with explanations
    - Explain why the message is unsafe          -> each Flag carries a plain-English reason
Key skills demonstrated: threat analysis, awareness of cyber-attack patterns,
security decision-making (the "Pause, Verify, Report" workflow and the
Safe / Suspicious / Malicious triage tree from the training material).

Design notes:
    - Every indicator below maps directly to a red flag named in the
    DecodeLabs Project 3 deck: sender-domain mismatch, typosquatting,
    homoglyph attacks, combosquatting, the subdomain trap, urgency/
    authority/curiosity/fear cognitive triggers, requests for sensitive
    info, and dangerous attachment extensions.
    - This tool is purely a DETECTOR: it contains no functioning malicious
    links, no ability to send messages, and no evasion techniques. It only
    reads text/URLs the user provides and reports on known-bad patterns.
    - No external dependencies. Pure standard library (tkinter, re,
    ipaddress, unicodedata, urllib.parse) so it runs anywhere Python 3 + Tk
    is installed. No network calls are made analysis is 100% local and
    pattern-based, not a live threat-intel lookup.
================================================================================
"""

import ipaddress
import re
import tkinter as tk
import unicodedata
from tkinter import ttk, messagebox
from urllib.parse import urlparse


# ------------------------------------------------------------------------- #
# 1. CORE ANALYSIS LOGIC (kept UI-independent so it can be unit-tested / reused)
# ------------------------------------------------------------------------- #

class Flag:
    """A single detected red flag: what triggered it, how severe it is,
    and critically, per the brief *why* it makes the message/URL
    unsafe."""

    def __init__(self, name: str, severity: str, reason: str):
        self.name = name
        self.severity = severity  # "low" | "medium" | "high"
        self.reason = reason

    def __repr__(self):
        return f"Flag({self.name!r}, {self.severity!r})"


SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}

# A short list of well-known brand domains used only to detect *impersonation*
# of them (typosquatting / combosquatting) this is a defensive reference
# list, not a directory of real credentials or private data.
KNOWN_BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "netflix.com", "linkedin.com", "instagram.com",
    "chatgpt.com", "openai.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "tk", "top", "club", "gq", "ml", "cf", "ga", "work", "click",
    "link", "zip", "review", "country", "stream", "loan", "men",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
}

URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "act fast", "expires in",
    "24 hours", "within 30 minutes", "final notice", "account will be closed",
    "account will be suspended", "limited time", "right away",
]

AUTHORITY_PHRASES = [
    "it support", "it department", "legal action", "law enforcement",
    "executive assistant", "ceo", "irs", "hr department", "compliance team",
]

FEAR_GREED_PHRASES = [
    "unauthorized access", "suspicious activity detected", "you have won",
    "claim your prize", "your account has been compromised",
    "payment overdue", "unusual sign-in", "verify your identity",
]

SENSITIVE_INFO_PHRASES = [
    "password", "one-time code", "one time code", "otp", "mfa code",
    "verification code", "social security", "ssn", "credit card number",
    "bank account", "wire transfer", "routing number", "cvv",
]

SECRECY_PHRASES = [
    "do not discuss", "strictly confidential", "bypass standard procedure",
    "do not tell", "keep this between us",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear account holder",
]

DANGEROUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".js", ".iso", ".jar", ".bat", ".vbs", ".hta", ".lnk",
]


# --- URL analysis ---------------------------------------------------------- #

def _get_registrable_domain(hostname: str) -> str:
    """Very small heuristic to approximate the 'root domain' (last two
    labels) for comparison purposes e.g. 'login.mail.amazon.com' -> 'amazon.com'."""
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _levenshtein(a: str, b: str) -> int:
    """Standard edit-distance calculation, used to catch typosquatting
    (e.g. 'amaz0n.com' is distance 1 from 'amazon.com')."""
    if len(a) < len(b):
        a, b = b, a
    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current_row = [i]
        for j, char_b in enumerate(b, 1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def analyze_url(url: str) -> list:
    """Returns a list of Flag objects describing every red flag found in
    a single URL. An empty list means no known indicators were matched
    NOT a guarantee of safety, just an absence of the patterns checked."""
    flags = []
    url = url.strip()
    if not url:
        return flags

    # Ensure a scheme so urlparse extracts the host correctly
    parseable = url if "://" in url else f"http://{url}"
    parsed = urlparse(parseable)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        flags.append(Flag(
            "Unparseable URL", "medium",
            "The link doesn't resolve to a clear hostname, which is itself "
            "unusual for a legitimate link.",
        ))
        return flags

    # 1. Not using HTTPS
    if parsed.scheme == "http":
        flags.append(Flag(
            "No HTTPS encryption", "low",
            "The connection isn't encrypted, so any data submitted on this "
            "page (like a password) could be intercepted in transit.",
        ))

    # 2. IP address instead of a domain name
    try:
        ipaddress.ip_address(hostname)
        flags.append(Flag(
            "IP address used instead of a domain", "high",
            "Legitimate organizations almost never link directly to a raw "
            "IP address this is commonly used to dodge domain-based "
            "blocklists and to hide the true identity of the site.",
        ))
    except ValueError:
        pass

    # 3. The '@' trick browsers ignore everything before '@' in the host
    if "@" in url.split("://")[-1].split("/")[0]:
        flags.append(Flag(
            "'@' symbol in the URL authority", "high",
            "Everything before an '@' in a URL is ignored by the browser as "
            "login info attackers use this to make a malicious domain "
            "look like it starts with a trusted name (e.g. "
            "'paypal.com@evil.net' actually goes to evil.net).",
        ))

    # 4. Explicit port number specified
    if parsed.port:
        flags.append(Flag(
            "Non-standard port specified", "medium",
            "A specific port number in a link is unusual for everyday "
            "browsing and can indicate a non-standard or self-hosted "
            "malicious server.",
        ))

    # 5. Known URL shortener
    if hostname in URL_SHORTENERS:
        flags.append(Flag(
            "URL shortening service", "medium",
            "Shortened links hide the real destination until after you've "
            "already clicked, making them a common way to disguise "
            "malicious sites.",
        ))

    # 6. Suspicious / commonly abused TLD
    tld = hostname.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        flags.append(Flag(
            f"Uncommon top-level domain (.{tld})", "low",
            "This TLD is inexpensive and loosely regulated, so it's "
            "disproportionately popular with attackers not proof of "
            "malice on its own, but worth extra scrutiny.",
        ))

    # 7. Homoglyph / punycode detection (mixed scripts or IDN encoding)
    if hostname.startswith("xn--") or any(
        label.startswith("xn--") for label in hostname.split(".")
    ):
        flags.append(Flag(
            "Punycode-encoded domain (possible homoglyph attack)", "high",
            "This domain uses internationalized character encoding, which "
            "can visually mimic a trusted brand using look-alike letters "
            "from another alphabet (e.g. a Cyrillic 'a' in 'paypal.com').",
        ))
    elif any(unicodedata.category(ch).startswith("L") and ord(ch) > 127
             for ch in hostname):
        flags.append(Flag(
            "Non-ASCII characters in domain (possible homoglyph attack)",
            "high",
            "The domain contains non-standard characters that can visually "
            "impersonate a trusted brand's normal-looking domain name.",
        ))

    # 8. Subdomain trap excessive subdomains burying the real root domain
    label_count = hostname.count(".")
    if label_count >= 4:
        flags.append(Flag(
            "Excessive subdomains (possible 'subdomain trap')", "medium",
            "Long subdomain chains can bury a fake or unrelated root domain "
            "at the end of a legitimate-looking string always read a URL's "
            "root domain from right to left.",
        ))

    # 9. Typosquatting close-but-not-exact match to a known brand domain
    root_domain = _get_registrable_domain(hostname)
    if root_domain not in KNOWN_BRAND_DOMAINS:
        for brand in KNOWN_BRAND_DOMAINS:
            distance = _levenshtein(root_domain, brand)
            if 0 < distance <= 2:
                flags.append(Flag(
                    f"Possible typosquat of '{brand}'", "high",
                    f"'{root_domain}' is only {distance} character(s) "
                    f"different from the real '{brand}' a classic "
                    "typosquatting technique that relies on the reader not "
                    "looking closely.",
                ))
                break

    # 10. Combosquatting brand name + security-related word, wrong root domain
    if root_domain not in KNOWN_BRAND_DOMAINS:
        combo_keywords = ("secure", "login", "verify", "update", "account", "signin")
        for brand in KNOWN_BRAND_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name in hostname and any(k in hostname for k in combo_keywords):
                flags.append(Flag(
                    f"Possible combosquat referencing '{brand_name}'", "high",
                    f"The domain mentions '{brand_name}' alongside a "
                    "security-related word like 'secure' or 'login', but "
                    f"the actual root domain isn't '{brand}' a common "
                    "pattern for fake login pages.",
                ))
                break

    # 11. Excessively long URL (can hide structure / evade quick review)
    if len(url) > 90:
        flags.append(Flag(
            "Unusually long URL", "low",
            "Very long URLs are harder to visually audit and are sometimes "
            "used to bury suspicious parameters or a fake path that looks "
            "legitimate at a glance.",
        ))

    return flags


# --- Message / email analysis ---------------------------------------------- #

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


def _find_phrases(text_lower: str, phrase_list) -> list:
    return [phrase for phrase in phrase_list if phrase in text_lower]


def analyze_message(text: str, sender_display_name: str = "",
                     sender_email: str = "") -> dict:
    """Analyzes pasted email/message text (optionally with sender display
    name and address) and returns a dict with all detected Flags, the
    URLs found embedded in the message (each independently analyzed),
    and an overall verdict."""
    flags = []
    text_lower = text.lower()

    # Cognitive-trigger language (Authority / Urgency / Curiosity / Fear-Greed)
    urgency_hits = _find_phrases(text_lower, URGENCY_PHRASES)
    if urgency_hits:
        flags.append(Flag(
            "Urgency language", "medium",
            "Phrases like " + ", ".join(f"'{p}'" for p in urgency_hits[:3]) +
            " are designed to trigger a fight-or-flight response that "
            "short-circuits careful verification.",
        ))

    authority_hits = _find_phrases(text_lower, AUTHORITY_PHRASES)
    if authority_hits:
        flags.append(Flag(
            "Authority impersonation language", "medium",
            "References to " + ", ".join(f"'{p}'" for p in authority_hits[:3]) +
            " invoke authority to discourage the reader from questioning "
            "the request.",
        ))

    fear_hits = _find_phrases(text_lower, FEAR_GREED_PHRASES)
    if fear_hits:
        flags.append(Flag(
            "Fear or greed trigger", "medium",
            "Phrases like " + ", ".join(f"'{p}'" for p in fear_hits[:3]) +
            " are designed to provoke an emotional reaction (fear of loss "
            "or hope of reward) instead of rational evaluation.",
        ))

    secrecy_hits = _find_phrases(text_lower, SECRECY_PHRASES)
    if secrecy_hits:
        flags.append(Flag(
            "Request for secrecy / bypassing procedure", "high",
            "Legitimate requests do not ask you to hide them from "
            "colleagues or skip normal verification steps this is a "
            "strong indicator of social engineering.",
        ))

    # Requests for sensitive information
    sensitive_hits = _find_phrases(text_lower, SENSITIVE_INFO_PHRASES)
    if sensitive_hits:
        flags.append(Flag(
            "Request for sensitive information", "high",
            "The message asks for " + ", ".join(f"'{p}'" for p in sensitive_hits[:3]) +
            " legitimate organizations never ask for credentials, MFA "
            "codes, or full card numbers over email.",
        ))

    # Generic greeting (lack of personalization)
    greeting_hits = _find_phrases(text_lower, GENERIC_GREETINGS)
    if greeting_hits:
        flags.append(Flag(
            "Generic greeting", "low",
            "A greeting like " + f"'{greeting_hits[0]}'" +
            " instead of your actual name suggests a mass-sent template "
            "rather than a message truly meant for you.",
        ))

    # Dangerous attachment extensions mentioned in the text
    attachment_hits = [ext for ext in DANGEROUS_ATTACHMENT_EXTENSIONS if ext in text_lower]
    if attachment_hits:
        flags.append(Flag(
            "Dangerous attachment type mentioned", "high",
            "File extensions like " + ", ".join(attachment_hits) +
            " can execute code on your device the moment they're opened, "
            "unlike a normal document.",
        ))

    # Sender display-name vs. domain mismatch
    if sender_display_name and sender_email:
        display_lower = sender_display_name.lower()
        email_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        for brand in KNOWN_BRAND_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name in display_lower and email_domain and brand not in email_domain:
                flags.append(Flag(
                    "Sender display-name / domain mismatch", "high",
                    f"The display name references '{brand_name}', but the "
                    f"actual sending address's domain ('{email_domain}') "
                    f"doesn't match '{brand}' the display name is not "
                    "proof of who actually sent the message.",
                ))
                break

    # Embedded URLs extract and analyze each one independently
    found_urls = URL_PATTERN.findall(text)
    url_results = {}
    for url in found_urls:
        url_flags = analyze_url(url)
        if url_flags:
            url_results[url] = url_flags
            flags.append(Flag(
                f"Suspicious link found: {url[:50]}{'...' if len(url) > 50 else ''}",
                "high" if any(f.severity == "high" for f in url_flags) else "medium",
                f"This embedded link triggered {len(url_flags)} red flag(s) "
                "of its own see the URL Analyzer breakdown for details.",
            ))

    verdict, action = _classify(flags)

    return {
        "flags": flags,
        "url_results": url_results,
        "verdict": verdict,
        "action": action,
    }


def _classify(flags: list) -> tuple:
    """Maps a list of Flags onto the training material's triage tree:
    Safe -> Close, Suspicious -> Warn User, Malicious -> Block & Escalate."""
    if not flags:
        return "Safe", "Close no known red flags detected."

    score = sum(SEVERITY_WEIGHT[f.severity] for f in flags)
    has_high = any(f.severity == "high" for f in flags)

    if has_high and score >= 5:
        return "Malicious", "Block sender/domain & escalate to security team."
    if has_high or score >= 3:
        return "Suspicious", "Warn the user and verify through a separate, trusted channel."
    return "Suspicious", "Low-confidence signals present verify before acting."


# ------------------------------------------------------------------------- #
# 2. SAMPLE LIBRARY built-in illustrative examples for hands-on practice
#    (purely textual, no functioning malicious links or payloads)
# ------------------------------------------------------------------------- #

SAMPLE_MESSAGES = {
    "IT Password Reset (Urgency + Credential Harvesting)": {
        "sender_name": "IT Security",
        "sender_email": "no-reply@it-support-alerts.com",
        "body": (
            "Dear Customer,\n\n"
            "URGENT: Your password will expire in 24 hours. To avoid losing "
            "access to your account, you must verify your identity "
            "immediately by clicking the link below and entering your "
            "current password and one-time code.\n\n"
            "http://it-support-alerts.com.login-update.co/verify\n\n"
            "Failure to act within 24 hours will result in your account "
            "being suspended.\n\n"
            "IT Support Team"
        ),
    },
    "CEO Wire Transfer Request (Authority + Secrecy)": {
        "sender_name": "CEO",
        "sender_email": "ceo.urgent@executive-update.com",
        "body": (
            "Hi,\n\n"
            "I'm in a meeting and can't talk. I need you to process an "
            "urgent wire transfer today this is strictly confidential, "
            "do not discuss it with anyone else on the team, and bypass "
            "standard approval procedure given the time constraint.\n\n"
            "I'll send the bank account and routing number shortly. Please "
            "confirm you're available to action this right away.\n\n"
            "Thanks."
        ),
    },
    "Prize Notification (Fear/Greed + Shortened Link)": {
        "sender_name": "Rewards Team",
        "sender_email": "rewards@prizeclaim.xyz",
        "body": (
            "Congratulations! You have won a prize in our monthly draw. "
            "Claim your prize now before it expires click here:\n\n"
            "https://bit.ly/claim-prize-now\n\n"
            "This offer is only valid for a limited time, so act fast!"
        ),
    },
    "Legitimate-Looking Internal Memo (mostly safe, low signal)": {
        "sender_name": "Sarah Lee",
        "sender_email": "sarah.lee@company.com",
        "body": (
            "Hi Team,\n\n"
            "Please review the attached Q3 project status document at your "
            "earliest convenience. No immediate action is required happy "
            "to discuss on our regular Thursday sync.\n\n"
            "Thanks,\nSarah"
        ),
    },
}


# ------------------------------------------------------------------------- #
# 3. GUI LAYER (Tkinter) dark theme kept consistent with Projects 1 & 2
# ------------------------------------------------------------------------- #

BG = "#1e1e2e"
BG_PANEL = "#181825"
FG = "#cdd6f4"
FG_DIM = "#a6adc8"
ACCENT = "#89b4fa"
GREEN = "#a6e3a1"
YELLOW = "#f9e2af"
RED = "#f38ba8"
ENTRY_BG = "#313244"
BORDER = "#45475a"

VERDICT_COLOR = {"Safe": GREEN, "Suspicious": YELLOW, "Malicious": RED}
SEVERITY_COLOR = {"low": FG_DIM, "medium": YELLOW, "high": RED}
SEVERITY_ICON = {"low": "ℹ", "medium": "⚠", "high": "⛔"}


class PhishingAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Red-Flag Analyzer")
        self.geometry("920x780")
        self.minsize(860, 720)
        self.configure(bg=BG)

        self._build_style()
        self._build_header()
        self._build_notebook()

    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab", background=BG_PANEL, foreground=FG_DIM,
            padding=(16, 10), font=("Segoe UI", 10, "bold"),
        )
        style.map("TNotebook.Tab", background=[("selected", ENTRY_BG)],
                  foreground=[("selected", FG)])
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

    def _build_header(self):
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="x", padx=24, pady=(20, 8))
        tk.Label(frame, text="🎣 Phishing Red-Flag Analyzer", bg=BG, fg=FG,
                  font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(
            frame, text=" Project 3 · Threat Identification",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 10),
        ).pack(anchor="w")

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(4, 20))

        self.url_tab = tk.Frame(self.notebook, bg=BG)
        self.msg_tab = tk.Frame(self.notebook, bg=BG)
        self.sample_tab = tk.Frame(self.notebook, bg=BG)

        self.notebook.add(self.url_tab, text="🔗  URL Analyzer")
        self.notebook.add(self.msg_tab, text="✉️  Message Analyzer")
        self.notebook.add(self.sample_tab, text="📚  Sample Library")

        self._build_url_tab()
        self._build_message_tab()
        self._build_sample_tab()

    # ===================================================================== #
    # TAB 1 URL Analyzer
    # ===================================================================== #
    def _build_url_tab(self):
        tab = self.url_tab
        tk.Label(
            tab, text="Paste a single URL to check it against known "
                      "phishing indicators (typosquatting, homoglyphs, "
                      "IP-based links, URL shorteners, and more).",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 9), wraplength=850, justify="left",
        ).pack(anchor="w", padx=4, pady=(16, 8))

        row = tk.Frame(tab, bg=BG)
        row.pack(fill="x", padx=4, pady=(0, 12))
        self.url_entry = tk.Entry(
            row, bg=ENTRY_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 11),
        )
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        ttk.Button(row, text="🔍 Analyze URL", style="Accent.TButton",
                    command=self._on_analyze_url).pack(side="left")

        self.url_verdict_label = tk.Label(
            tab, text="", bg=BG, font=("Segoe UI", 13, "bold"),
        )
        self.url_verdict_label.pack(anchor="w", padx=4, pady=(0, 8))

        self.url_results_frame = tk.Frame(tab, bg=BG_PANEL)
        self.url_results_frame.pack(fill="both", expand=True, padx=4, pady=(0, 16))

    def _on_analyze_url(self):
        url = self.url_entry.get().strip()
        for widget in self.url_results_frame.winfo_children():
            widget.destroy()

        if not url:
            self.url_verdict_label.config(text="⚠ Enter a URL first.", fg=RED)
            return

        flags = analyze_url(url)
        verdict, action = _classify(flags)
        self.url_verdict_label.config(
            text=f"Verdict: {verdict} {action}", fg=VERDICT_COLOR[verdict],
        )
        self._render_flags(self.url_results_frame, flags)

    # ===================================================================== #
    # TAB 2 Message Analyzer
    # ===================================================================== #
    def _build_message_tab(self):
        tab = self.msg_tab

        sender_row = tk.Frame(tab, bg=BG)
        sender_row.pack(fill="x", padx=4, pady=(16, 8))

        tk.Label(sender_row, text="Sender display name (optional):", bg=BG,
                  fg=FG_DIM, font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w")
        self.sender_name_entry = tk.Entry(
            sender_row, bg=ENTRY_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 10), width=30,
        )
        self.sender_name_entry.grid(row=1, column=0, sticky="we", ipady=4, padx=(0, 12))

        tk.Label(sender_row, text="Sender email address (optional):", bg=BG,
                  fg=FG_DIM, font=("Segoe UI", 9)).grid(row=0, column=1, sticky="w")
        self.sender_email_entry = tk.Entry(
            sender_row, bg=ENTRY_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 10), width=30,
        )
        self.sender_email_entry.grid(row=1, column=1, sticky="we", ipady=4)
        sender_row.columnconfigure(0, weight=1)
        sender_row.columnconfigure(1, weight=1)

        tk.Label(tab, text="Message body:", bg=BG, fg=FG_DIM,
                  font=("Segoe UI", 9)).pack(anchor="w", padx=4, pady=(8, 2))
        self.msg_text = tk.Text(
            tab, height=8, bg=ENTRY_BG, fg=FG, insertbackground=FG, relief="flat",
            font=("Consolas", 10), wrap="word", highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT,
        )
        self.msg_text.pack(fill="both", expand=False, padx=4)

        ttk.Button(tab, text="🔍 Analyze Message", style="Accent.TButton",
                    command=self._on_analyze_message).pack(anchor="w", padx=4, pady=10)

        self.msg_verdict_label = tk.Label(tab, text="", bg=BG, font=("Segoe UI", 13, "bold"))
        self.msg_verdict_label.pack(anchor="w", padx=4, pady=(0, 8))

        # Scrollable results area
        results_container = tk.Frame(tab, bg=BG)
        results_container.pack(fill="both", expand=True, padx=4, pady=(0, 16))
        canvas = tk.Canvas(results_container, bg=BG_PANEL, highlightthickness=0)
        scrollbar = ttk.Scrollbar(results_container, orient="vertical", command=canvas.yview)
        self.msg_results_frame = tk.Frame(canvas, bg=BG_PANEL)
        self.msg_results_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.msg_results_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _on_analyze_message(self):
        text = self.msg_text.get("1.0", "end-1c")
        sender_name = self.sender_name_entry.get().strip()
        sender_email = self.sender_email_entry.get().strip()

        for widget in self.msg_results_frame.winfo_children():
            widget.destroy()

        if not text.strip():
            self.msg_verdict_label.config(text="⚠ Paste a message first.", fg=RED)
            return

        result = analyze_message(text, sender_name, sender_email)
        verdict = result["verdict"]
        self.msg_verdict_label.config(
            text=f"Verdict: {verdict} {result['action']}",
            fg=VERDICT_COLOR[verdict],
        )
        self._render_flags(self.msg_results_frame, result["flags"])

    # ===================================================================== #
    # TAB 3 Sample Library
    # ===================================================================== #
    def _build_sample_tab(self):
        tab = self.sample_tab
        tk.Label(
            tab, text="Load a built-in illustrative sample to see the "
                      "analyzer in action, or use these as practice material "
                      "before testing real messages.",
            bg=BG, fg=FG_DIM, font=("Segoe UI", 9), wraplength=850, justify="left",
        ).pack(anchor="w", padx=4, pady=(16, 8))

        for name in SAMPLE_MESSAGES:
            row = tk.Frame(tab, bg=ENTRY_BG)
            row.pack(fill="x", padx=4, pady=4)
            tk.Label(row, text=name, bg=ENTRY_BG, fg=FG, font=("Segoe UI", 10),
                      anchor="w").pack(side="left", fill="x", expand=True, padx=10, pady=10)
            ttk.Button(row, text="Load →", style="Ghost.TButton",
                        command=lambda n=name: self._load_sample(n)).pack(side="right", padx=10)

    def _load_sample(self, name: str):
        sample = SAMPLE_MESSAGES[name]
        self.sender_name_entry.delete(0, "end")
        self.sender_name_entry.insert(0, sample["sender_name"])
        self.sender_email_entry.delete(0, "end")
        self.sender_email_entry.insert(0, sample["sender_email"])
        self.msg_text.delete("1.0", "end")
        self.msg_text.insert("1.0", sample["body"])
        self.notebook.select(self.msg_tab)
        self._on_analyze_message()

    # -- shared rendering helper --------------------------------------------
    def _render_flags(self, container: tk.Frame, flags: list):
        if not flags:
            tk.Label(
                container, text="✓ No known red flags detected.", bg=BG_PANEL,
                fg=GREEN, font=("Segoe UI", 10, "bold"),
            ).pack(anchor="w", padx=14, pady=14)
            return

        for flag in flags:
            row = tk.Frame(container, bg=BG_PANEL)
            row.pack(fill="x", padx=10, pady=6)
            icon = SEVERITY_ICON[flag.severity]
            color = SEVERITY_COLOR[flag.severity]
            tk.Label(
                row, text=f"{icon} {flag.name}", bg=BG_PANEL, fg=color,
                font=("Segoe UI", 10, "bold"), anchor="w",
            ).pack(anchor="w")
            tk.Label(
                row, text=flag.reason, bg=BG_PANEL, fg=FG_DIM,
                font=("Segoe UI", 9), wraplength=820, justify="left", anchor="w",
            ).pack(anchor="w", padx=(20, 0))


if __name__ == "__main__":
    app = PhishingAnalyzerApp()
    app.mainloop()
