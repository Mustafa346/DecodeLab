# Phishing Awareness Analysis

**Project 3**
Track: Junior Analyst // Defensive Logic Threat Identification
Prepared by: Mustafa BS Cyber Security, COMSATS University Islamabad
Batch 2026

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Objectives](#2-objectives)
3. [Methodology](#3-methodology)
4. [Threat Taxonomy What "Phishing" Actually Covers](#4-threat-taxonomy--what-phishing-actually-covers)
5. [Red Flag Reference Catalogue](#5-red-flag-reference-catalogue)
6. [Sample Message Analysis](#6-sample-message-analysis)
   - [6.1 Sample 1 IT Password Reset](#61-sample-1--it-password-reset-credential-harvesting)
   - [6.2 Sample 2 CEO Wire Transfer Request](#62-sample-2--ceo-wire-transfer-request-business-email-compromise)
   - [6.3 Sample 3 Prize Notification](#63-sample-3--prize-notification-fear-greed--smishing-style)
   - [6.4 Sample 4 Legitimate Internal Memo (Control Example)](#64-sample-4--legitimate-internal-memo-control-example)
7. [Comparative Summary Table](#7-comparative-summary-table)
8. [The Triage Decision Tree](#8-the-triage-decision-tree)
9. [Tool: Phishing Red-Flag Analyzer](#9-tool-phishing-red-flag-analyzer)
10. [Testing & Validation](#10-testing--validation)
11. [Limitations & Responsible Use](#11-limitations--responsible-use)
12. [Conclusion](#12-conclusion)
13. [References](#13-references)

---

## 1. Introduction

Phishing remains the single most common entry point for security breaches industry breach reports consistently attribute the large majority of successful intrusions to some form of phishing, and controlled red-team simulations show that a meaningful share of employees will interact with a well-crafted lure within minutes of it landing in their inbox. Unlike a firewall or an antivirus signature, the "perimeter" being tested in a phishing attack is a human being, reading a message and making a split-second trust decision.

This report documents a structured analysis of representative phishing techniques and sample messages, produced as part of the DecodeLabs Project 3 milestone. The exercise's brief is explicit: analyze sample emails or messages, identify suspicious links or keywords, list the red flags present, and explain *why* each message is unsafe. Rather than treating this as a one-off writing exercise, the red flags catalogued here were also implemented as working detection logic in an accompanying tool (see [Section 9](#9-tool-phishing-red-flag-analyzer)), so the analysis produces something reusable rather than a static document.

## 2. Objectives

- Analyze multiple sample messages representing distinct phishing techniques and identify every suspicious link, keyword, or structural anomaly present.
- Catalogue red flags into clear categories (domain deception, psychological manipulation, data harvesting, presentation anomalies) rather than treating them as an unordered list.
- For every red flag identified, explain in plain language *why* it makes the message unsafe not just that it is present.
- Apply a consistent, repeatable triage decision (Safe / Suspicious / Malicious → Close / Warn / Block & Escalate) to each sample, rather than a subjective gut call.
- Translate the same detection logic into working code, producing a reusable analyzer rather than a single-use write-up.

## 3. Methodology

Each sample message in this report was evaluated against a fixed red-flag checklist built from five categories (see [Section 5](#5-red-flag-reference-catalogue)), checked in the same order every time:

1. **Sender identity** does the display name match the actual sending domain?
2. **Link inspection** is every URL's true destination legitimate, or does it use a domain-deception technique?
3. **Language analysis** does the message rely on urgency, authority, fear, greed, or a request for secrecy to short-circuit careful review?
4. **Data requested** is the message asking for credentials, codes, or financial details it has no legitimate reason to request over this channel?
5. **Attachments** are any referenced attachments a file type capable of executing code?

This same five-step checklist was then converted directly into the `analyze_url()` and `analyze_message()` functions in the accompanying Python tool, so the manual analysis below and the tool's automated output are methodologically identical the tool is not a separate, ad-hoc heuristic, it is this checklist made executable.

## 4. Threat Taxonomy What "Phishing" Actually Covers

"Phishing" is often used as a catch-all term, but attacks vary significantly by delivery channel and targeting precision. Distinguishing between them matters because the appropriate response and detection method differs for each:

| Type | Delivery Channel | Description |
|---|---|---|
| **Mass phishing** | Email | Generic lures mimicking ubiquitous brands, sent at high volume with low personalization. Low success rate per message, but high volume compensates. |
| **Spear phishing** | Email | Contextually precise references real project names, colleagues, or internal jargon, typically gathered via open-source reconnaissance (e.g. LinkedIn). |
| **Whaling** | Email | Spear phishing specifically targeting executives, aimed at high-value outcomes like wire transfers or M&A documents. |
| **Smishing** | SMS | Malicious links delivered by text, often disguised as delivery notifications or bank alerts. |
| **Vishing** | Voice call | Live calls using caller-ID spoofing to impersonate IT support, banks, or government agencies. |
| **Quishing** | QR code | Malicious codes on posters or in PDFs that push the victim onto an unmanaged mobile device where URLs are harder to inspect. |
| **Callback phishing (TOAD)** | Email + phone | An email containing no malicious link at all only a phone number to call, moving the attack to a channel with no automated scanning. |
| **Search engine phishing** | Web | SEO poisoning that places malicious look-alike sites above legitimate ones in search results. |

The sample analysis in this report focuses primarily on email-delivered mass phishing, spear phishing, and whaling, since these map most directly to the tool's text- and URL-based detection approach.

## 5. Red Flag Reference Catalogue

Every red flag referenced throughout this report falls into one of the following five categories. This catalogue is the checklist applied consistently to every sample in Section 6, and is also the exact list of checks implemented in the accompanying tool.

### 5.1 Domain Deception

| Red Flag | Description |
|---|---|
| **Typosquatting** | Registering a common misspelling of a real domain (`amaz0n.com` instead of `amazon.com`). |
| **Homoglyph attack** | Substituting visually identical characters from another alphabet (e.g. a Cyrillic "а" in place of a Latin "a"). |
| **Combosquatting** | Appending security-related words to a real brand name (`yourbank-secure-login.com`). |
| **Subdomain trap** | Burying a malicious root domain at the end of a long, legitimate-looking subdomain chain always read a URL's root domain from **right to left**. |
| **IP-based links** | Linking directly to a raw IP address instead of a domain name, dodging domain-based blocklists. |
| **Dangling DNS takeover** | Attacker provisions a resource matching a DNS record a company forgot to delete, inheriting an already-trusted subdomain. |

### 5.2 Link Mechanics

| Red Flag | Description |
|---|---|
| **The `@` trick** | Everything before an `@` in a URL is treated as login info and ignored by the browser `paypal.com@evil.net` actually navigates to `evil.net`. |
| **URL shorteners** | Hide the true destination until after the click. |
| **Missing HTTPS** | Data submitted on the page can be intercepted in transit. |
| **Uncommon TLDs** | Cheap, loosely regulated top-level domains (`.xyz`, `.tk`, `.top`) are disproportionately popular with attackers. |

### 5.3 Psychological Triggers

| Red Flag | Description |
|---|---|
| **Authority** | Impersonating the C-suite, IT, or law enforcement to demand unquestioned compliance. |
| **Urgency** | Artificial time pressure ("account locked in 30 minutes") that triggers a fight-or-flight response and reduces rational processing. |
| **Curiosity** | Exploiting the need to fill a knowledge gap ("see what your colleague said about you"). |
| **Fear / Greed** | Threatening consequences or promising unearned rewards. |
| **Secrecy requests** | Demands to keep a request confidential or to bypass standard procedure a legitimate request never asks you to hide it from colleagues. |

### 5.4 Data Harvesting Requests

| Red Flag | Description |
|---|---|
| **Credential requests** | Passwords, usernames, or security question answers requested over email. |
| **MFA fatigue** | Repeated, unprompted authenticator push notifications designed to wear the target down until they approve one by accident. |
| **Financial detail requests** | Bank account numbers, routing numbers, or card details requested outside an established, verified process. |

### 5.5 Presentation Anomalies

| Red Flag | Description |
|---|---|
| **Sender-domain mismatch** | The visible display name shows a trusted name, but the underlying email address belongs to an unrelated domain. |
| **Generic greeting** | "Dear Customer" instead of the recipient's actual name suggests a mass-sent template. |
| **Fake forwarded chains** | `FW:` threads containing pasted headers and odd timestamps for conversations the recipient was never part of. |
| **Dangerous attachments** | Uncommon executable file extensions (`.iso`, `.js`, `.scr`, `.hta`) or HTML smuggling links disguised as standard documents. |

## 6. Sample Message Analysis

Four representative samples are analyzed below using the checklist from Section 3. Three are deliberately unsafe, illustrating different attack patterns; the fourth is a genuinely benign control example, included specifically to test for false positives a red-flag checklist is only useful if it doesn't also flag legitimate mail.

> **Note on sample content:** all sample messages below are original, illustrative constructions written for this analysis. No real individual, company, or functioning malicious infrastructure is referenced or linked.

### 6.1 Sample 1 IT Password Reset (Credential Harvesting)

**From:** IT Security `<no-reply@it-support-alerts.com>`
**Subject:** Urgent Password Expiration Notice

> Dear Customer,
>
> URGENT: Your password will expire in 24 hours. To avoid losing access to your account, you must verify your identity immediately by clicking the link below and entering your current password and one-time code.
>
> `http://it-support-alerts.com.login-update.co/verify`
>
> Failure to act within 24 hours will result in your account being suspended.
>
> IT Support Team

**Red flags identified:**

| # | Flag | Category | Why it's unsafe |
|---|---|---|---|
| 1 | Urgency language ("URGENT", "24 hours", "immediately") | Psychological | Designed to trigger fast, unverified action before the reader can think critically. |
| 2 | Authority impersonation ("IT Support Team") | Psychological | Borrows institutional trust to discourage the reader from questioning the request. |
| 3 | Fear trigger ("account will be suspended") | Psychological | Threatens a negative consequence to force compliance. |
| 4 | Generic greeting ("Dear Customer") | Presentation | Indicates a mass-sent template, not a message genuinely addressed to the recipient. |
| 5 | Direct request for password + one-time code | Data harvesting | No legitimate IT department ever needs your actual password or a live MFA code this is the single clearest indicator in the message. |
| 6 | Subdomain trap: `it-support-alerts.com.login-update.co` | Domain deception | Reading right to left, the *true* root domain is `login-update.co` `it-support-alerts.com` is just a fake subdomain prefix designed to look familiar at a glance. |
| 7 | No HTTPS on the link | Link mechanics | Any credentials submitted would be sent unencrypted. |

**Verdict: Malicious.** Multiple high-severity indicators (direct credential/MFA request, disguised root domain) combine with textbook urgency-authority-fear language. **Recommended action: Block sender/domain & escalate to security team**, not merely delete.

---

### 6.2 Sample 2 CEO Wire Transfer Request (Business Email Compromise)

**From:** CEO `<ceo.urgent@executive-update.com>`
**Subject:** Immediate Action Required

> Hi,
>
> I'm in a meeting and can't talk. I need you to process an urgent wire transfer today this is strictly confidential, do not discuss it with anyone else on the team, and bypass standard approval procedure given the time constraint.
>
> I'll send the bank account and routing number shortly. Please confirm you're available to action this right away.
>
> Thanks.

**Red flags identified:**

| # | Flag | Category | Why it's unsafe |
|---|---|---|---|
| 1 | Urgency language ("urgent", "today", "right away") | Psychological | Pressures the recipient into skipping normal verification. |
| 2 | Secrecy + procedure-bypass request | Psychological | **This is the single strongest indicator in the entire message.** No legitimate executive request needs to be hidden from colleagues or exempted from standard financial controls this instruction exists specifically to prevent anyone else from catching the fraud. |
| 3 | Financial data incoming ("bank account and routing number") | Data harvesting | Sets up a follow-on message requesting an irreversible wire transfer. |
| 4 | Unverifiable claimed unavailability ("in a meeting, can't talk") | Psychological | Pre-emptively blocks the recipient's natural instinct to call and confirm a real Business Email Compromise (BEC) pattern seen in cases where attackers have stolen over $100M using this exact technique against corporate finance teams. |
| 5 | Sender domain doesn't match a real corporate domain (`executive-update.com`) | Domain deception | A genuine CEO email would come from the company's actual, established domain, not a newly registered look-alike. |

**Verdict: Malicious.** Even without an embedded link, this is a textbook Business Email Compromise pattern. **Recommended action: Block sender/domain & escalate to security team**, and separately verify any pending transfer requests through a known, trusted phone number never one provided in the suspicious message itself.

---

### 6.3 Sample 3 Prize Notification (Fear/Greed & Smishing-Style)

**From:** Rewards Team `<rewards@prizeclaim.xyz>`
**Subject:** Congratulations Claim Your Prize

> Congratulations! You have won a prize in our monthly draw. Claim your prize now before it expires click here:
>
> `https://bit.ly/claim-prize-now`
>
> This offer is only valid for a limited time, so act fast!

**Red flags identified:**

| # | Flag | Category | Why it's unsafe |
|---|---|---|---|
| 1 | Greed trigger ("You have won", "Claim your prize") | Psychological | Exploits hope of an unearned reward to encourage an impulsive click. |
| 2 | Urgency language ("expires", "limited time", "act fast") | Psychological | Compresses the decision window, discouraging the recipient from pausing to verify. |
| 3 | Uncommon TLD (`.xyz`) | Domain deception | Cheap, loosely regulated TLD disproportionately favored by low-cost mass-phishing campaigns not proof of malice alone, but a meaningful risk signal combined with everything else here. |
| 4 | URL shortener (`bit.ly`) | Link mechanics | Hides the real destination until after the click; there is no legitimate reason a prize notification needs its destination obscured. |
| 5 | Unsolicited notification for a contest the recipient never entered | Contextual | The most fundamental red flag: you cannot win a drawing you never entered. |

**Verdict: Suspicious** (would escalate to **Malicious** the moment the shortened link is expanded and shows a credential-harvesting or malware-hosting destination this sample was deliberately left at the "before you click" stage to illustrate what a recipient sees *before* they can fully confirm intent). **Recommended action: Warn the user and verify through a separate, trusted channel** in this case, simply recognizing "I never entered this contest" is sufficient to close it without needing to click through.

---

### 6.4 Sample 4 Legitimate Internal Memo (Control Example)

**From:** Sarah Lee `<sarah.lee@company.com>`
**Subject:** Q3 Project Status Update Non-Urgent

> Hi Team,
>
> Please review the attached Q3 project status document at your earliest convenience. No immediate action is required happy to discuss on our regular Thursday sync.
>
> Thanks,
> Sarah

**Red flags identified:** **None.**

- Sender display name matches a plausible real person, and there's no reason to suspect the domain (`company.com`) no impersonation pattern present.
- No urgency, authority-pressure, fear, greed, or secrecy language the message explicitly states *no immediate action is required*, the opposite of a phishing lure.
- No request for credentials, codes, or financial information.
- No embedded links or referenced dangerous attachment types.
- Personalized greeting ("Hi Team" from a named, known sender) rather than a generic mass-mail greeting.

**Verdict: Safe.** **Recommended action: Close** no further action needed. This sample is included deliberately to confirm the checklist doesn't over-trigger on ordinary business correspondence; a red-flag system that flags everything is as useless as one that flags nothing.

## 7. Comparative Summary Table

| Sample | Domain Deception | Psychological Triggers | Data Harvesting | Presentation Anomalies | Verdict | Action |
|---|:---:|:---:|:---:|:---:|---|---|
| 1. IT Password Reset | ✓ Subdomain trap | ✓ Urgency, Authority, Fear | ✓ Password + OTP request | ✓ Generic greeting | **Malicious** | Block & Escalate |
| 2. CEO Wire Transfer | ✓ Look-alike domain | ✓ Urgency, Secrecy | ✓ Financial data incoming | | **Malicious** | Block & Escalate |
| 3. Prize Notification | ✓ Suspicious TLD | ✓ Urgency, Greed | (pre-click) | | **Suspicious** | Warn User |
| 4. Internal Memo | | | | | **Safe** | Close |

## 8. The Triage Decision Tree

Every analyzed message resolves to exactly one of three actionable outcomes this is deliberate. An analyst (human or automated) that produces a vague "this seems a bit off" conclusion hasn't actually finished the job. The decision tree used throughout this report and implemented in the tool is:

```
Incoming Message / URL
        │
        ▼
  Header & Content Checks
   (sender domain, link
    destinations, language,
    data requests, attachments)
        │
   ┌────┼────┐
   ▼    ▼    ▼
 Safe  Suspicious  Malicious
   │       │           │
   ▼       ▼           ▼
 Close  Warn User   Block Domain
                     & Escalate
```

This mirrors the broader "Pause, Verify, Report" principle for human recipients:

1. **Pause** recognize the cognitive trigger (urgency, fear, authority) and stop interacting with the message.
2. **Verify** confirm the request through a secondary, out-of-band channel (e.g. a phone call to a known number, not one provided in the message).
3. **Report** use the organization's reporting mechanism rather than simply deleting the message, so the security team can purge the threat from other inboxes too.

## 9. Tool: Phishing Red-Flag Analyzer

To ensure this analysis produces something reusable rather than a one-time document, every check described in Sections 5–8 was implemented as executable Python logic in an accompanying GUI application, `phishing_redflag_analyzer.py`.

- **URL Analyzer** runs any single URL through an 11-point check covering every item in the Domain Deception and Link Mechanics categories (Section 5.1–5.2).
- **Message Analyzer** scans pasted email/message text for every item in the Psychological Triggers, Data Harvesting, and Presentation Anomalies categories (Section 5.3–5.5), and automatically extracts and independently analyzes any URLs found inside the message.
- **Sample Library** the four samples analyzed in Section 6 are built directly into the tool, so the exact verdicts documented in this report can be reproduced with one click.
- **Verdict engine** implements the Section 8 decision tree programmatically, so every analysis ends in the same three actionable outcomes used throughout this report.

See the accompanying `README.md` for full setup instructions, usage guide, and a code example showing how the analysis functions can be imported and reused independently of the GUI.

## 10. Testing & Validation

The tool's detection logic was validated directly against the samples in this report, plus additional known-clean domains, to confirm both **true positive** and **true negative** behavior:

| Test input | Expected | Actual result |
|---|---|---|
| `amazon.com` | 0 flags | 0 flags ✓ |
| `accounts.google.com` | 0 flags | 0 flags ✓ |
| `amaz0n.com` (typosquat) | Typosquat flag | Flagged as 1-character edit-distance match to `amazon.com` ✓ |
| `paypal.com-secure-login.info` (combosquat) | Combosquat flag | Flagged correctly despite containing the brand name ✓ |
| `192.168.1.5` (raw IP link) | IP-address flag | Flagged ✓ |
| Sample 1 (IT Password Reset) | Malicious | Malicious, 7 flags ✓ |
| Sample 2 (CEO Wire Transfer) | Malicious | Malicious, 5 flags ✓ |
| Sample 3 (Prize Notification) | Suspicious | Suspicious, 5 flags ✓ |
| Sample 4 (Internal Memo) | Safe, 0 flags | Safe, 0 flags ✓ |

The zero-false-positive result on Sample 4 and both known-clean domains is as important as correctly catching the malicious samples a checklist (or tool) that cries wolf on legitimate mail trains users to ignore warnings entirely, which is its own security failure.

## 11. Limitations & Responsible Use

- **Pattern matching has a ceiling.** Both this analysis and the accompanying tool detect *known* indicator patterns. A sufficiently well-crafted spear-phishing message from a genuinely compromised legitimate account, with no domain deception and no obviously manipulative language, can evade every check listed here. Red-flag analysis reduces risk; it does not eliminate it.
- **"Safe" means "no known indicators," not "verified legitimate."** This distinction matters operationally the correct response to a 0-flag result on an unusual request is still to verify through a separate channel if anything about it feels contextually wrong.
- **The known-brand list used for typosquat/combosquat detection is deliberately small.** A production-grade tool would integrate a continuously updated brand-protection dataset rather than a fixed illustrative list.
- **No live threat intelligence is queried.** Domain age, hosting reputation, and real-time blocklists are all out of scope this tool performs structural and linguistic analysis only.
- **Responsible use:** every sample, keyword list, and detection rule in this report and the accompanying tool exists to *identify* phishing patterns, not to generate them. No functioning malicious link, sending infrastructure, or evasion technique is included anywhere in this deliverable.

## 12. Conclusion

Phishing succeeds by exploiting the gap between a technical control and a human's split-second reaction and closing that gap requires the same structured thinking a technical vulnerability assessment would use, just applied to language and presentation instead of code. The four samples analyzed in this report cover three distinct attack patterns (credential harvesting, Business Email Compromise, and a fear/greed-driven mass-phishing lure) plus a legitimate control message, and in every case the same five-category checklist domain deception, link mechanics, psychological triggers, data harvesting, and presentation anomalies was sufficient to reach a clear, actionable verdict.

Converting that checklist into working code (Section 9) was a deliberate choice: a red-flag list that lives only in a document has to be re-applied manually every time, while the same logic implemented as a reusable analyzer can be run against new messages instantly and consistently. That consistency is the actual goal of security awareness training not memorizing a list of examples, but internalizing a repeatable process that holds up against messages the analyst has never seen before.

## 13. References

- Verizon Data Breach Investigations Report (DBIR) cited statistic on the proportion of security breaches involving phishing.
- DecodeLabs Industrial Training Kit Project 3 brief and supporting slide deck, "Building the Human Firewall" (Batch 2026).
- Publicly reported Business Email Compromise case involving spoofed vendor documentation used to defraud major technology companies of over $100 million referenced here in general terms as an illustration of BEC's real-world financial impact, no case-specific operational details reproduced.
