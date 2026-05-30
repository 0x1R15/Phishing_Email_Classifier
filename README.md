# Phishing Email Classifier & Threat Triage Tool

A lightweight, zero-dependency Python desktop application with a minimal, dark audit-style GUI designed for SOC teams, incident response analysts, and students to triage phishing threats.

## Architecture

The tool is designed with a straightforward pipelines layout:
```
Email Input (EML/Pasted Text) ➔ Ingestion & Fallback Heuristics ➔ Parsing Engine ➔ Feature Extraction ➔ Hybrid Scoring Engine ➔ SIEM Report & Logs
```

### Components

1. **Parser Engine (`analyzer/parser.py`)**: Utilizes standard library `email` package to handle RFC 822 emails, parsing MIME multipart sections, extracting body texts (HTML and plain text), header fields, and attachment details. It includes fallback regex heuristics if plain text is pasted without mail system headers.
2. **Reputation Analyzer (`analyzer/reputation.py`)**: Includes a whitelist of major corporate entities (e.g. PayPal, Microsoft, Google, Chase). Detects lookalike domains (e.g. `paypaI.com` with a capital I) using edit distance (Levenshtein) and substring brand abuse detection.
3. **Feature Extractor (`analyzer/features.py`)**:
   - **Header Integrity**: Verifies SPF/DKIM/DMARC statuses from `Authentication-Results` or `Received-SPF` headers. Checks alignment between `From`, `Return-Path`, and `Reply-To`. Checks for Display Name brand spoofing.
   - **URL Inspection**: Extracts URLs, checks for display/href domain mismatches (e.g. display text says `https://paypal.com` but link goes to `http://phish-site.com`), host-as-IP detection, high-risk TLD checks (e.g. `.xyz`, `.top`), hyphenated domain anomalies, and calculates Shannon entropy of the domain.
   - **Keyword threat density**: Measures counts of urgency, financial, and credential-harvesting triggers.
   - **Attachments Audit**: Flags double extensions (e.g. `card_logs.pdf.exe`) and high-risk extensions (e.g. `.exe`, `.scr`, `.vbs`).
4. **Hybrid Classification Engine (`analyzer/classifier.py`)**:
   - **Rule-Based Scorer (60% weight)**: Normalizes security indicators to a risk score of 0-100.
   - **ML Layer (40% weight)**: Implements a custom **Multinomial Naive Bayes Classifier** from scratch in pure Python. It uses **Feature Injection** (converting structural flags into text tokens like `__feat_spf_fail__`) to train the model on both body content and structural context.
   - **Aggregator**: Produces a final Hybrid Risk Score (0-100), mapping to:
     - `0 - 35`: **Legitimate** (Low Priority)
     - `36 - 69`: **Suspicious** (Medium Priority)
     - `70 - 100`: **Phishing** (High Priority)

---

## File Structure

```
phishing-email-classifier/
│
├── app.py                      # Main entrypoint for Tkinter GUI
├── test_analyzer.py            # Verification tests for core parser/classifier
├── README.md                   # Documentation
│
├── analyzer/
│   ├── __init__.py
│   ├── parser.py               # Email MIME parsing and address resolving
│   ├── reputation.py           # Levenshtein distance & typosquatting detection
│   ├── features.py             # Header, URL, keyword, and attachment extractor
│   └── classifier.py           # Rule-based scorer + custom Naive Bayes classifier
│
└── data/
    ├── training_corpus.json    # Labeled seed dataset for Naive Bayes training
    └── cases.json              # Local database logging triaged SOC incidents
```

---

## Running the Application

Ensure you are using Python 3.6+ (compatible with Python 3.12+). There are **no external library dependencies** to install.

### Running Core Heuristic Verification Tests

To verify that the email parser and classification rules perform as expected on standard threat profiles:
```powershell
python test_analyzer.py
```

### Running the Desktop GUI

To launch the dark audit-style threat triage dashboard:
```powershell
python app.py
```

---

## Minimal Audit-Style GUI Features

The interface uses a low-distraction, monochrome SOC layout:
- **Email Ingestion**: Allows raw email text pastes or direct `.eml` file uploads.
- **Threat Analysis**: Displays structured indicators (Header integrity logs, URL inspections with entropy details, keyword density, and attachment alerts). Shows the ML probability weights.
- **Validation Feedback**: Allows analysts to correct model verdicts and retrain the Naive Bayes model in real time (automatically saved to `training_corpus.json`).
- **SIEM Case Logger**: Generates JSON incident logs for cases. Logged cases appear in the local triage database, allowing filtering, deletions, and exports as CSV or SIEM JSON.
