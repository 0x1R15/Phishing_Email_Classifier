import os
import json
from analyzer.parser import parse_raw_email
from analyzer.classifier import HybridClassifier

# Define sample emails representing three tiers
LEGITIMATE_EMAIL = """From: "GitHub Security" <noreply@github.com>
To: analyst@soc.company.com
Subject: [GitHub] Security Alert: Vulnerability found in npm package dependency
Date: Sat, 30 May 2026 10:00:00 +0000
Message-ID: <alert-1234567@github.com>
Authentication-Results: mx.google.com; spf=pass (google.com: domain of noreply@github.com designates 192.0.2.10 as permitted sender); dkim=pass; dmarc=pass

Hi,
A vulnerability was found in the package 'lodash' which your project relies on.
Please check the repository settings to merge the automated security pull request.
For more details, visit https://github.com/myorg/myproject/security/alerts.

Best regards,
The GitHub Security Team
"""

SUSPICIOUS_EMAIL = """From: "Help Desk" <support@free-mail-sender.org>
To: analyst@soc.company.com
Subject: Notice: Check your account dashboard status
Date: Sat, 30 May 2026 10:15:00 +0000
Message-ID: <dashboard-msg@free-mail-sender.org>
Authentication-Results: mx.google.com; spf=none; dkim=none

Hello user,
We notice that there is some activity pending in your dashboard.
Please click the link to confirm your login details.
The dashboard can be found at http://dashboard-service.net/login.
Please act soon.
"""

PHISHING_EMAIL = """From: "PayPal Security" <security@paypaI-security-update.xyz>
To: analyst@soc.company.com
Subject: URGENT: Your PayPal Account is Restricted - Action Required!
Date: Sat, 30 May 2026 10:30:00 +0000
Message-ID: <restrict-998877@paypaI-security-update.xyz>
Authentication-Results: mx.google.com; spf=fail (google.com: domain of security@paypaI-security-update.xyz does not designate 203.0.113.50 as permitted sender); dkim=fail; dmarc=fail

Dear Customer,
We detected suspicious card login attempts from an unknown location.
For your safety, we have locked your account. To restore your access immediately,
you must verify your identity by logging into our secure web panel within 24 hours.
Failure to do so will result in permanent suspension of your account and billing.

Click here to verify: http://paypal-security-login.xyz/auth/login.html

Attached is a summary of the card logs: card_logs.pdf.exe
"""

def run_tests():
    print("=" * 60)
    print("RUNNING PHISHING EMAIL CLASSIFIER ENGINE TESTS")
    print("=" * 60)
    
    # Path to local corpus
    corpus_path = os.path.join("data", "training_corpus.json")
    print(f"Loading classifier with training corpus: {corpus_path}")
    classifier = HybridClassifier(corpus_path)
    
    # Test 1: Legitimate Email
    print("\n--- TEST 1: Legitimate Email ---")
    parsed_legit = parse_raw_email(LEGITIMATE_EMAIL)
    res_legit = classifier.analyze_email(parsed_legit)
    print(f"Verdict: {res_legit['verdict']}")
    print(f"Risk Score: {res_legit['risk_score']} / 100")
    print(f"Priority: {res_legit['priority']}")
    print(f"Rule Score: {res_legit['rule_score']}, ML Score: {res_legit['ml_score']}")
    print(f"ML Probs: {res_legit['ml_probabilities']}")
    print(f"Triggered Checks: {[c['name'] for c in res_legit['triggered_checks']]}")
    
    assert res_legit['verdict'] == "Legitimate", "Test 1 failed: Should be classified as Legitimate"
    assert res_legit['risk_score'] < 35, "Test 1 failed: Score should be < 35"
    
    # Test 2: Suspicious Email
    print("\n--- TEST 2: Suspicious Email ---")
    parsed_susp = parse_raw_email(SUSPICIOUS_EMAIL)
    res_susp = classifier.analyze_email(parsed_susp)
    print(f"Verdict: {res_susp['verdict']}")
    print(f"Risk Score: {res_susp['risk_score']} / 100")
    print(f"Priority: {res_susp['priority']}")
    print(f"Rule Score: {res_susp['rule_score']}, ML Score: {res_susp['ml_score']}")
    print(f"Triggered Checks: {[c['name'] for c in res_susp['triggered_checks']]}")
    
    assert res_susp['verdict'] == "Suspicious", "Test 2 failed: Should be classified as Suspicious"
    assert 35 <= res_susp['risk_score'] < 70, "Test 2 failed: Score should be between 35 and 70"

    # Test 3: Phishing Email
    print("\n--- TEST 3: Phishing Email ---")
    parsed_phish = parse_raw_email(PHISHING_EMAIL)
    res_phish = classifier.analyze_email(parsed_phish)
    print(f"Verdict: {res_phish['verdict']}")
    print(f"Risk Score: {res_phish['risk_score']} / 100")
    print(f"Priority: {res_phish['priority']}")
    print(f"Rule Score: {res_phish['rule_score']}, ML Score: {res_phish['ml_score']}")
    print(f"Triggered Checks: {[c['name'] for c in res_phish['triggered_checks']]}")
    print(f"Extracted URLs: {[u['url'] for u in res_phish['url_details']]}")
    print(f"URL Lookalike check: {[u.get('is_lookalike') for u in res_phish['url_details']]}")
    
    assert res_phish['verdict'] == "Phishing", "Test 3 failed: Should be classified as Phishing"
    assert res_phish['risk_score'] >= 70, "Test 3 failed: Score should be >= 70"
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
