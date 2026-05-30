import re
import math
import urllib.parse
from .reputation import check_domain_reputation, get_domain_sld

# High-risk TLDs
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "club", "info", "work", "zip", "gq", 
    "cf", "fit", "cc", "live", "icu", "ru", "cn", "link", "click"
}

# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "pif", "vbs", "js", "docm", "xlsm", 
    "hta", "msi", "jar", "wsf", "cmd", "lnk", "cpl", "ps1"
}

# Suspicious keyword categories (to be matched as full tokens/words)
KEYWORDS_URGENCY = {
    "urgent", "immediate", "suspended", "unauthorized", "compromised", 
    "expires", "restrict", "restricted", "limit", "limited", "block", 
    "blocked", "pending", "soon", "attention", "critical", "warning", "notice"
}

KEYWORDS_FINANCIAL = {
    "wire", "invoice", "payment", "refund", "billing", "bitcoin", "crypto", 
    "overdue", "transfer", "transaction", "transactions", "receipt", "fee", 
    "fees", "bank", "card", "cards", "account", "accounts", "billing", "fund", "funds"
}

KEYWORDS_CREDENTIALS = {
    "password", "passwords", "login", "logins", "signin", "signins", 
    "verify", "verification", "credentials", "confirm", "confirmation", 
    "identity", "reset", "access", "restore", "restoration", "details", "click"
}

def calculate_shannon_entropy(text):
    """
    Calculates the Shannon entropy of a string.
    """
    if not text:
        return 0.0
    
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
        
    entropy = 0.0
    total_len = len(text)
    for count in freq.values():
        p = count / total_len
        entropy -= p * math.log2(p)
        
    return round(entropy, 2)

def extract_urls_from_text(text):
    """
    Extracts raw URLs from plain text.
    """
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    cleaned_urls = []
    for u in urls:
        u = re.sub(r'[.,;:!?\)\"\'\]]+$', '', u)
        if not u.startswith("http"):
            u = "http://" + u
        cleaned_urls.append(u)
    return list(set(cleaned_urls))

def extract_urls_from_html_and_mismatches(html_content):
    """
    Extracts URLs from HTML content, checking for mismatched text/href pairs.
    """
    a_tag_pattern = r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>'
    matches = re.findall(a_tag_pattern, html_content, re.IGNORECASE | re.DOTALL)
    
    urls = []
    mismatches = []
    
    for href, text in matches:
        href = href.strip()
        text = strip_html_tags_simple(text).strip()
        urls.append(href)
        
        text_is_url = False
        text_url = None
        
        if re.match(r'^(https?://|www\.)[^\s]+', text, re.IGNORECASE):
            text_is_url = True
            text_url = text if text.startswith("http") else "http://" + text
            
        if text_is_url:
            try:
                href_parsed = urllib.parse.urlparse(href)
                text_parsed = urllib.parse.urlparse(text_url)
                
                href_domain = href_parsed.netloc.lower().split(":")[0]
                text_domain = text_parsed.netloc.lower().split(":")[0]
                
                href_domain_clean = href_domain.replace("www.", "")
                text_domain_clean = text_domain.replace("www.", "")
                
                if href_domain_clean != text_domain_clean:
                    mismatches.append({
                        "display_text": text,
                        "actual_href": href,
                        "display_domain": text_domain,
                        "actual_domain": href_domain,
                        "type": "Mismatched Domain"
                    })
            except Exception:
                pass
                
    return list(set(urls)), mismatches

def strip_html_tags_simple(html):
    return re.sub(r'<[^>]+>', '', html)

def analyze_headers(parsed_email):
    """
    Performs header security checks.
    """
    headers = parsed_email["headers"]
    checks = []
    flags = {}
    
    # 1. SPF Check
    spf_status = "none"
    auth_results = headers.get("authentication-results", "")
    rec_spf = headers.get("received-spf", "")
    
    full_auth_string = (str(auth_results) + " " + str(rec_spf)).lower()
    if "spf=pass" in full_auth_string or "spf pass" in full_auth_string:
        spf_status = "pass"
    elif "spf=fail" in full_auth_string or "spf fail" in full_auth_string:
        spf_status = "fail"
    elif "spf=softfail" in full_auth_string or "spf softfail" in full_auth_string:
        spf_status = "softfail"
    elif "spf=none" in full_auth_string or "spf none" in full_auth_string:
        spf_status = "none"
        
    flags["spf"] = spf_status
    if spf_status == "fail":
        checks.append({"name": "SPF Fail", "severity": "High", "details": "SPF verification failed (sender domain spoofing)."})
    elif spf_status == "softfail":
        checks.append({"name": "SPF Softfail", "severity": "Medium", "details": "SPF verification returned softfail status."})
    elif spf_status == "none":
        checks.append({"name": "SPF Missing", "severity": "Medium", "details": "No SPF authentication header found."})
        
    # 2. DKIM Check
    dkim_status = "none"
    if "dkim=pass" in full_auth_string or "dkim pass" in full_auth_string:
        dkim_status = "pass"
    elif "dkim=fail" in full_auth_string or "dkim fail" in full_auth_string:
        dkim_status = "fail"
        
    flags["dkim"] = dkim_status
    if dkim_status == "fail":
        checks.append({"name": "DKIM Fail", "severity": "High", "details": "DKIM cryptographic signature verification failed."})
    elif dkim_status == "none":
        checks.append({"name": "DKIM Missing", "severity": "Medium", "details": "No DKIM signature verification found."})
        
    # 3. DMARC Check
    dmarc_status = "none"
    if "dmarc=pass" in full_auth_string or "dmarc pass" in full_auth_string:
        dmarc_status = "pass"
    elif "dmarc=fail" in full_auth_string or "dmarc fail" in full_auth_string:
        dmarc_status = "fail"
        
    flags["dmarc"] = dmarc_status
    if dmarc_status == "fail":
        checks.append({"name": "DMARC Fail", "severity": "High", "details": "DMARC domain policy validation failed."})
    elif dmarc_status == "none":
        checks.append({"name": "DMARC Missing", "severity": "Medium", "details": "No DMARC validation results found."})
        
    # 4. Domain Alignments
    from_domain = parsed_email["from_domain"]
    return_path_domain = parsed_email["return_path_domain"]
    reply_to_domain = parsed_email["reply_to_domain"]
    
    if return_path_domain and from_domain and return_path_domain != from_domain:
        checks.append({
            "name": "Return-Path Mismatch",
            "severity": "Medium",
            "details": f"Return-Path domain ({return_path_domain}) does not match From domain ({from_domain})."
        })
        flags["return_path_mismatch"] = True
    else:
        flags["return_path_mismatch"] = False
        
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        is_both_public = (reply_to_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"] and 
                          from_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"])
        if not is_both_public:
            checks.append({
                "name": "Reply-To Mismatch",
                "severity": "High",
                "details": f"Reply-to domain ({reply_to_domain}) differs from From domain ({from_domain})."
            })
            flags["reply_to_mismatch"] = True
        else:
            flags["reply_to_mismatch"] = False
    else:
        flags["reply_to_mismatch"] = False

    # 5. Display Name Spoofing
    from_name = parsed_email["from_name"].lower()
    flags["display_name_spoof"] = False
    
    brands = ["paypal", "microsoft", "google", "chase", "bank of america", "netflix", "amazon", "apple", "support", "security", "admin"]
    for brand in brands:
        if brand in from_name:
            if brand.replace(" ", "") not in from_domain.replace(".", ""):
                is_public_mail = from_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com"]
                if is_public_mail or (brand in ["paypal", "microsoft", "google", "chase", "netflix", "amazon", "apple"]):
                    checks.append({
                        "name": "Display Name Brand Spoofing",
                        "severity": "High",
                        "details": f"Sender name claims to be '{parsed_email['from_name']}', but sent from unrelated domain '{from_domain}'."
                    })
                    flags["display_name_spoof"] = True
                    break
                    
    # 6. Message-ID validation
    message_id = parsed_email["message_id"]
    flags["invalid_message_id"] = False
    if message_id:
        match = re.search(r'@([^>]+)>?$', message_id)
        if match:
            msg_id_domain = match.group(1).lower().strip()
            if msg_id_domain != from_domain and not from_domain.endswith("." + msg_id_domain):
                flags["invalid_message_id"] = True
    else:
        checks.append({"name": "Missing Message-ID", "severity": "Medium", "details": "Email is missing a Message-ID header."})
        flags["invalid_message_id"] = True
        
    return checks, flags

def analyze_urls(parsed_email):
    """
    Extracts and evaluates URLs.
    """
    text_urls = extract_urls_from_text(parsed_email["body_text"])
    html_urls, html_mismatches = extract_urls_from_html_and_mismatches(parsed_email["body_html"])
    
    all_urls = list(set(text_urls + html_urls))
    
    checks = []
    url_details = []
    flags = {
        "has_mismatched_urls": len(html_mismatches) > 0,
        "has_ip_urls": False,
        "has_high_entropy_urls": False,
        "has_lookalike_urls": False,
        "has_suspicious_tld_urls": False,
        "has_hyphenated_urls": False,
        "total_urls": len(all_urls)
    }
    
    for url in all_urls:
        url_info = {
            "url": url,
            "domain": "",
            "entropy": 0.0,
            "is_ip": False,
            "is_lookalike": False,
            "matched_brand": None,
            "has_high_risk_tld": False,
            "has_hyphen": False,
            "triggered_keywords": []
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower().split(":")[0]
            url_info["domain"] = domain
            
            # 1. IP Host Check
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                url_info["is_ip"] = True
                flags["has_ip_urls"] = True
                
            # 2. Entropy Check on SLD
            sld = get_domain_sld(domain)
            entropy = calculate_shannon_entropy(sld)
            url_info["entropy"] = entropy
            if entropy >= 4.0 and len(sld) > 8:
                url_info["has_high_entropy_entropy"] = True
                flags["has_high_entropy_urls"] = True
                
            # 3. TLD Check
            tld = domain.split(".")[-1] if "." in domain else ""
            if tld in HIGH_RISK_TLDS:
                url_info["has_high_risk_tld"] = True
                flags["has_suspicious_tld_urls"] = True
                
            # 4. Brand Reputation / Typosquatting in URL
            rep_check = check_domain_reputation(domain)
            if rep_check["is_lookalike"]:
                url_info["is_lookalike"] = True
                url_info["matched_brand"] = rep_check["matched_brand"]
                flags["has_lookalike_urls"] = True
                
            # 5. Hyphen Check
            if "-" in sld:
                url_info["has_hyphen"] = True
                flags["has_hyphenated_urls"] = True

            # 6. Phishing keywords in URL path/subdomains
            url_keywords = ["login", "verify", "signin", "billing", "update", "account", "secure", "bank", "webscr", "cmd", "paypal", "microsoft", "office365", "confirm"]
            for kw in url_keywords:
                if kw in url.lower():
                    if not (rep_check["is_whitelisted"] and kw in sld):
                        url_info["triggered_keywords"].append(kw)
                        
            url_details.append(url_info)
            
        except Exception:
            pass
            
    for mismatch in html_mismatches:
        checks.append({
            "name": "Mismatched URL Link",
            "severity": "High",
            "details": f"Link text displays '{mismatch['display_text']}' but actual link points to '{mismatch['actual_href']}'."
        })
        
    if flags["has_ip_urls"]:
        checks.append({"name": "IP Address in URL", "severity": "High", "details": "Email contains links where the host is an IP address."})
    if flags["has_lookalike_urls"]:
        checks.append({"name": "Lookalike Brand URL", "severity": "High", "details": "Email contains links designed to spoof well-known brands."})
    if flags["has_high_entropy_urls"]:
        checks.append({"name": "High Entropy Domain Link", "severity": "Medium", "details": "Email contains links to domains with random/auto-generated names."})
    if flags["has_suspicious_tld_urls"]:
        checks.append({"name": "High-Risk TLD Link", "severity": "Medium", "details": "Email contains links using high-risk Top-Level Domains (e.g. .xyz, .top)."})
    if flags["has_hyphenated_urls"]:
        checks.append({"name": "Hyphenated Domain Link", "severity": "Medium", "details": "Email contains links using domains with hyphens, often used in phishing."})
        
    return checks, flags, url_details

def analyze_content(parsed_email):
    """
    Analyzes email subject and body for text/keyword patterns using word token intersection.
    """
    subject = parsed_email["subject"].lower()
    body = parsed_email["body_text"].lower()
    
    # Tokenize text into words
    words = set(re.findall(r'\b[a-z0-9-]+\b', subject + " " + body))
    
    urgency_hits = list(words.intersection(KEYWORDS_URGENCY))
    financial_hits = list(words.intersection(KEYWORDS_FINANCIAL))
    credential_hits = list(words.intersection(KEYWORDS_CREDENTIALS))
    
    checks = []
    flags = {
        "urgency_count": len(urgency_hits),
        "financial_count": len(financial_hits),
        "credential_count": len(credential_hits),
        "is_all_caps_subject": parsed_email["subject"].isupper() and len(parsed_email["subject"]) > 5
    }
    
    if flags["is_all_caps_subject"]:
        checks.append({"name": "ALL CAPS Subject", "severity": "Medium", "details": "The email subject is written entirely in uppercase, indicating artificial urgency."})
        
    if len(urgency_hits) >= 2:
        checks.append({
            "name": "High Urgency Pressure",
            "severity": "Medium",
            "details": f"Urgency/threat language detected multiple times: {', '.join(urgency_hits[:3])}"
        })
        
    if len(financial_hits) >= 2:
        checks.append({
            "name": "Financial Solicitation Signals",
            "severity": "Medium",
            "details": f"Transaction/invoice terms detected: {', '.join(financial_hits[:3])}"
        })
        
    if len(credential_hits) >= 2:
        checks.append({
            "name": "Credential Harvesting Phrasing",
            "severity": "High",
            "details": f"Security verification or password reset triggers found: {', '.join(credential_hits[:3])}"
        })
        
    return checks, flags, {
        "urgency_hits": urgency_hits,
        "financial_hits": financial_hits,
        "credential_hits": credential_hits
    }

def analyze_attachments(parsed_email):
    """
    Evaluates risk profiles of email attachments.
    """
    attachments = parsed_email["attachments"]
    checks = []
    
    flags = {
        "has_attachments": len(attachments) > 0,
        "has_dangerous_attachments": False,
        "has_double_ext_attachments": False
    }
    
    for att in attachments:
        filename = att["filename"]
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        
        name_parts = filename.split(".")
        if len(name_parts) >= 3:
            penultimate_ext = name_parts[-2].lower()
            if penultimate_ext in ["pdf", "doc", "docx", "xls", "xlsx", "zip", "txt"]:
                flags["has_double_ext_attachments"] = True
                checks.append({
                    "name": "Double Extension Attachment",
                    "severity": "High",
                    "details": f"Attachment '{filename}' has a deceptive double extension."
                })
                
        if ext in DANGEROUS_EXTENSIONS:
            flags["has_dangerous_attachments"] = True
            checks.append({
                "name": "High-Risk Attachment Type",
                "severity": "High",
                "details": f"Attachment '{filename}' has an executable or active content script extension (.{ext})."
            })
            
    return checks, flags
