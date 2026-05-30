import re

WHITELISTED_DOMAINS = [
    "microsoft.com",
    "paypal.com",
    "google.com",
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "amazon.com",
    "apple.com",
    "netflix.com",
    "facebook.com",
    "linkedin.com",
    "github.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citibank.com",
    "fedex.com",
    "ups.com",
    "dhl.com"
]

def levenshtein_distance(s1, s2):
    s1 = s1.lower()
    s2 = s2.lower()
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def get_domain_sld(domain):
    """
    Extracts the Second-Level Domain (SLD) or main brand name.
    e.g. 'paypal' from 'paypal.com', 'microsoft' from 'login.microsoft.co.uk'
    """
    domain = domain.lower().strip()
    # Strip port if any
    domain = domain.split(":")[0]
    
    # Simple regex to get main part of domain
    # Remove common country-code TLDs or gTLDs
    parts = domain.split(".")
    if len(parts) >= 2:
        # If it ends with something like .co.uk or .com.br, check
        if len(parts) > 2 and parts[-2] in ["co", "com", "org", "net", "edu", "gov"]:
            return parts[-3]
        return parts[-2]
    return domain

def check_domain_reputation(sender_domain):
    """
    Analyzes the sender domain and returns a dict with security checks:
    - is_whitelisted: bool
    - is_lookalike: bool
    - matched_brand: str or None
    - reason: str or None
    """
    sender_domain = sender_domain.lower().strip()
    
    # 1. Direct Whitelist Match
    if sender_domain in WHITELISTED_DOMAINS:
        return {
            "is_whitelisted": True,
            "is_lookalike": False,
            "matched_brand": sender_domain,
            "reason": "Domain is in the trusted corporate whitelist."
        }
        
    sender_sld = get_domain_sld(sender_domain)
    
    # 2. Substring Brand Abuse (e.g., paypal-security.xyz or micros0ft-update.net)
    for trusted_domain in WHITELISTED_DOMAINS:
        trusted_sld = get_domain_sld(trusted_domain)
        
        # Check if the trusted brand is embedded inside the sender domain
        # e.g., "paypal" in "paypal-billing.com" but avoid subdomains like mail.google.com matching google.com
        if trusted_sld in sender_domain:
            # Check if it's a legitimate subdomain of the trusted brand (e.g. mail.paypal.com ends with .paypal.com)
            if sender_domain.endswith("." + trusted_domain):
                return {
                    "is_whitelisted": True,
                    "is_lookalike": False,
                    "matched_brand": trusted_domain,
                    "reason": f"Legitimate subdomain of trusted brand: {trusted_domain}"
                }
            else:
                return {
                    "is_whitelisted": False,
                    "is_lookalike": True,
                    "matched_brand": trusted_domain,
                    "reason": f"Sender domain contains trusted brand name '{trusted_sld}' but is not a legitimate subdomain."
                }
                
    # 3. Typosquatting / Edit Distance Check
    for trusted_domain in WHITELISTED_DOMAINS:
        trusted_sld = get_domain_sld(trusted_domain)
        
        # We only check edit distance if lengths are close (avoid comparing 'dhl' to 'bankofamerica')
        if abs(len(sender_sld) - len(trusted_sld)) <= 2:
            dist = levenshtein_distance(sender_sld, trusted_sld)
            # Edit distance of 1 or 2 is suspicious for typosquatting (e.g. paypa1 vs paypal, micros0ft vs microsoft)
            if 0 < dist <= 2:
                return {
                    "is_whitelisted": False,
                    "is_lookalike": True,
                    "matched_brand": trusted_domain,
                    "reason": f"Possible typosquatting detected. Domain '{sender_sld}' is very similar to trusted brand '{trusted_sld}' (Edit Distance: {dist})."
                }
                
    return {
        "is_whitelisted": False,
        "is_lookalike": False,
        "matched_brand": None,
        "reason": "Unknown domain with no direct similarity to popular whitelisted brands."
    }
