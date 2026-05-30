import email
from email import policy
import re
import urllib.parse

def parse_raw_email(raw_text):
    """
    Parses a raw email string. Handles full RFC 822 headers + body structure
    and provides a fallback for plain text inputs where headers are formatted
    manually (e.g., 'From: ...', 'Subject: ...' lines at the top).
    """
    raw_text = raw_text.strip()
    msg = email.message_from_string(raw_text, policy=policy.default)
    
    headers = {}
    body_text = ""
    body_html = ""
    attachments = []
    
    # Extract standard headers
    for key in msg.keys():
        # Standardize header names
        headers[key.lower()] = msg.get(key)
        
    # Heuristic fallback: if 'from' and 'subject' are missing from standard headers,
    # let's check if they are written in plain text at the beginning of the text
    if 'from' not in headers or not headers['from']:
        # Let's check first 10 lines for "from:", "to:", "subject:", etc.
        lines = raw_text.splitlines()[:10]
        extracted = {}
        for line in lines:
            match = re.match(r'^(from|to|subject|date|message-id|reply-to|return-path):\s*(.*)$', line, re.IGNORECASE)
            if match:
                key = match.group(1).lower()
                val = match.group(2).strip()
                extracted[key] = val
        
        if extracted:
            headers.update(extracted)
            # The body is everything after the header lines in the paste
            # Let's clean the raw text to extract body
            body_lines = []
            in_header_block = True
            for line in raw_text.splitlines():
                if in_header_block:
                    if re.match(r'^(from|to|subject|date|message-id|reply-to|return-path):\s*(.*)$', line, re.IGNORECASE):
                        continue
                    elif line.strip() == "":
                        # First blank line ends headers block
                        in_header_block = False
                        continue
                    else:
                        # Non-header line in the header block - might mean headers finished without blank line
                        in_header_block = False
                body_lines.append(line)
            body_text = "\n".join(body_lines).strip()

    # Extract body and attachments for proper RFC 822 emails
    if not body_text:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("content-disposition", ""))
                
                # Check for attachment
                if "attachment" in content_disposition or part.get_filename():
                    filename = part.get_filename() or "unnamed_attachment"
                    payload = part.get_payload(decode=True) or b""
                    size = len(payload)
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": size,
                        "disposition": content_disposition
                    })
                else:
                    # It's a body part
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode(errors="ignore")
                    elif content_type == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html += payload.decode(errors="ignore")
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True) or b""
            decoded_payload = payload.decode(errors="ignore")
            if content_type == "text/html":
                body_html = decoded_payload
            else:
                body_text = decoded_payload

    # Clean display names and addresses
    parsed_from = parse_address_field(headers.get("from", ""))
    parsed_to = parse_address_field(headers.get("to", ""))
    parsed_reply_to = parse_address_field(headers.get("reply-to", ""))
    parsed_return_path = parse_address_field(headers.get("return-path", ""))
    
    # Fallback to standard body if plain text is empty but HTML exists
    if not body_text and body_html:
        body_text = strip_html_tags(body_html)
        
    return {
        "headers": headers,
        "from_name": parsed_from["name"],
        "from_address": parsed_from["address"],
        "from_domain": parsed_from["domain"],
        "to_name": parsed_to["name"],
        "to_address": parsed_to["address"],
        "to_domain": parsed_to["domain"],
        "reply_to_address": parsed_reply_to["address"],
        "reply_to_domain": parsed_reply_to["domain"],
        "return_path_address": parsed_return_path["address"],
        "return_path_domain": parsed_return_path["domain"],
        "subject": headers.get("subject", "").strip(),
        "date": headers.get("date", "").strip(),
        "message_id": headers.get("message-id", "").strip(),
        "body_text": body_text.strip(),
        "body_html": body_html.strip(),
        "attachments": attachments
    }

def parse_address_field(field_value):
    """
    Parses fields like From/To/Reply-To to extract display name, email, and domain.
    e.g., '"PayPal Security" <security@paypal.com>' ->
    { 'name': 'PayPal Security', 'address': 'security@paypal.com', 'domain': 'paypal.com' }
    """
    if not field_value:
        return {"name": "", "address": "", "domain": ""}
        
    field_value = str(field_value).strip()
    
    # Try parsing format: "Display Name" <email@domain.com>
    match = re.search(r'^(.*?)\s*<([^>]+)>$', field_value)
    if match:
        name = match.group(1).replace('"', '').strip()
        address = match.group(2).strip()
    else:
        # Just email, e.g. email@domain.com
        name = ""
        address = field_value
        
    # Basic validation for email
    domain = ""
    if "@" in address:
        parts = address.split("@")
        domain = parts[-1].strip().lower()
        
    return {
        "name": name,
        "address": address.lower(),
        "domain": domain
    }

def strip_html_tags(html_content):
    """
    Extracts readable plain text from HTML content using regexes.
    """
    # Replace common line break tags with newlines
    text = re.sub(r'<br\s*/?>', '\n', html_content, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</div>', '\n', text, flags=re.IGNORECASE)
    
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    
    # Decode HTML entities
    text = text.replace("&nbsp;", " ")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&amp;", "&")
    text = text.replace("&quot;", '"')
    
    # Clean up whitespace
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n\s*\n+', '\n\n', text)
    return text.strip()
