import os
import json
import re
import math
from .reputation import check_domain_reputation
from .features import (
    analyze_headers, analyze_urls, analyze_content, analyze_attachments,
    KEYWORDS_URGENCY, KEYWORDS_FINANCIAL, KEYWORDS_CREDENTIALS
)

STOPWORDS = {
    "the", "a", "to", "of", "and", "is", "in", "for", "on", "it", "that", 
    "this", "with", "you", "your", "our", "we", "i", "my", "me", "he", "she", 
    "they", "them", "us", "are", "was", "were", "be", "been", "have", "has", 
    "had", "do", "does", "did", "but", "if", "or", "as", "at", "by", "an"
}

class NaiveBayesClassifier:
    def __init__(self):
        # Class word frequencies: {label: {word: count}}
        self.word_counts = {"legitimate": {}, "suspicious": {}, "phishing": {}}
        # Class document counts: {label: count}
        self.class_counts = {"legitimate": 0, "suspicious": 0, "phishing": 0}
        # Vocabulary set
        self.vocab = set()
        # Prior probabilities
        self.priors = {}
        # Likelihood parameters
        self.likelihoods = {}
        
    def tokenize(self, text, subject="", injected_features=None):
        """
        Tokenizes text by splitting on non-alphanumeric chars,
        removing stopwords, and appending injected feature tokens.
        """
        combined = (subject + " " + text).lower()
        words = re.findall(r'[a-z0-9]+', combined)
        tokens = [w for w in words if w not in STOPWORDS and len(w) > 2]
        
        if injected_features:
            tokens.extend(injected_features)
            
        return tokens

    def train(self, dataset):
        """
        Trains Naive Bayes model on a list of emails.
        """
        self.word_counts = {"legitimate": {}, "suspicious": {}, "phishing": {}}
        self.class_counts = {"legitimate": 0, "suspicious": 0, "phishing": 0}
        self.vocab = set()
        
        for item in dataset:
            label = item.get("label", "legitimate")
            if label not in self.class_counts:
                continue
                
            self.class_counts[label] += 1
            
            raw_features = item.get("features", [])
            tokens = self.tokenize(item.get("body", ""), item.get("subject", ""), raw_features)
            
            for token in tokens:
                self.vocab.add(token)
                self.word_counts[label][token] = self.word_counts[label].get(token, 0) + 1
                
        total_docs = sum(self.class_counts.values())
        for label in self.class_counts:
            if total_docs > 0:
                self.priors[label] = self.class_counts[label] / total_docs
            else:
                self.priors[label] = 1.0 / len(self.class_counts)
                
    def predict_probabilities(self, text, subject="", injected_features=None):
        """
        Predicts probability distribution for the given text and features.
        """
        tokens = self.tokenize(text, subject, injected_features)
        
        log_scores = {}
        vocab_size = len(self.vocab)
        
        if vocab_size == 0:
            vocab_size = 1000
            
        for label in self.class_counts:
            prior_prob = self.priors.get(label, 1.0 / 3.0)
            if prior_prob == 0:
                prior_prob = 1e-9
            log_scores[label] = math.log(prior_prob)
            
            total_words_in_class = sum(self.word_counts[label].values())
            
            for token in tokens:
                count = self.word_counts[label].get(token, 0)
                prob = (count + 1.0) / (total_words_in_class + vocab_size)
                log_scores[label] += math.log(prob)
                
        max_log = max(log_scores.values())
        exp_scores = {}
        for label, score in log_scores.items():
            try:
                exp_scores[label] = math.exp(score - max_log)
            except OverflowError:
                exp_scores[label] = 0.0
                
        sum_exp = sum(exp_scores.values())
        if sum_exp > 0:
            probs = {label: val / sum_exp for label, val in exp_scores.items()}
        else:
            probs = {"legitimate": 0.33, "suspicious": 0.33, "phishing": 0.34}
            
        return probs


class HybridClassifier:
    def __init__(self, training_corpus_path=None):
        self.nb = NaiveBayesClassifier()
        self.corpus_path = training_corpus_path
        self.load_and_train()
        
    def load_and_train(self):
        """Loads dataset and trains the Naive Bayes model."""
        if self.corpus_path and os.path.exists(self.corpus_path):
            try:
                with open(self.corpus_path, "r", encoding="utf-8") as f:
                    dataset = json.load(f)
                self.nb.train(dataset)
            except Exception as e:
                print(f"Error training Naive Bayes model: {e}")
                self.nb.train([])
        else:
            self.nb.train([])
            
    def add_to_corpus(self, subject, body, label, features):
        """Appends a new labeled email to the corpus file and retrains."""
        if not self.corpus_path:
            return False
            
        try:
            dataset = []
            if os.path.exists(self.corpus_path):
                with open(self.corpus_path, "r", encoding="utf-8") as f:
                    dataset = json.load(f)
            
            # Avoid duplicates
            for item in dataset:
                if item.get("body", "").strip() == body.strip() and item.get("subject", "").strip() == subject.strip():
                    item["label"] = label
                    item["features"] = features
                    break
            else:
                dataset.append({
                    "label": label,
                    "subject": subject,
                    "body": body,
                    "features": features
                })
                
            os.makedirs(os.path.dirname(self.corpus_path), exist_ok=True)
            with open(self.corpus_path, "w", encoding="utf-8") as f:
                json.dump(dataset, f, indent=2)
                
            self.nb.train(dataset)
            return True
        except Exception as e:
            print(f"Failed to add to corpus: {e}")
            return False

    def get_injected_feature_tokens(self, header_flags, url_flags, content_flags, attachment_flags):
        """Maps boolean feature flags to ML-injectable token strings."""
        tokens = []
        
        # Headers
        spf = header_flags.get("spf", "none")
        tokens.append(f"__feat_spf_{spf}__")
        
        dkim = header_flags.get("dkim", "none")
        tokens.append(f"__feat_dkim_{dkim}__")
        
        dmarc = header_flags.get("dmarc", "none")
        tokens.append(f"__feat_dmarc_{dmarc}__")
        
        if header_flags.get("return_path_mismatch"):
            tokens.append("__feat_return_path_mismatch__")
        if header_flags.get("reply_to_mismatch"):
            tokens.append("__feat_reply_to_mismatch__")
        if header_flags.get("display_name_spoof"):
            tokens.append("__feat_display_name_spoof__")
        if header_flags.get("invalid_message_id"):
            tokens.append("__feat_invalid_message_id__")
            
        # URLs
        if url_flags.get("has_mismatched_urls"):
            tokens.append("__feat_mismatched_urls__")
        if url_flags.get("has_ip_urls"):
            tokens.append("__feat_ip_urls__")
        if url_flags.get("has_lookalike_urls"):
            tokens.append("__feat_lookalike_urls__")
        if url_flags.get("has_suspicious_tld_urls"):
            tokens.append("__feat_suspicious_tld_urls__")
        if url_flags.get("has_hyphenated_urls"):
            tokens.append("__feat_hyphenated_urls__")
        if url_flags.get("total_urls", 0) > 0:
            tokens.append("__feat_has_urls__")
            
        # Content
        if content_flags.get("urgency_count", 0) >= 2:
            tokens.append("__feat_urgency_high__")
        if content_flags.get("financial_count", 0) >= 2:
            tokens.append("__feat_financial_high__")
        if content_flags.get("credential_count", 0) >= 2:
            tokens.append("__feat_credential_high__")
        if content_flags.get("is_all_caps_subject"):
            tokens.append("__feat_all_caps_subject__")
            
        # Attachments
        if attachment_flags.get("has_attachments"):
            tokens.append("__feat_has_attachments__")
        if attachment_flags.get("has_dangerous_attachments"):
            tokens.append("__feat_dangerous_attachments__")
        if attachment_flags.get("has_double_ext_attachments"):
            tokens.append("__feat_double_ext_attachments__")
            
        return tokens

    def calculate_rule_based_score(self, header_flags, url_flags, content_flags, attachment_flags, url_details, content_details):
        """
        Accumulates points for security risks to compute a score out of 100.
        """
        score = 0
        
        # 1. Header rules (Max +50)
        spf = header_flags.get("spf", "none")
        if spf == "fail":
            score += 15
        elif spf == "softfail" or spf == "none":
            score += 5
            
        dkim = header_flags.get("dkim", "none")
        if dkim == "fail":
            score += 15
        elif dkim == "none":
            score += 5

        dmarc = header_flags.get("dmarc", "none")
        if dmarc == "fail":
            score += 20
        elif dmarc == "none":
            score += 5

        if header_flags.get("return_path_mismatch"):
            score += 10
        if header_flags.get("reply_to_mismatch"):
            score += 20
        if header_flags.get("display_name_spoof"):
            score += 20
        if header_flags.get("invalid_message_id"):
            score += 10
            
        # 2. URL rules (Max +60)
        if url_flags.get("has_mismatched_urls"):
            score += 20
        if url_flags.get("has_ip_urls"):
            score += 25
        if url_flags.get("has_lookalike_urls"):
            score += 25
        if url_flags.get("has_hyphenated_urls"):
            score += 5
        
        # Entropy & TLDs details
        high_entropy_count = sum(1 for u in url_details if u.get("entropy", 0.0) >= 4.0)
        score += min(20, high_entropy_count * 10)
        
        high_risk_tld_count = sum(1 for u in url_details if u.get("has_high_risk_tld", False))
        score += min(20, high_risk_tld_count * 10)
        
        # Unique keyword hits inside URLs
        unique_url_keywords = set()
        for u in url_details:
            unique_url_keywords.update(u.get("triggered_keywords", []))
        score += min(16, len(unique_url_keywords) * 8)
        
        # 3. Content rules (Max +40)
        if content_flags.get("is_all_caps_subject"):
            score += 10
        
        # Count words matched
        score += min(15, len(content_details.get("urgency_hits", [])) * 5)
        score += min(12, len(content_details.get("financial_hits", [])) * 4)
        score += min(18, len(content_details.get("credential_hits", [])) * 6)
        
        # 4. Attachment rules (Max +50)
        if attachment_flags.get("has_dangerous_attachments"):
            score += 30
        if attachment_flags.get("has_double_ext_attachments"):
            score += 35
            
        return max(0, min(100, score))

    def analyze_email(self, parsed_email):
        """
        Executes hybrid classification on parsed email.
        """
        header_checks, header_flags = analyze_headers(parsed_email)
        url_checks, url_flags, url_details = analyze_urls(parsed_email)
        content_checks, content_flags, content_details = analyze_content(parsed_email)
        attachment_checks, attachment_flags = analyze_attachments(parsed_email)
        
        all_checks = header_checks + url_checks + content_checks + attachment_checks
        
        feature_tokens = self.get_injected_feature_tokens(
            header_flags, url_flags, content_flags, attachment_flags
        )
        
        rule_score = self.calculate_rule_based_score(
            header_flags, url_flags, content_flags, attachment_flags, url_details, content_details
        )
        
        ml_probs = self.nb.predict_probabilities(
            parsed_email["body_text"], parsed_email["subject"], feature_tokens
        )
        
        ml_score = round(100 * ml_probs["phishing"] + 50 * ml_probs["suspicious"], 1)
        
        hybrid_score = round(0.6 * rule_score + 0.4 * ml_score, 1)
        
        if hybrid_score >= 70.0:
            verdict = "Phishing"
            priority = "High"
            color = "#f44336"
        elif hybrid_score >= 35.0:
            verdict = "Suspicious"
            priority = "Medium"
            color = "#ff9800"
        else:
            verdict = "Legitimate"
            priority = "Low"
            color = "#4caf50"
            
        return {
            "verdict": verdict,
            "priority": priority,
            "risk_score": hybrid_score,
            "color_hex": color,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "ml_probabilities": ml_probs,
            "triggered_checks": all_checks,
            "extracted_features": {
                "headers": header_flags,
                "urls": url_flags,
                "content": content_flags,
                "attachments": attachment_flags
            },
            "url_details": url_details,
            "content_hits": content_details,
            "injected_tokens": feature_tokens
        }
