import os
import sys
import json
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from analyzer.parser import parse_raw_email
from analyzer.classifier import HybridClassifier

class PhishingClassifierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Threat Triage (Audit Mode)")
        self.root.geometry("1100x750")
        self.root.minsize(1000, 650)
        
        # Paths
        self.data_dir = "data"
        self.corpus_path = os.path.join(self.data_dir, "training_corpus.json")
        self.cases_path = os.path.join(self.data_dir, "cases.json")
        
        # Initialize classifier
        self.classifier = HybridClassifier(self.corpus_path)
        
        # Current analysis state
        self.current_parsed_email = None
        self.current_analysis_result = None
        
        # Configure GUI style
        self.setup_styles()
        
        # Build UI layout
        self.build_ui()
        
        # Load historical case logs
        self.load_cases()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Define Dark SOC Palette
        self.bg_deep = "#121214"      # Dark background
        self.bg_panel = "#1e1e24"     # Card/Panel background
        self.bg_active = "#2d2d34"    # Active/Selected tab/button
        self.fg_main = "#e0e0e6"      # Main text
        self.fg_muted = "#a0a0a8"     # Muted text
        self.fg_white = "#ffffff"     # Highlight white
        self.border_color = "#2d2d34"  # Borders
        
        # Apply styles
        self.root.configure(bg=self.bg_deep)
        
        self.style.configure("TNotebook", background=self.bg_deep, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.bg_active, foreground=self.fg_muted, padding=[15, 6], font=("Segoe UI", 9, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.bg_panel)], foreground=[("selected", self.fg_white)])
        
        self.style.configure("TFrame", background=self.bg_panel)
        self.style.configure("Deep.TFrame", background=self.bg_deep)
        
        self.style.configure("TLabelframe", background=self.bg_panel, foreground=self.fg_white, bordercolor=self.border_color, borderwidth=1)
        self.style.configure("TLabelframe.Label", background=self.bg_panel, foreground=self.fg_white, font=("Segoe UI", 10, "bold"))
        
        self.style.configure("TLabel", background=self.bg_panel, foreground=self.fg_main, font=("Segoe UI", 9))
        self.style.configure("Bold.TLabel", background=self.bg_panel, foreground=self.fg_white, font=("Segoe UI", 10, "bold"))
        self.style.configure("Muted.TLabel", background=self.bg_panel, foreground=self.fg_muted, font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", background=self.bg_panel, foreground=self.fg_white, font=("Segoe UI", 12, "bold"))
        
        self.style.configure("TButton", background=self.bg_active, foreground=self.fg_main, borderwidth=1, relief="flat", font=("Segoe UI", 9))
        self.style.map("TButton", background=[("active", "#3e3e46"), ("pressed", self.bg_deep)], foreground=[("active", self.fg_white)])
        
        self.style.configure("Treeview", background=self.bg_panel, foreground=self.fg_main, fieldbackground=self.bg_panel, rowheight=24, font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", background=self.bg_active, foreground=self.fg_white, relief="flat", font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", "#3e3e46")])

    def build_ui(self):
        # Top Header Bar (Audit-style title)
        header_frame = tk.Frame(self.root, bg=self.bg_deep, height=50)
        header_frame.pack(fill="x", padx=15, pady=5)
        
        title_lbl = tk.Label(header_frame, text="PHISHING EMAIL CLASSIFIER & THREAT TRIAGE TOOL", bg=self.bg_deep, fg=self.fg_white, font=("Segoe UI", 14, "bold"))
        title_lbl.pack(side="left")
        
        mode_lbl = tk.Label(header_frame, text="AUDIT MODE // SECURE ANALYTICS", bg=self.bg_deep, fg="#ff9800", font=("Consolas", 9, "bold"))
        mode_lbl.pack(side="right", pady=5)
        
        # Tabs container
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Tab 1: Ingest
        self.tab_ingest = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_ingest, text="EMAIL INGESTION")
        self.build_tab_ingest()
        
        # Tab 2: Threat Analysis
        self.tab_analysis = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_analysis, text="THREAT ANALYSIS")
        self.build_tab_analysis()
        
        # Tab 3: Case Logs
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="CASE LOGS & SIEM")
        self.build_tab_logs()

    # ----------------------------------------------------
    # TAB 1: INGESTION UI
    # ----------------------------------------------------
    def build_tab_ingest(self):
        # Layout inside ingestion frame
        # Left side: Pasted Raw text
        # Right side: File import & guidelines
        top_bar = ttk.Frame(self.tab_ingest)
        top_bar.pack(fill="x", padx=10, pady=10)
        
        lbl_ingest = ttk.Label(top_bar, text="INPUT RAW EMAIL DATA (HEADERS + BODY)", style="Bold.TLabel")
        lbl_ingest.pack(side="left")
        
        btn_load = ttk.Button(top_bar, text="Open .eml File...", command=self.load_eml_file)
        btn_load.pack(side="right")
        
        # Main text box for ingestion
        text_frame = ttk.Frame(self.tab_ingest)
        text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        self.txt_raw_email = tk.Text(text_frame, bg=self.bg_deep, fg=self.fg_main, insertbackground=self.fg_white, selectbackground="#3e3e46", selectforeground=self.fg_white, bd=1, relief="solid", highlightcolor=self.border_color, font=("Consolas", 10))
        self.txt_raw_email.pack(side="left", fill="both", expand=True)
        
        sb_raw = ttk.Scrollbar(text_frame, orient="vertical", command=self.txt_raw_email.yview)
        sb_raw.pack(side="right", fill="y")
        self.txt_raw_email.configure(yscrollcommand=sb_raw.set)
        
        # Bottom controls
        bottom_bar = ttk.Frame(self.tab_ingest)
        bottom_bar.pack(fill="x", padx=10, pady=10)
        
        btn_analyze = ttk.Button(bottom_bar, text="RUN ANALYSIS", width=25, command=self.run_ingestion_analysis)
        btn_analyze.pack(side="left")
        
        btn_clear = ttk.Button(bottom_bar, text="Clear Ingest Text", command=self.clear_ingest)
        btn_clear.pack(side="right")
        
        # Instructions/Guidelines card
        info_frame = ttk.LabelFrame(self.tab_ingest, text="Parser Instructions")
        info_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        info_text = (
            "1. Copy the full email headers and body (RFC 822 format) and paste them into the console above.\n"
            "2. Alternatively, use the 'Open .eml File...' button to load a standard email file directly from disk.\n"
            "3. If only plain-text body is pasted, the parsing engine will attempt to extract manually declared metadata at the top of the text (e.g. 'From: ...', 'Subject: ...' lines)."
        )
        info_lbl = ttk.Label(info_frame, text=info_text, justify="left", style="Muted.TLabel")
        info_lbl.pack(padx=10, pady=8, anchor="w")

    # ----------------------------------------------------
    # TAB 2: THREAT ANALYSIS UI
    # ----------------------------------------------------
    def build_tab_analysis(self):
        # We need a 3-tier layout:
        # 1. Top Panel: Verdict, Score, Priority, and Log Action
        # 2. Middle Panel: Two columns
        #    - Left: Header Integrities & Attachments Audit
        #    - Right: Extracted URLs & Entropy Table
        # 3. Bottom Panel: Two columns
        #    - Left: Keyword Hits & Phishing Signals
        #    - Right: ML Class Probability & Verification Retraining
        
        # Top Panel
        self.verdict_frame = ttk.Frame(self.tab_analysis)
        self.verdict_frame.pack(fill="x", padx=10, pady=10)
        
        self.lbl_verdict_title = ttk.Label(self.verdict_frame, text="VERDICT:", style="Bold.TLabel")
        self.lbl_verdict_title.pack(side="left", padx=(0, 5))
        
        self.lbl_verdict = tk.Label(self.verdict_frame, text="NO ANALYSIS COMPLETED", bg=self.bg_active, fg=self.fg_muted, font=("Segoe UI", 11, "bold"), padx=10, pady=2)
        self.lbl_verdict.pack(side="left", padx=5)
        
        self.lbl_score_title = ttk.Label(self.verdict_frame, text="RISK SCORE:", style="Bold.TLabel")
        self.lbl_score_title.pack(side="left", padx=(15, 5))
        
        self.lbl_score = tk.Label(self.verdict_frame, text="N/A", bg=self.bg_panel, fg=self.fg_main, font=("Segoe UI", 12, "bold"))
        self.lbl_score.pack(side="left", padx=5)
        
        self.lbl_priority_title = ttk.Label(self.verdict_frame, text="PRIORITY:", style="Bold.TLabel")
        self.lbl_priority_title.pack(side="left", padx=(15, 5))
        
        self.lbl_priority = tk.Label(self.verdict_frame, text="N/A", bg=self.bg_panel, fg=self.fg_main, font=("Segoe UI", 12, "bold"))
        self.lbl_priority.pack(side="left", padx=5)
        
        self.btn_log_case = ttk.Button(self.verdict_frame, text="Log Case to SIEM", state="disabled", command=self.log_current_case)
        self.btn_log_case.pack(side="right", padx=5)
        
        # Middle Frame (Columns)
        mid_frame = ttk.Frame(self.tab_analysis)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Left Column (Headers & Attachments)
        left_mid_col = ttk.Frame(mid_frame, width=450)
        left_mid_col.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        # LabelFrame: Header Integrity
        self.lf_headers = ttk.LabelFrame(left_mid_col, text="Header Audit Indicators")
        self.lf_headers.pack(fill="both", expand=True, pady=(0, 5))
        
        # Text/List area for Header checks
        self.txt_headers = tk.Text(self.lf_headers, bg=self.bg_deep, fg=self.fg_main, bd=0, font=("Consolas", 9), height=8)
        self.txt_headers.pack(fill="both", expand=True, padx=5, pady=5)
        
        # LabelFrame: Attachments Audit
        self.lf_attachments = ttk.LabelFrame(left_mid_col, text="Attachments Security Audit")
        self.lf_attachments.pack(fill="x", pady=5)
        
        self.txt_attachments = tk.Text(self.lf_attachments, bg=self.bg_deep, fg=self.fg_main, bd=0, font=("Consolas", 9), height=3)
        self.txt_attachments.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Right Column (URLs Table)
        right_mid_col = ttk.LabelFrame(mid_frame, text="Extracted Links & Entropy Checks", width=550)
        right_mid_col.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        # URL Treeview
        url_scroll = ttk.Scrollbar(right_mid_col)
        url_scroll.pack(side="right", fill="y")
        
        self.tv_urls = ttk.Treeview(right_mid_col, columns=("url", "entropy", "lookalike", "tld"), show="headings", yscrollcommand=url_scroll.set)
        self.tv_urls.pack(fill="both", expand=True, padx=5, pady=5)
        url_scroll.config(command=self.tv_urls.yview)
        
        self.tv_urls.heading("url", text="Target URL Domain/Path")
        self.tv_urls.heading("entropy", text="SLD Entropy")
        self.tv_urls.heading("lookalike", text="Lookalike Spoof?")
        self.tv_urls.heading("tld", text="High-Risk TLD?")
        
        self.tv_urls.column("url", width=250, anchor="w")
        self.tv_urls.column("entropy", width=80, anchor="center")
        self.tv_urls.column("lookalike", width=90, anchor="center")
        self.tv_urls.column("tld", width=80, anchor="center")
        
        # Bottom Frame (Columns)
        bottom_frame = ttk.Frame(self.tab_analysis)
        bottom_frame.pack(fill="x", padx=10, pady=5)
        
        # Bottom Left (Keywords)
        left_bot_col = ttk.LabelFrame(bottom_frame, text="Keyword Risk Analysis")
        left_bot_col.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        self.txt_keywords = tk.Text(left_bot_col, bg=self.bg_deep, fg=self.fg_main, bd=0, font=("Consolas", 9), height=5)
        self.txt_keywords.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bottom Right (ML Breakdown & Retraining Feedback)
        right_bot_col = ttk.LabelFrame(bottom_frame, text="ML Model Prediction & Feedback Loop")
        right_bot_col.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        self.txt_ml_explanation = tk.Text(right_bot_col, bg=self.bg_deep, fg=self.fg_main, bd=0, font=("Consolas", 9), height=3)
        self.txt_ml_explanation.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Feedback Controls Frame
        fb_frame = ttk.Frame(right_bot_col)
        fb_frame.pack(fill="x", padx=5, pady=(0, 5))
        
        ttk.Label(fb_frame, text="Override Verdict:", style="Muted.TLabel").pack(side="left", padx=5)
        
        self.verdict_var = tk.StringVar(value="phishing")
        self.cb_verdict = ttk.Combobox(fb_frame, textvariable=self.verdict_var, values=["legitimate", "suspicious", "phishing"], state="readonly", width=12)
        self.cb_verdict.pack(side="left", padx=5)
        
        self.btn_feedback = ttk.Button(fb_frame, text="Submit Corrective Feedback", command=self.submit_ml_feedback, state="disabled")
        self.btn_feedback.pack(side="left", padx=10)

    # ----------------------------------------------------
    # TAB 3: CASE LOGS UI
    # ----------------------------------------------------
    def build_tab_logs(self):
        # Top panel: search & filter
        search_bar = ttk.Frame(self.tab_logs)
        search_bar.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(search_bar, text="Filter Verdict:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar(value="All")
        cb_filter = ttk.Combobox(search_bar, textvariable=self.filter_var, values=["All", "Phishing", "Suspicious", "Legitimate"], state="readonly", width=12)
        cb_filter.pack(side="left", padx=5)
        cb_filter.bind("<<ComboboxSelected>>", lambda e: self.update_logs_table())
        
        ttk.Label(search_bar, text="Search Sender/Subject:").pack(side="left", padx=(15, 5))
        self.search_var = tk.StringVar()
        self.ent_search = ttk.Entry(search_bar, textvariable=self.search_var, width=20)
        self.ent_search.pack(side="left", padx=5)
        self.ent_search.bind("<KeyRelease>", lambda e: self.update_logs_table())
        
        # Buttons to export
        btn_exp_csv = ttk.Button(search_bar, text="Export CSV Logs", command=self.export_csv)
        btn_exp_csv.pack(side="right", padx=5)
        
        btn_exp_json = ttk.Button(search_bar, text="Export Selected JSON", command=self.export_selected_json)
        btn_exp_json.pack(side="right", padx=5)
        
        # Middle panel: cases treeview table
        tbl_frame = ttk.Frame(self.tab_logs)
        tbl_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        tbl_scroll = ttk.Scrollbar(tbl_frame)
        tbl_scroll.pack(side="right", fill="y")
        
        self.tv_cases = ttk.Treeview(tbl_frame, columns=("case_id", "date", "sender", "subject", "verdict", "score"), show="headings", yscrollcommand=tbl_scroll.set)
        self.tv_cases.pack(fill="both", expand=True)
        tbl_scroll.config(command=self.tv_cases.yview)
        
        self.tv_cases.heading("case_id", text="Case ID")
        self.tv_cases.heading("date", text="Logged Date")
        self.tv_cases.heading("sender", text="Sender Email")
        self.tv_cases.heading("subject", text="Email Subject")
        self.tv_cases.heading("verdict", text="Verdict")
        self.tv_cases.heading("score", text="Score")
        
        self.tv_cases.column("case_id", width=120, anchor="center")
        self.tv_cases.column("date", width=120, anchor="center")
        self.tv_cases.column("sender", width=180, anchor="w")
        self.tv_cases.column("subject", width=250, anchor="w")
        self.tv_cases.column("verdict", width=90, anchor="center")
        self.tv_cases.column("score", width=60, anchor="center")
        
        self.tv_cases.bind("<<TreeviewSelect>>", self.on_case_selected)
        
        # Bottom panel: Detailed Case JSON viewer
        details_frame = ttk.LabelFrame(self.tab_logs, text="Selected Case Details (Structured SIEM Output)")
        details_frame.pack(fill="x", padx=10, pady=(5, 10))
        
        self.txt_case_details = tk.Text(details_frame, bg=self.bg_deep, fg=self.fg_main, insertbackground=self.fg_white, bd=1, relief="solid", font=("Consolas", 9), height=8)
        self.txt_case_details.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        det_scroll = ttk.Scrollbar(details_frame, command=self.txt_case_details.yview)
        det_scroll.pack(side="right", fill="y")
        self.txt_case_details.configure(yscrollcommand=det_scroll.set)
        
        # Table management buttons
        btn_mgmt_frame = ttk.Frame(details_frame)
        btn_mgmt_frame.pack(side="right", fill="y", padx=5, pady=5)
        
        btn_del = ttk.Button(btn_mgmt_frame, text="Delete Case", command=self.delete_selected_case)
        btn_del.pack(fill="x", pady=5)
        
        btn_clear_hist = ttk.Button(btn_mgmt_frame, text="Clear History", command=self.clear_case_history)
        btn_clear_hist.pack(fill="x", pady=5)

    # ----------------------------------------------------
    # CORE LOGIC & EVENT HANDLERS
    # ----------------------------------------------------
    def load_eml_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml"), ("Text Files", "*.txt"), ("All Files", "*.*")])
        if not file_path:
            return
            
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.txt_raw_email.delete("1.0", tk.END)
            self.txt_raw_email.insert(tk.END, content)
            messagebox.showinfo("EML Loaded", f"Successfully loaded file: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error Reading File", f"Could not parse EML file: {e}")

    def clear_ingest(self):
        self.txt_raw_email.delete("1.0", tk.END)

    def run_ingestion_analysis(self):
        raw_text = self.txt_raw_email.get("1.0", tk.END).strip()
        if not raw_text:
            messagebox.showwarning("Empty Input", "Please paste raw email text or load an EML file first.")
            return
            
        # Parse email
        try:
            self.current_parsed_email = parse_raw_email(raw_text)
        except Exception as e:
            messagebox.showerror("Parsing Failure", f"Failed to ingest raw email structure: {e}")
            return
            
        # Analyze threat
        try:
            self.current_analysis_result = self.classifier.analyze_email(self.current_parsed_email)
        except Exception as e:
            messagebox.showerror("Analysis Failure", f"Classification engine failed: {e}")
            return
            
        # Display results on Tab 2
        self.display_analysis_results()
        
        # Switch to analysis tab
        self.notebook.select(self.tab_analysis)
        
        # Enable logging and feedback controls
        self.btn_log_case.config(state="normal")
        self.btn_feedback.config(state="normal")
        
        # Preset the override verdict selector to match current prediction
        current_v = self.current_analysis_result["verdict"].lower()
        self.cb_verdict.set(current_v)

    def display_analysis_results(self):
        p = self.current_parsed_email
        r = self.current_analysis_result
        
        # Update Top Panel
        self.lbl_verdict.config(text=r["verdict"].upper(), bg=r["color_hex"], fg="#ffffff" if r["verdict"] != "Legitimate" else "#000000")
        self.lbl_score.config(text=f"{r['risk_score']} / 100", fg=r["color_hex"])
        self.lbl_priority.config(text=r["priority"].upper(), fg=r["color_hex"])
        
        # 1. Display Headers Audit (Left mid panel)
        self.txt_headers.config(state="normal")
        self.txt_headers.delete("1.0", tk.END)
        self.txt_headers.insert(tk.END, f"Sender Name   : {p['from_name']}\n")
        self.txt_headers.insert(tk.END, f"Sender Address: {p['from_address']}\n")
        self.txt_headers.insert(tk.END, f"Sender Domain : {p['from_domain']}\n")
        self.txt_headers.insert(tk.END, f"Reply-To      : {p['reply_to_address'] or 'N/A'}\n")
        self.txt_headers.insert(tk.END, f"Return-Path   : {p['return_path_address'] or 'N/A'}\n")
        self.txt_headers.insert(tk.END, f"Message-ID    : {p['message_id'] or 'N/A'}\n")
        self.txt_headers.insert(tk.END, "-" * 55 + "\n")
        
        hdr_flags = r["extracted_features"]["headers"]
        self.txt_headers.insert(tk.END, f"SPF check  : {hdr_flags.get('spf', 'none').upper()}\n")
        self.txt_headers.insert(tk.END, f"DKIM check : {hdr_flags.get('dkim', 'none').upper()}\n")
        self.txt_headers.insert(tk.END, f"DMARC check: {hdr_flags.get('dmarc', 'none').upper()}\n")
        
        triggered_hdr_rules = [chk for chk in r["triggered_checks"] if chk["name"] in ["SPF Fail", "SPF Softfail", "SPF Missing", "DKIM Fail", "DKIM Missing", "DMARC Fail", "DMARC Missing", "Return-Path Mismatch", "Reply-To Mismatch", "Display Name Brand Spoofing", "Missing Message-ID"]]
        if triggered_hdr_rules:
            self.txt_headers.insert(tk.END, "\nTriggered Header Anomalies:\n")
            for chk in triggered_hdr_rules:
                self.txt_headers.insert(tk.END, f" - [{chk['severity']}] {chk['name']}: {chk['details']}\n")
        else:
            self.txt_headers.insert(tk.END, "\nNo header anomalies detected.\n")
        self.txt_headers.config(state="disabled")
        
        # 2. Display Attachments Audit
        self.txt_attachments.config(state="normal")
        self.txt_attachments.delete("1.0", tk.END)
        if not p["attachments"]:
            self.txt_attachments.insert(tk.END, "No file attachments detected in email structure.")
        else:
            for idx, att in enumerate(p["attachments"], 1):
                size_kb = round(att["size_bytes"] / 1024, 1)
                self.txt_attachments.insert(tk.END, f"[{idx}] {att['filename']} ({size_kb} KB, MIME: {att['content_type']})\n")
            
            triggered_att_rules = [chk for chk in r["triggered_checks"] if "Attachment" in chk["name"]]
            if triggered_att_rules:
                self.txt_attachments.insert(tk.END, "Security Warnings:\n")
                for chk in triggered_att_rules:
                    self.txt_attachments.insert(tk.END, f"  * [{chk['severity']}] {chk['name']}: {chk['details']}\n")
        self.txt_attachments.config(state="disabled")
        
        # 3. Display URLs (Right mid panel)
        # Clear previous rows
        for item in self.tv_urls.get_children():
            self.tv_urls.delete(item)
            
        for u in r["url_details"]:
            # Display domain (or full url if short)
            disp_url = u["domain"] if len(u["url"]) > 50 else u["url"]
            lookalike_lbl = "YES" if u["is_lookalike"] else "No"
            tld_lbl = "YES" if u["has_high_risk_tld"] else "No"
            self.tv_urls.insert("", tk.END, values=(disp_url, u["entropy"], lookalike_lbl, tld_lbl))
            
        # 4. Display Content Keywords (Bottom left panel)
        self.txt_keywords.config(state="normal")
        self.txt_keywords.delete("1.0", tk.END)
        hits = r["content_hits"]
        self.txt_keywords.insert(tk.END, f"Urgency Indicators ({len(hits['urgency_hits'])}): {', '.join(hits['urgency_hits']) if hits['urgency_hits'] else 'None'}\n\n")
        self.txt_keywords.insert(tk.END, f"Financial Indicators ({len(hits['financial_hits'])}): {', '.join(hits['financial_hits']) if hits['financial_hits'] else 'None'}\n\n")
        self.txt_keywords.insert(tk.END, f"Credential Harvesting ({len(hits['credential_hits'])}): {', '.join(hits['credential_hits']) if hits['credential_hits'] else 'None'}\n")
        
        triggered_content_rules = [chk for chk in r["triggered_checks"] if chk["name"] in ["ALL CAPS Subject", "High Urgency Pressure", "Financial Solicitation Signals", "Credential Harvesting Phrasing"]]
        if triggered_content_rules:
            self.txt_keywords.insert(tk.END, "\nContent Signals:\n")
            for chk in triggered_content_rules:
                self.txt_keywords.insert(tk.END, f" - {chk['name']}: {chk['details']}\n")
        self.txt_keywords.config(state="disabled")
        
        # 5. Display ML Explanation (Bottom right panel)
        self.txt_ml_explanation.config(state="normal")
        self.txt_ml_explanation.delete("1.0", tk.END)
        probs = r["ml_probabilities"]
        self.txt_ml_explanation.insert(tk.END, f"Naive Bayes Probability Weights:\n")
        self.txt_ml_explanation.insert(tk.END, f" - Legitimate: {probs['legitimate']*100:.2f}% | Suspicious: {probs['suspicious']*100:.2f}% | Phishing: {probs['phishing']*100:.2f}%\n")
        self.txt_ml_explanation.insert(tk.END, f"Injected Feature Tokens:\n")
        self.txt_ml_explanation.insert(tk.END, f" {', '.join(r['injected_tokens'])}\n")
        self.txt_ml_explanation.config(state="disabled")

    def submit_ml_feedback(self):
        if not self.current_parsed_email or not self.current_analysis_result:
            return
            
        target_label = self.verdict_var.get()
        subject = self.current_parsed_email["subject"]
        body = self.current_parsed_email["body_text"]
        injected_tokens = self.current_analysis_result["injected_tokens"]
        
        success = self.classifier.add_to_corpus(subject, body, target_label, injected_tokens)
        if success:
            messagebox.showinfo("ML Model Retrained", f"Successfully recorded email as '{target_label}' in corpus. ML Model parameters updated in memory.")
            # Re-run analysis to show updated probability breakdown
            self.run_ingestion_analysis()
        else:
            messagebox.showerror("Error", "Could not write feedback to corpus file.")

    def log_current_case(self):
        if not self.current_parsed_email or not self.current_analysis_result:
            return
            
        p = self.current_parsed_email
        r = self.current_analysis_result
        
        # Generate case data
        case_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{os.urandom(2).hex().upper()}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Extract sender
        sender = p["from_address"] or "unknown@domain.com"
        subject = p["subject"] or "(No Subject)"
        
        case_details = {
            "case_id": case_id,
            "timestamp": timestamp,
            "sender": sender,
            "subject": subject,
            "verdict": r["verdict"],
            "risk_score": r["risk_score"],
            "priority": r["priority"],
            "features_detected": [chk["name"] for chk in r["triggered_checks"]],
            "extracted_metadata": {
                "spf": r["extracted_features"]["headers"].get("spf", "none"),
                "dkim": r["extracted_features"]["headers"].get("dkim", "none"),
                "dmarc": r["extracted_features"]["headers"].get("dmarc", "none"),
                "reply_to_mismatch": r["extracted_features"]["headers"].get("reply_to_mismatch", False),
                "display_name_spoof": r["extracted_features"]["headers"].get("display_name_spoof", False),
                "url_count": r["extracted_features"]["urls"].get("total_urls", 0),
                "has_ip_urls": r["extracted_features"]["urls"].get("has_ip_urls", False),
                "has_lookalike_urls": r["extracted_features"]["urls"].get("has_lookalike_urls", False),
                "has_dangerous_attachments": r["extracted_features"]["attachments"].get("has_dangerous_attachments", False)
            }
        }
        
        # Save case data to cases.json
        cases_list = []
        if os.path.exists(self.cases_path):
            try:
                with open(self.cases_path, "r", encoding="utf-8") as f:
                    cases_list = json.load(f)
            except Exception:
                pass
                
        cases_list.append(case_details)
        
        try:
            os.makedirs(os.path.dirname(self.cases_path), exist_ok=True)
            with open(self.cases_path, "w", encoding="utf-8") as f:
                json.dump(cases_list, f, indent=2)
                
            messagebox.showinfo("Case Logged", f"Threat case triaged and saved under ID: {case_id}")
            self.load_cases() # Reload table
            self.btn_log_case.config(state="disabled") # Disable to prevent double logging
        except Exception as e:
            messagebox.showerror("Error Logging Case", f"Could not write case data: {e}")

    def load_cases(self):
        """Loads cases from cases.json file."""
        self.all_cases = []
        if os.path.exists(self.cases_path):
            try:
                with open(self.cases_path, "r", encoding="utf-8") as f:
                    self.all_cases = json.load(f)
            except Exception as e:
                print(f"Error loading cases.json: {e}")
        self.update_logs_table()

    def update_logs_table(self):
        # Clear previous rows
        for item in self.tv_cases.get_children():
            self.tv_cases.delete(item)
            
        filter_verdict = self.filter_var.get()
        search_query = self.search_var.get().lower().strip()
        
        for case in self.all_cases:
            # Apply Filter
            if filter_verdict != "All" and case.get("verdict") != filter_verdict:
                continue
                
            # Apply Search
            sender = case.get("sender", "").lower()
            subject = case.get("subject", "").lower()
            if search_query and (search_query not in sender and search_query not in subject):
                continue
                
            self.tv_cases.insert(
                "", tk.END,
                values=(
                    case.get("case_id"),
                    case.get("timestamp"),
                    case.get("sender"),
                    case.get("subject"),
                    case.get("verdict"),
                    case.get("risk_score")
                )
            )

    def on_case_selected(self, event):
        selected_items = self.tv_cases.selection()
        if not selected_items:
            return
            
        item_id = selected_items[0]
        case_id = self.tv_cases.item(item_id, "values")[0]
        
        # Find case details
        matched_case = None
        for case in self.all_cases:
            if case.get("case_id") == case_id:
                matched_case = case
                break
                
        if matched_case:
            self.txt_case_details.config(state="normal")
            self.txt_case_details.delete("1.0", tk.END)
            self.txt_case_details.insert(tk.END, json.dumps(matched_case, indent=2))
            self.txt_case_details.config(state="disabled")

    def delete_selected_case(self):
        selected_items = self.tv_cases.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a case to delete.")
            return
            
        item_id = selected_items[0]
        case_id = self.tv_cases.item(item_id, "values")[0]
        
        # Confirm deletion
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete case {case_id}?")
        if not confirm:
            return
            
        # Filter list
        self.all_cases = [c for c in self.all_cases if c.get("case_id") != case_id]
        
        # Save back
        try:
            with open(self.cases_path, "w", encoding="utf-8") as f:
                json.dump(self.all_cases, f, indent=2)
            self.txt_case_details.config(state="normal")
            self.txt_case_details.delete("1.0", tk.END)
            self.txt_case_details.config(state="disabled")
            self.update_logs_table()
            messagebox.showinfo("Case Deleted", f"Successfully deleted case: {case_id}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save changes: {e}")

    def clear_case_history(self):
        if not self.all_cases:
            return
            
        confirm = messagebox.askyesno("Confirm Clear", "Are you sure you want to permanently clear the entire case history?")
        if not confirm:
            return
            
        self.all_cases = []
        try:
            with open(self.cases_path, "w", encoding="utf-8") as f:
                json.dump(self.all_cases, f, indent=2)
            self.txt_case_details.config(state="normal")
            self.txt_case_details.delete("1.0", tk.END)
            self.txt_case_details.config(state="disabled")
            self.update_logs_table()
            messagebox.showinfo("History Cleared", "Successfully cleared all triaged cases.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear case logs: {e}")

    def export_csv(self):
        if not self.all_cases:
            messagebox.showwarning("No Logs", "There are no cases to export.")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return
            
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Header row
                writer.writerow(["Case ID", "Timestamp", "Sender", "Subject", "Verdict", "Risk Score", "Priority", "Extracted Features"])
                
                for case in self.all_cases:
                    writer.writerow([
                        case.get("case_id"),
                        case.get("timestamp"),
                        case.get("sender"),
                        case.get("subject"),
                        case.get("verdict"),
                        case.get("risk_score"),
                        case.get("priority"),
                        ", ".join(case.get("features_detected", []))
                    ])
            messagebox.showinfo("CSV Exported", f"Successfully exported cases to: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {e}")

    def export_selected_json(self):
        selected_items = self.tv_cases.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a case to export as JSON.")
            return
            
        item_id = selected_items[0]
        case_id = self.tv_cases.item(item_id, "values")[0]
        
        # Find case details
        matched_case = None
        for case in self.all_cases:
            if case.get("case_id") == case_id:
                matched_case = case
                break
                
        if not matched_case:
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if not file_path:
            return
            
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(matched_case, f, indent=2)
            messagebox.showinfo("JSON Exported", f"Successfully exported case details to: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export JSON: {e}")

def main():
    root = tk.Tk()
    app = PhishingClassifierApp(root)
    
    # Ensure correct data directory existence on start
    os.makedirs(app.data_dir, exist_ok=True)
    
    # Start loop
    root.mainloop()

if __name__ == "__main__":
    main()
