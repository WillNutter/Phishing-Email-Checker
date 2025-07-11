# phishing_email_checker.py
# A basic phishing email URL checker with a GUI using only built-in libraries

import tkinter as tk
from tkinter import filedialog, messagebox
import re
from urllib.parse import urlparse

# Basic heuristic-based phishing URL checker
PHISHING_KEYWORDS = ["login", "verify", "update", "secure", "account", "banking"]
SUSPICIOUS_DOMAINS = [".xyz", ".top", ".club", ".info", ".ru"]

def extract_urls(text):
    # Regex to extract URLs from the email text
    url_pattern = re.compile(r"https?://[\w\.-/\?=&%]+")
    return url_pattern.findall(text)

def is_phishing_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in domain or keyword in path:
            return True
    for suspicious in SUSPICIOUS_DOMAINS:
        if domain.endswith(suspicious):
            return True
    return False

def analyze_email(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        urls = extract_urls(content)
        phishing_found = any(is_phishing_url(url) for url in urls)
        return phishing_found, urls
    except Exception as e:
        return False, [f"Error reading file: {e}"]

# GUI setup
class PhishingCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Email Checker")

        self.label = tk.Label(root, text="Choose an email file to analyze")
        self.label.pack(pady=10)

        self.check_button = tk.Button(root, text="Choose Email File", command=self.choose_file)
        self.check_button.pack(pady=5)

        self.result_text = tk.Text(root, height=15, width=60)
        self.result_text.pack(pady=10)

    def choose_file(self):
        file_path = filedialog.askopenfilename(title="Open Email File", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            phishing, urls = analyze_email(file_path)
            self.display_result(phishing, urls)

    def display_result(self, phishing, urls):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "URLs found:\n")
        for url in urls:
            self.result_text.insert(tk.END, f"- {url}\n")
        result = "\nPHISHING ATTEMPT DETECTED!" if phishing else "\nNo phishing detected."
        self.result_text.insert(tk.END, result)

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingCheckerGUI(root)
    root.mainloop()
