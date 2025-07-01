import os
import re
import sys

# Dangerous patterns indicating custom/insecure crypto
DANGEROUS_PATTERNS = [
    (r"def\s+encrypt", "Custom 'encrypt' function detected"),
    (r"def\s+decrypt", "Custom 'decrypt' function detected"),
    (r"def\s+hash", "Custom 'hash' function detected"),
    (r"\bMD5\b", "MD5 detected (considered insecure)"),
    (r"\bSHA1\b", "SHA1 detected (considered insecure)"),
    (r"from\s+Crypto\.Cipher", "Use of PyCrypto (deprecated/insecure)"),
    (r"import\s+Crypto", "Use of Crypto module (possibly insecure)"),
    (r"\bhashlib\.md5\b", "hashlib.md5 used (considered insecure)"),
    (r"\bhashlib\.sha1\b", "hashlib.sha1 used (considered insecure)"),
    (r"def\s+[a-zA-Z_]*crypt[a-zA-Z_]*", "Suspicious custom cryptographic function")
]

def scan_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        for pattern, message in DANGEROUS_PATTERNS:
            if re.search(pattern, content):
                print(f"[!] {message} in {filepath}")
                return True
    return False

def main():
    has_issues = False
    for root, _, files in os.walk("."):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                if scan_file(full_path):
                    has_issues = True

    if has_issues:
        print("❌ Insecure crypto usage detected. Please use standard libraries like 'cryptography' or 'hashlib.sha256'.")
        sys.exit(1)
    else:
        print("✅ No insecure crypto usage detected.")

if __name__ == "__main__":
    main()
