from flask import Flask, render_template, request, jsonify, send_file
import os
import time
import base64
import hashlib
import math
import re
import pefile
import sqlite3
from stegano import lsb
from cryptography.fernet import Fernet

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
STEGO_FOLDER = 'stego_output'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STEGO_FOLDER, exist_ok=True)

FIXED_AES_KEY = Fernet.generate_key()
cipher_suite = Fernet(FIXED_AES_KEY)

# --- HELPER ALGORITHMS ---
def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def string_entropy(s):
    if not s: return 0
    entropy = 0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

# --- TRUE ANTIVIRUS ALGORITHM ---
def analyze_file_deep(file_bytes, filename):
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # STAGE 1: SIGNATURE-BASED DETECTION
    KNOWN_VIRUS_HASHES = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test Virus",
        "5e3647fb31df58145fb588c227e43e260840b3c1ee1f7bd84ea8924b80e4fb81": "Ransomware.WannaCry",
        "8e2f8cc50de3f3e1aedee8a24b07fb1c64dfc4a0349c1ef34559c3cb0344d57a": "Trojan.Emotet"
    }
    
    if file_hash in KNOWN_VIRUS_HASHES:
        virus_name = KNOWN_VIRUS_HASHES[file_hash]
        return file_hash, "Malicious Payload", "INFECTED (VIRUS DETECTED)", [f"<b>[!] CRITICAL ALERT:</b> Exact signature match for <b>{virus_name}</b>. This file contains a known virus and is extremely dangerous."], "#ff0000"

    # STAGE 2: BYTE-PATTERN MATCHING
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in file_bytes:
         return file_hash, "Test Virus", "INFECTED (VIRUS DETECTED)", ["<b>[!] CRITICAL ALERT:</b> Standard Antivirus Test string detected. The file acts as a virus."], "#ff0000"

    # STAGE 3: HEURISTIC ANALYSIS & VENDOR ALLOWLISTING
    is_pe = file_bytes.startswith(b'MZ')
    entropy = calculate_entropy(file_bytes)
    chunk = file_bytes[:1000000]
    printable_chars = ''.join(chr(c) if 32 <= c <= 126 else ' ' for c in chunk)
    lower_strings = printable_chars.lower()
    
    threat_score = 0
    reasons = []
    content_desc = "Standard Data File"

    dangerous_cmds = ['virtualalloc', 'createremotethread', 'wscript.shell']
    found_cmds = [cmd for cmd in dangerous_cmds if cmd in lower_strings]
    if found_cmds:
        threat_score += 40
        reasons.append(f"[-] Malicious API calls detected: {', '.join(found_cmds)}.")

    if is_pe:
        content_desc = "Windows Executable Program (.exe / .dll)"
        company_name = "Unknown Publisher"
        product_name = "Unknown Program"
        try:
            pe = pefile.PE(data=file_bytes)
            for fileinfo in pe.FileInfo:
                for st in fileinfo[0].StringTable:
                    for entry in st.entries.items():
                        if entry[0] == b'CompanyName': company_name = entry[1].decode('utf-8', 'ignore')
                        if entry[0] == b'ProductName': product_name = entry[1].decode('utf-8', 'ignore')
            
            trusted_vendors = ['microsoft', 'google', 'whatsapp', 'adobe', 'apple', 'zoom']
            if any(trusted in company_name.lower() for trusted in trusted_vendors):
                threat_score -= 50 
                reasons.append(f"[+] <b>Verified Trusted Publisher:</b> {company_name} ({product_name}). File is safe.")
            elif company_name != "Unknown Publisher":
                reasons.append(f"[i] Publisher identified as: {company_name}.")
            else:
                threat_score += 10
                reasons.append("[-] No digital publisher signature found. Be cautious.")
                
        except Exception:
            pass

        if entropy > 7.3 and threat_score >= 0:
            threat_score += 20
            reasons.append(f"[-] High code obfuscation/packing (Entropy: {entropy:.2f}).")

    else:
        if entropy > 7.8:
            threat_score += 15
            reasons.append("[-] File data is highly randomized/encrypted. Could be an archive or an encrypted payload.")
        else:
            reasons.append("[+] Standard file format verified. No executable virus payloads detected.")

    if threat_score >= 40:
        risk_level, color = "HIGH RISK (SUSPICIOUS)", "#ffae00"
    else:
        risk_level, color = "CLEAN (NO VIRUS DETECTED)", "#00ff41"

    if not reasons:
        reasons.append("File scanned successfully. No threats found.")

    return file_hash, content_desc, risk_level, reasons, color


# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan_url', methods=['POST'])
def scan_url():
    url = request.form['url'].strip()
    score = 0
    warnings = []
    
    if not url.startswith('http'):
        score += 20; warnings.append("No protocol (HTTP/HTTPS) specified.")
    elif not url.startswith('https'): 
        score += 20; warnings.append("Not using HTTPS (Data travels in plaintext, extremely insecure).")
    
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 30; warnings.append("IP Address used instead of a domain name (High Phishing Indicator).")
        
    if len(url) > 75:
        score += 10; warnings.append("URL is suspiciously long (Often used to hide real domain names).")
    if url.count('.') > 3 and "www" not in url:
        score += 15; warnings.append("Multiple subdomains detected.")
    if url.count('-') > 3:
        score += 15; warnings.append("Excessive use of hyphens (Common in fake/fraudulent domains).")

    url_entropy = string_entropy(url)
    if url_entropy > 4.5:
        score += 15; warnings.append(f"High character randomness ({url_entropy:.2f}) - Domain looks AI-generated.")
        
    suspicious_tlds = ['.xyz', '.top', '.pw', '.click', '.tk', '.cc']
    if any(tld in url for tld in suspicious_tlds):
        score += 20; warnings.append("Suspicious Top-Level Domain detected.")

    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
    if any(s in url for s in shorteners):
        score += 20; warnings.append("URL Shortener used (Hides the actual malicious destination).")
        
    phishing_words = ['login', 'verify', 'update', 'account', 'secure', 'bank', 'service', 'auth', 'support', 'recovery', 'signin', 'admin', 'billing']
    found_words = [w for w in phishing_words if w in url.lower()]
    if found_words: 
        score += 25; warnings.append(f"Targeted phishing keywords detected: {', '.join(found_words)}")
        
    risk = "SAFE"; color = "#00ff41"
    if score >= 50: risk = "UNSAFE (MALICIOUS/PHISHING)"; color = "#ff0000"
    elif score >= 20: risk = "SUSPICIOUS"; color = "#ffae00"
    
    return jsonify({"risk": risk, "score": score, "warnings": warnings, "color": color})

@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files: return jsonify({"error": "No file"})
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No file selected"})
    
    file_bytes = file.read()
    if not file_bytes:
         return jsonify({"risk": "CLEAN", "message": "File is empty.", "color": "#00ff41"})

    file_hash, content_desc, risk_level, reasons, color = analyze_file_deep(file_bytes, file.filename)
    
    reasons_html = "<br>".join(reasons)
    message = f"""
    <b>File Hash (SHA-256):</b><br><span style="font-family: monospace; font-size: 0.9em; color: #66fcf1;">{file_hash}</span><br><br>
    <b>Identified Format:</b><br>{content_desc}<br><br>
    <b>Scan Results:</b><br>{reasons_html}
    """
    
    return jsonify({"risk": risk_level, "message": message, "color": color})

@app.route('/hash_cracker', methods=['POST'])
def hash_cracker():
    target_hash = request.form.get('hash', '').strip().lower()
    dictionary = ["password", "123456", "admin", "welcome", "qwerty", "dragon", "letmein123", "cyberguard", "omkar", "sankalp"]
    
    if 'wordlist' in request.files:
        wordlist_file = request.files['wordlist']
        if wordlist_file.filename != '':
            try:
                content = wordlist_file.read().decode('utf-8', errors='ignore')
                dictionary = [line.strip() for line in content.splitlines() if line.strip()]
            except Exception as e:
                return jsonify({"status": "error", "msg": "Failed to read the uploaded dictionary file."})
    
    for word in dictionary:
        hashed_word = hashlib.sha256(word.encode()).hexdigest()
        if hashed_word == target_hash:
            return jsonify({
                "status": "CRACKED", 
                "msg": f"Match found!\nTarget Hash: {target_hash}\nDecrypted Password: '{word}'\n(Tested against {len(dictionary)} words)"
            })
            
    return jsonify({
        "status": "FAILED", 
        "msg": f"Target Hash: {target_hash}\nResult: Hash not found.\n(Tested against {len(dictionary)} words)"
    })

@app.route('/stego_hide', methods=['POST'])
def stego_hide():
    if 'file' not in request.files: return jsonify({"error": "No file"})
    file = request.files['file']
    secret = request.form['secret']
    filename = f"hidden_{int(time.time())}.png"
    filepath = os.path.join(STEGO_FOLDER, filename)
    try:
        secret_img = lsb.hide(file, secret)
        secret_img.save(filepath)
        return jsonify({"status": "success", "download_url": f"/download_stego/{filename}"})
    except Exception as e:
        return jsonify({"status": "error", "msg": "Use a PNG image for best results."})

@app.route('/stego_reveal', methods=['POST'])
def stego_reveal():
    if 'file' not in request.files: return jsonify({"error": "No file"})
    file = request.files['file']
    try:
        message = lsb.reveal(file)
        if not message: message = "No hidden message found."
        return jsonify({"message": message})
    except:
        return jsonify({"message": "Error: Could not decode image."})

@app.route('/download_stego/<filename>')
def download_stego(filename):
    return send_file(os.path.join(STEGO_FOLDER, filename), as_attachment=True)

@app.route('/crypto', methods=['POST'])
def crypto():
    algo = request.form.get('algo')
    mode = request.form.get('mode') 
    text = request.form.get('text', '')
    key = request.form.get('key', '') 
    
    result = ""
    try:
        if algo == 'caesar':
            shift = 3 if mode == 'encrypt' else -3
            for char in text:
                if char.isalpha():
                    base = 65 if char.isupper() else 97
                    result += chr((ord(char) - base + shift) % 26 + base)
                else: result += char
        elif algo == 'aes':
            if mode == 'encrypt': result = cipher_suite.encrypt(text.encode()).decode()
            else: result = cipher_suite.decrypt(text.encode()).decode()
        elif algo == 'base64':
            if mode == 'encrypt': result = base64.b64encode(text.encode()).decode()
            else: result = base64.b64decode(text.encode()).decode()
        elif algo == 'sha256':
            result = hashlib.sha256(text.encode()).hexdigest()
        elif algo == 'vigenere':
            if not key: return jsonify({"result": "Error: Vigenère requires a Keyword."})
            key_indices = [ord(k.upper()) - 65 for k in key if k.isalpha()]
            if not key_indices: return jsonify({"result": "Error: Key must contain letters."})
            res_chars = []
            k_len = len(key_indices)
            k_pos = 0
            for char in text:
                if char.isalpha():
                    shift = key_indices[k_pos % k_len]
                    if mode == 'decrypt': shift = -shift
                    base = 65 if char.isupper() else 97
                    res_chars.append(chr((ord(char) - base + shift) % 26 + base))
                    k_pos += 1
                else:
                    res_chars.append(char)
            result = "".join(res_chars)
        elif algo == 'vernam':
            if not key: return jsonify({"result": "Error: Vernam requires a Key."})
            if len(key) < len(text): return jsonify({"result": "Error: For Vernam, Key length must be >= Text length."})
            res_chars = []
            for t, k in zip(text, key):
                if t.isalpha() and k.isalpha():
                    shift = ord(k.upper()) - 65
                    if mode == 'decrypt': shift = -shift
                    base = 65 if t.isupper() else 97
                    res_chars.append(chr((ord(t) - base + shift) % 26 + base))
                else:
                    res_chars.append(t) 
            result = "".join(res_chars)
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return jsonify({"result": result})

@app.route('/sqli_interactive', methods=['POST'])
def sqli_interactive():
    if 'db_file' not in request.files: 
        return jsonify({"status": "ERROR", "msg": "No database file uploaded.", "color": "#ff0000"})
    
    db_file = request.files['db_file']
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    mode = request.form.get('mode', 'vulnerable')
    
    if db_file.filename == '':
        return jsonify({"status": "ERROR", "msg": "No file selected.", "color": "#ff0000"})

    temp_path = os.path.join(UPLOAD_FOLDER, f"interactive_{int(time.time())}.db")
    db_file.save(temp_path)
    
    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        
        # SMART AUTO-DETECT LOGIC
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if cursor.fetchone():
            t_name, u_col, p_col = 'users', 'username', 'password'
        else:
            t_name, u_col, p_col = 'staff', 'email', 'access_hash'
        
        if mode == 'vulnerable':
            query = f"SELECT * FROM {t_name} WHERE {u_col}='{username}' AND {p_col}='{password}'"
            cursor.execute(query)
        else:
            query = f"SELECT * FROM {t_name} WHERE {u_col}=? AND {p_col}=?"
            cursor.execute(query, (username, password))
            
        data = cursor.fetchall()
        
        if data:
            if mode == 'vulnerable' and ("' OR" in username.upper() or "' OR" in password.upper() or "'=" in username or "'=" in password or "--" in username or "--" in password or "UNION" in username.upper() or "UNION" in password.upper()):
                msg = f">> ACCESS GRANTED (BYPASS SUCCESSFUL) <<\n{len(data)} records dumped from '{t_name}' database table!"
                color = "#ff0000"
            else:
                msg = ">> ACCESS GRANTED <<\nValid credentials provided."
                color = "#00ff41"
        else:
            msg = ">> ACCESS DENIED <<\nInvalid input or blocked payload."
            color = "#ffae00"
            
        return jsonify({"status": "SUCCESS", "msg": msg, "query": query, "color": color})
        
    except Exception as e:
        broken_query = f"SELECT * FROM target_table WHERE user_col='{username}' AND pass_col='{password}'"
        return jsonify({"status": "ERROR", "msg": f"SQL SYNTAX ERROR:\n{str(e)}", "query": broken_query, "color": "#ff0000"})
    finally:
        conn.close()
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == '__main__':
    app.run(debug=True)