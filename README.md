# Cyber Guard | Advanced Cybersecurity Toolkit 🛡️

Cyber Guard is a comprehensive, offline web-based cybersecurity toolkit developed as a final-year IT diploma project at K.K. Wagh Polytechnic. Designed for educational threat simulation and vulnerability auditing, this platform bundles eight distinct security utilities into a secure, isolated local environment.

## 🚀 Key Features and Tools

* **URL Vulnerability Scanner:** Analyzes links for phishing indicators, DGAs, and obfuscation. Evaluates URL entropy, missing HTTPS protocols, IP-based domains, excessive hyphens, suspicious TLDs, and URL shorteners.
* **File Static Analyzer:** Performs deep heuristic scans and checks for packed payloads. Utilizes signature-based detection against known virus hashes, calculates file entropy, and parses PE files to verify trusted vendor signatures for Windows executables.
* **Forensic Metadata Extractor:** Extracts EXIF data locally from uploaded images to reveal hidden tags such as GPS coordinates, camera models, and creation dates.
* **Image Steganography:** Allows users to encode and decode secret messages hidden within image pixels. Powered by Least Significant Bit (LSB) steganography processing.
* **Offline Hash Cracker:** Executes a realistic dictionary attack against SHA-256 cryptographic hashes using a custom uploaded `.txt` wordlist or the built-in dictionary.
* **Encryption Engine (Crypto Hub):** Secures and decrypts data using multiple cryptographic algorithms, including Caesar, AES-128, Base64, SHA-256, Vigenère, and Vernam ciphers.
* **Interactive SQL Injection Lab:** Provides a safe environment to test uploaded offline `.db` or `.sqlite` databases. Features a toggle between vulnerable query execution and secure parameterized queries to demonstrate how login bypasses function.
* **Cyber Awareness Game:** Offers interactive phishing detection training, tracking a live score as users classify simulated email, SMS, and phone scenarios as legitimate or suspicious.

## 💻 Technical Architecture

* **Backend Framework:** Python with Flask.
* **Core Libraries:** `hashlib` for cryptography, `pefile` for executable analysis, `sqlite3` for the SQLi lab, `stegano` for image hiding, and `cryptography.fernet` for AES implementation.
* **Frontend Interface:** Styled using Bootstrap 5 and FontAwesome icons.
* **Client-side Processing:** Utilizes `exif-js` for immediate, local metadata extraction within the browser.

## ⚙️ How to Run Locally

1. Clone the repository and navigate into the project directory.
2. Install the required Python dependencies: `pip install flask pefile stegano cryptography`
3. Run the Flask application: `python app.py`
4. Open a web browser and navigate to `http://127.0.0.1:5000` to access the dashboard.

## 👥 Project Team

* **Developers:** Omkar Kasar, Sankalp Kamble, and Aditya Patil
* **Mentorship:** Prof. Poonam Thakare
