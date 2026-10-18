🚀 WAF-DETECTOR

⚡ A fast Web Application Firewall detection and fingerprinting tool written in Python. WAF-DETECTOR checks a target's HTTP response headers, cookies, and body patterns against a bundled signature database, ranks matches by confidence and evidence score, and optionally runs behavioral probes to see which attack payloads are blocked.

✨ Features

🛡️ Signature-based WAF detection (30+ WAFs, CDNs, and reverse proxies)
🍪 Header, cookie, and body pattern matching
📊 Confidence ranking (high / medium) with evidence scoring
🧪 Optional behavioral probes (SQLi, XSS, LFI, RCE, traversal, scanner UA)
🎯 Bypass technique hints per detected WAF
🌐 HTTP/HTTPS proxy support
💾 JSON report export
🎨 TrueColor gradient banner and rainbow author tag
📦 Zero external dependencies — Python standard library only

📋 Requirements

🐧 Linux, macOS, or Windows
🐍 Python 3.8 or later
📦 Git
📝 A waf_signatures.json file in the working directory

🛠️ Installation

Step 1 — Update package lists

    sudo apt update

Step 2 — Install Git and Python 3

    sudo apt install -y git python3 python3-pip

Step 3 — Check your Python version

    python3 --version

Python 3.8 or later is required. If your version is older, install a newer one from https://www.python.org/downloads/

Step 4 — Clone the repository

    git clone https://github.com/K52-ai/waf-detector.git

Step 5 — Enter the project directory

    cd waf-detector

Step 6 — Verify the signature file is present

    ls waf_signatures.json

The file must be in the same directory as waf_detector.py.

Step 7 — Make the script executable

    chmod +x waf_detector.py

Step 8 — No pip install needed

WAF-DETECTOR uses only the Python standard library. Skip this step if you already have Python 3.8+.

▶️ Usage

Step 1 — Start the tool with a target URL

    python3 waf_detector.py https://example.com

Step 2 — Or start without arguments

    python3 waf_detector.py

The tool will prompt:

    Target: https://example.com

Enter your authorized target URL and press Enter.

Step 3 — Run with behavioral probes

    python3 waf_detector.py https://example.com --behavior

Sends test payloads (SQLi, XSS, LFI, RCE, traversal) and reports which ones were blocked.

Step 4 — Save a JSON report

    python3 waf_detector.py https://example.com -j

Writes the full report to waf_report.json.

Step 5 — Combine flags

    python3 waf_detector.py https://example.com --behavior -j -v

Step 6 — Route through a proxy (Burp, ZAP, etc.)

    python3 waf_detector.py https://example.com --proxy http://127.0.0.1:8080

Step 7 — Set a custom timeout

    python3 waf_detector.py https://example.com --timeout 30

📝 Signature File

waf_signatures.json maps WAF keys to signature objects:

    "cloudflare": {
      "name": "Cloudflare",
      "type": "Cloud-based (CDN + WAF)",
      "headers": {
        "server": "cloudflare",
        "cf-ray": "*",
        "cf-cache-status": "*"
      },
      "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
      "confidence": "high"
    }

Supported fields:

- name — display name
- type — deployment model
- headers — header name → wildcard pattern (* = any value)
- cookies — cookie name substrings
- body_patterns — body substrings
- confidence — high or medium

To add a new WAF, append an object to the JSON root and re-run.

📊 Results

🟢 WAF DETECTED — best match by evidence score
🟡 Other possible matches — lower-confidence candidates
🔵 Behavioral analysis — blocked vs passed payloads (with --behavior)
💾 waf_report.json — full structured report (with -j)

View the saved report:

    cat waf_report.json

Count detection matches:

    jq '.matches | length' waf_report.json

🖼️ Screenshots

Add your actual screenshots to the assets/ folder, then reference them:

    ![Detection](assets/detection.png)
    ![Behavioral](assets/behavioral.png)

⚠️ Important Notes

🛡️ Signature matching relies on known header and cookie patterns — unknown or custom WAFs may not be identified.
🔍 Header matching is case-insensitive and supports * wildcards, but does not inspect TLS fingerprints.
🧪 Behavioral probes send attack payloads to the target — only enable --behavior against systems you are authorized to test.
🔐 TLS certificate verification is disabled in the HTTP client.
⚡ Requests are sequential; concurrency is not implemented in this version.
🌐 Proxy support covers HTTP and HTTPS via --proxy.

⚖️ Responsible Use

Use WAF-DETECTOR only on systems you own or have explicit permission to test. Respect server rate limits and applicable laws.

📜 License

MIT License. See LICENSE for details.

👨‍💻 Author

K52-ai — 🔗 GitHub Repository
<img width="1005" height="597" alt="image" src="https://github.com/user-attachments/assets/6135953b-3ec7-4a47-bc05-b20eba4a84d9" />
<img width="1005" height="601" alt="image" src="https://github.com/user-attachments/assets/dc1ae7a0-e68d-47d9-85b7-f2418e04961e" />

