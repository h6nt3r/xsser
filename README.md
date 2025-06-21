# 🧪 xsser - Advanced XSS Scanner with Playwright
## 🚀 Features

- ✅ **Reflected XSS Detection**
- ✅ **DOM-Based XSS Detection** via browser instrumentation
- 🎭 **Payload Encodings**: Supports URL, Base64, Unicode, HTML, AltCaps, null byte (key/element) encoding.
- 🌐 **HTTP Methods**: Supports GET, POST, PUT, PATCH.
- 📄 **Input via URL, File, or STDIN**
- 📄 **Multi-URL Support**: Scan a single URL or batch scan from a file.
- ✍️ **Custom Payloads**: Accepts payload lists from user-supplied files.
- 📤 **Export Results**: Optionally write all vulnerable URLs to an output file.
- 🧠 **Smart Parameter Detection**: Replaces `*` in query parameters to pinpoint test vectors.
- 💡 **Handles Dialogs, Console Logs, and JS Sinks**

## 🧬 Payload Encoding Methods

xsser supports multiple encoding strategies to bypass input filters and WAFs. Below are the supported encoding methods with examples:

| Encoding    | Description                                            | Example Input       | Encoded Output                            |
|-------------|--------------------------------------------------------|----------------------|--------------------------------------------|
| `none`      | No encoding                                            | `<script>alert(1)</script>` | `<script>alert(1)</script>`        |
| `url`       | URL encodes characters                                 | `<script>`           | `%3Cscript%3E`                             |
| `base64`    | Encodes the entire payload in Base64                  | `<script>alert(1)</script>` | `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |
| `unicode`   | Converts to Unicode escape sequences                  | `<script>`           | `\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e` |
| `altc`      | Alternating casing for obfuscation                    | `<script>`           | `<ScRiPt>`                                 |
| `html`      | Escapes special characters to HTML entities           | `<script>`           | `&lt;script&gt;`                           |
| `nullk`     | Inserts null bytes before dangerous tags (key-based) | `<script>`           | `%00script`                                |
| `nulle`     | Obfuscates event handlers like `onerror`             | `onerror=alert(1)`   | `on%00error=alert(1)`                      |

## Installation
```
cd /opt/ && sudo git clone https://github.com/h6nt3r/xsser.git && cd xsser
sudo pip3 install -r requirements.txt --break-system-packages
playwright install chromium
cd
sudo chmod +x /opt/xsser/xsser.py
sudo ln -sf /opt/xsser/xsser.py /usr/local/bin/xsser
xsser -h
```
# 🧑‍💻 Usage
## Use in pipeline context
```
cat urls.txt | xsser -p ~/payloads/collection_payloads/xss/xssCollected.txt -x get,post -e url -o output.txt
```
## Use in single url context
```
xsser -u "http://testphp.vulnweb.com/Mod_Rewrite_Shop/details.php?id=ok&mjqN=ok" -p ~/payloads/collection_payloads/xss/xssCollected.txt -x get,post -e nullk -o output.txt
```
## Use file context
```
xsser -f urls.txt -p ~/payloads/collection_payloads/xss/xssCollected.txt -x get,post -e nullk -o output.txt
```
## Use in pinpoint url context
```
xsser -u "http://testphp.vulnweb.com/Mod_Rewrite_Shop/details.php?id=*&mjqN=ok" -p ~/payloads/collection_payloads/xss/xssCollected.txt -x get,post -e nullk -o output.txt
```
# Options
```
-u, --url        : Single target URL to scan
-f, --file       : File with list of URLs to scan
-p, --payloads   : REQUIRED. File containing XSS payloads
-o, --output     : Output file for vulnerable URLs
-e, --encoding   : Encoding method [none, url, base64, unicode, altc, html, nullk, nulle]
-x, --methods    : HTTP methods to test (comma-separated, e.g., get,post,put,patch)
```

# ⚠️ Legal Disclaimer
### This tool is for educational and authorized security testing only. Unauthorized use is illegal.

Always get explicit written permission before scanning any system.
