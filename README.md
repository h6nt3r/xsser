# XSSER – Multi-Threaded XSS Scanner with Payload Encoding

## Description

`xsser` is an advanced multi-threaded cross-site scripting (XSS) vulnerability scanner built with Selenium and Python 3. It supports custom payload encoding, multiple HTTP methods, output logging, and DOM-based vulnerability detection.

## Features

- 🚀 Multi-threaded URL scanning
- 🧪 Encoded payload injection (URL, base64, unicode, HTML, etc.)
- 📄 Support for GET and POST methods
- 🕵️ Alert box detection + DOM payload reflection
- 💡 Intelligent browser-based rendering using Selenium WebDriver
- 💾 Output vulnerable URLs to a file (optional)
- 🧵 Rate-limited threading to avoid detection or bans

## Requirements

- Python 3.8+
- Google Chrome (or Chromium)
- ChromeDriver (managed automatically via `webdriver-manager`)

## Installation

```bash
pip install -r requirements.txt