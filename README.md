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

#### prerequisite
```
sudo rm -rf ./google-chrome-stable*
sudo wget "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
sudo apt install ./google-chrome-stable*.deb -y
sudo rm -rf ./google-chrome-stable*
```
## Installation
```
cd /opt/ && sudo git clone https://github.com/h6nt3r/xsser.git && cd xsser/
sudo chmod +x *.py
sudo pip3 install -r requirements.txt --break-system-packages
sudo ln -sf /opt/xsser/xsser.py /usr/local/bin/xsser
cd
xsser -h
```
