# 🚀 Advance XSS Scanner

A fast, XSS scanning tool with payload injection and a silent mode for clean output. Below highlights features, usage, examples and tips in a compact, eye-catching style.

---

## ✨ Highlights

* 🔬 **Accurate**: Reserve-value logic + parameter filtering helps lower false positives.
* 🤫 **Silent mode**: `-s` prints only URLs (white = Not Vulnerable, red = XSS Found).
* ⚙️ **Parallel**: Multi-threaded (configurable `-t`) with atomic counters and deduped results.

---

## 🚩 Quick Usage

```bash
# single URL
xsser -u "http://testphp.vulnweb.com/listproducts.php?cat=a&dog=1" -p payloads.txt -o out.txt

# file of URLs
xsser -f urls.txt -p payloads.txt  -o out.txt

# Specific point injection
------------------------------------------------------------------
http://testphp.vulnweb.com/listproducts.php?cat=FUZZ&dog=1
http://testphp.vulnweb.com/login.php?id=FUZZ
http://testhtml5.vulnweb.com/comment?id=FUZZ
------------------------------------------------------------------
xsser -f urls.txt -p payloads.txt -pl "FUZZ" -o out.txt

# pipe input
echo "http://testphp.vulnweb.com/listproducts.php?cat=a&dog=2" | xsser -p payloads.txt -s
```

---

## 🧭 Flags (summary)

* `-u string` — single URL to scan
* `-f string` — file with URLs (one per line)
* `-p string` — payload file (one per line) **(required)**
* `-pl string` — keyword: only scan parameters whose value contains this keyword (silent skip otherwise)
* `-s` — silent: only print URLs (white = Not Vulnerable, red = XSS Found)
* `-t int` — number of worker threads (default `5`)
* `-T int` — timeout seconds per test (default `10`)
* `-o string` — output file (plain text, only XSS found URLs)

---

## 📦 Installation

1. Install Go (1.20+ recommended).
2. Install Chrome/Chromium on your machine.

## Upcomming features

* 50+ Encoding mechanism
* Many more....