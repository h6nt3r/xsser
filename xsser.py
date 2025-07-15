#!/usr/bin/env python3
import urllib3
import os
import argparse
from urllib.parse import urlsplit, parse_qs, urlunsplit, quote
import base64
from colorama import Fore, Back, init
import concurrent.futures
import time
import threading
import queue
import logging
import re
import sys
import json

init(autoreset=True)
logging.getLogger('WDM').setLevel(logging.ERROR)
logging.basicConfig(level=logging.ERROR, format='%(threadName)s: %(message)s')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def encode_payload(payload, encoding):
    if encoding == "url":
        return quote(payload, safe='')
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "unicode":
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    elif encoding == "altc":
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.lower() if i % 2 == 0 else char.upper()
            else:
                result += char
        return result
    elif encoding == "html":
        html_escape_table = {
            "<": "&lt;",
            ">": "&gt;",
            "&": "&amp;",
            "\"": "&quot;",
            "'": "&#39;"
        }
        return "".join(html_escape_table.get(c, c) for c in payload)
    elif encoding == "nullk":
        return re.sub(r'(?=(script|img|svg|iframe|body|embed|object|video))', '%00', payload, flags=re.IGNORECASE)
    elif encoding == "nulle":
        return re.sub(r'\bon\b', 'on%00', payload, flags=re.IGNORECASE)
    return payload

def inject_payloads(url, payloads, url_index, total_urls, driver, vulnerable_payload_count, output_queue=None, encoding="none", methods=["get"]):
    vulnerable_urls = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string, keep_blank_values=True)
    param_keys = list(query_params.keys())

    scan_keys = [key for key in param_keys if query_params[key] == ['*']]
    if not scan_keys:
        scan_keys = param_keys

    scan_index = 0
    for param_index, key in enumerate(param_keys, start=1):
        if key not in scan_keys:
            continue

        scan_index += 1
        print(Fore.BLUE + f"Parameter({scan_index}/{len(scan_keys)}): {key}")
        for payload_index, payload in enumerate(payloads, start=1):
            encoded_payload = encode_payload(payload, encoding)
            for method in methods:
                print(Fore.MAGENTA + f"Method: {method.upper()}")
                print(Fore.CYAN + f"Payload({payload_index}/{len(payloads)}): {encoded_payload}")
                test_params = query_params.copy()
                test_params[key] = [encoded_payload]
                new_query = "&".join(f"{k}={v[0]}" for k, v in test_params.items())
                new_url = urlunsplit((scheme, netloc, path, new_query, fragment))
                if is_vulnerable(new_url, payload, driver, method):
                    vulnerable_urls.append(new_url)
                    print(Fore.WHITE + "[\u2713] XSS Vulnerable: " + Back.GREEN + new_url + Back.RESET)
                    vulnerable_payload_count[0] += 1
                    if output_queue:
                        output_queue.put(new_url)
                else:
                    print(Fore.RED + f"[\u2717] Not Vulnerable: {new_url}")
                print()
    return vulnerable_urls

from selenium.common.exceptions import WebDriverException


def is_vulnerable(url, payload, driver, method="get"):
    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException
        from urllib.parse import urlsplit, urlunsplit, quote

        driver.set_page_load_timeout(10)
        driver.get("data:,")  # Reset the browser memory

        if method == "get":
            driver.get(url)
        else:
            # Prepare endpoint and body from query string
            parsed = urlsplit(url)
            endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
            data = parsed.query  # already in param1=value1&param2=value2 format

            js_fetch = f"""
                fetch({json.dumps(endpoint)}, {{
                    method: {json.dumps(method.upper())},
                    headers: {{
                        "Content-Type": "application/x-www-form-urlencoded"
                    }},
                    body: {json.dumps(data)}
                }})
                .then(r => r.text())
                .then(html => {{
                    document.body.innerHTML = html;
                }});
            """
            driver.execute_script(js_fetch)
            time.sleep(2)  # allow DOM to render response

        # ✅ 1. Alert-based detection
        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            if alert_text:
                return True
        except TimeoutException:
            pass

        # ✅ 2. DOM-based or raw reflection detection
        page_source = driver.page_source.lower()
        payload_l = payload.lower()
        quoted_payload = quote(payload).lower()

        if payload_l in page_source or quoted_payload in page_source:
            print(Fore.LIGHTYELLOW_EX + "[!] Payload reflected in HTML/DOM (no alert triggered)")
            return True

        # ✅ 3. Optional: SQLi error detection
        if "you have an error in your sql syntax" in page_source:
            print(Fore.LIGHTRED_EX + "[!] SQL error triggered — possible injection point")

        return False

    except Exception as e:
        if 'not attached to an active page' in str(e).lower():
            logging.warning(f"[!] Skipping unstable page (lost context): {url}")
        else:
            logging.error(f"Error during scan: {e}")
        return False

def scan_url(driver, url, payloads, url_index, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods):
    try:
        with rate_limit_semaphore:
            print(Fore.YELLOW + f"\nURL({url_index}/{total_urls}): {url}")
            start_time = time.time()
            found = inject_payloads(url, payloads, url_index, total_urls, driver, vulnerable_payload_count, output_queue, encoding, methods)
            elapsed_time = time.time() - start_time
            sleep_time = max(0, target_scan_time - elapsed_time)
            time.sleep(sleep_time)
            return found
    except Exception as e:
        logging.error(f"Thread error for URL {url}: {e}")
        return []

def worker_thread(thread_id, urls, payloads, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

    options = Options()
    options.add_argument('--headless=new')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-extensions')
    options.add_argument('--window-size=1280,720')
    prefs = {
        "profile.managed_default_content_settings.images": 2,
        "profile.managed_default_content_settings.stylesheets": 2,
        "profile.managed_default_content_settings.fonts": 2,
        "profile.managed_default_content_settings.media_stream": 2
    }
    options.add_experimental_option("prefs", prefs)

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    try:
        results = []
        for url_index, url in urls:
            result = scan_url(driver, url, payloads, url_index, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods)
            results.extend(result)
        return results
    finally:
        driver.quit()

def write_output_queue(output_queue, output_file):
    with open(output_file, 'a') as f:
        while True:
            try:
                url = output_queue.get()
                if url is None:
                    output_queue.task_done()
                    break
                f.write(url + '\n')
                f.flush()
                output_queue.task_done()
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                break

def xss_scan(urls, payloads, output_file=None, num_threads=1, encoding="none", methods=["get"]):
    from threading import BoundedSemaphore
    from math import ceil

    all_vulnerable = []
    vulnerable_payload_count = [0]
    total_urls = len(urls)

    target_scans_per_second_per_thread = 10.0 / max(1, num_threads)
    target_scan_time = 1.0 / target_scans_per_second_per_thread

    rate_limit_semaphore = BoundedSemaphore(value=num_threads)
    output_queue = queue.Queue() if output_file else None

    if output_file:
        writer_thread = threading.Thread(target=write_output_queue, args=(output_queue, output_file))
        writer_thread.start()

    urls_with_index = list(enumerate(urls, start=1))
    chunk_size = ceil(len(urls_with_index) / num_threads)
    chunks = [urls_with_index[i:i + chunk_size] for i in range(0, len(urls_with_index), chunk_size)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(worker_thread, i, chunk, payloads, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods)
            for i, chunk in enumerate(chunks)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                all_vulnerable.extend(future.result())
            except Exception as e:
                logging.error(f"Thread error: {e}")

    if output_file:
        output_queue.put(None)
        writer_thread.join()

    print(Fore.YELLOW + f"Total number of xss '{vulnerable_payload_count[0]}' found.")
    return all_vulnerable

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner")
    parser.add_argument("-u", "--url", help="Single URL to test")
    parser.add_argument("-f", "--file", help="File with list of URLs to test")
    parser.add_argument("-p", "--payloads", help="Path to payload file", required=True)
    parser.add_argument("-o", "--output", help="Output file to save vulnerable URLs")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads for scanning (default: 1)")
    parser.add_argument("-enc", "--encoding", choices=["url", "base64", "unicode", "altc", "html", "none", "nullk", "nulle"], default="none", help="Encoding mechanism for payloads")
    parser.add_argument("-x", "--methods", help="Comma-separated HTTP methods to test (e.g., get,post,put,patch)", default="get")
    args = parser.parse_args()

    if not os.path.isfile(args.payloads):
        print(Fore.RED + f"[!] Payload file not found: {args.payloads}")
        exit(1)

    with open(args.payloads, 'r') as f:
        payloads = [line.strip() for line in f if line.strip()]

    urls = []
    if args.url:
        urls.append(args.url.strip())
    elif args.file:
        if not os.path.isfile(args.file):
            print(Fore.RED + f"[!] URL file not found: {args.file}")
            exit(1)
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    elif not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        print(Fore.RED + "[!] Please provide a URL via -u, -f, or stdin piping.")
        exit(1)

    methods = [m.strip().lower() for m in args.methods.split(",")]

    xss_scan(urls, payloads, output_file=args.output, num_threads=args.threads, encoding=args.encoding, methods=methods)