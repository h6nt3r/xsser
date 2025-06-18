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
from playwright.sync_api import sync_playwright

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
        return ''.join(char.lower() if i % 2 == 0 else char.upper() for i, char in enumerate(payload))
    elif encoding == "html":
        html_escape_table = {
            "<": "&lt;", ">": "&gt;", "&": "&amp;",
            "\"": "&quot;", "'": "&#39;"
        }
        return "".join(html_escape_table.get(c, c) for c in payload)
    elif encoding == "nullk":
        return re.sub(r'(?=(script|img|svg|iframe|body|embed|object|video))', '%00', payload, flags=re.IGNORECASE)
    elif encoding == "nulle":
        return re.sub(r'\bon\b', 'on%00', payload, flags=re.IGNORECASE)
    return payload

def is_vulnerable(url, payload, context):
    try:
        page = context.new_page()
        xss_triggered = False

        def handle_dialog(dialog):
            nonlocal xss_triggered
            try:
                xss_triggered = True
                dialog.accept()
            except Exception as e:
                if "Target page, context or browser has been closed" not in str(e):
                    logging.error(f"Dialog accept failed: {e}")

        page.on("dialog", handle_dialog)
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(1500)  # 1.5s is usually enough for dialog popups
        page.close()
        return xss_triggered
    except Exception as e:
        logging.error(f"Error during scan: {e}")
        return False

def inject_payloads(url, payloads, url_index, total_urls, context, vulnerable_payload_count, output_queue=None, encoding="none"):
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
            print(Fore.CYAN + f"Payload({payload_index}/{len(payloads)}): {encoded_payload}")
            test_params = query_params.copy()
            test_params[key] = [encoded_payload]
            new_query = "&".join(f"{k}={v[0]}" for k, v in test_params.items())
            new_url = urlunsplit((scheme, netloc, path, new_query, fragment))
            if is_vulnerable(new_url, payload, context):
                vulnerable_urls.append(new_url)
                print(Fore.WHITE + "[✓] XSS Vulnerable: " + Back.GREEN + new_url + Back.RESET)
                vulnerable_payload_count[0] += 1
                if output_queue:
                    output_queue.put(new_url)
            else:
                print(Fore.RED + f"[✗] Not Vulnerable: {new_url}")
            print()
    return vulnerable_urls

def playwright_worker_thread(thread_id, urls, payloads, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context()  # Reuse context for all URLs in this thread
        try:
            results = []
            for url_index, url in urls:
                with rate_limit_semaphore:
                    print(Fore.YELLOW + f"\nURL({url_index}/{total_urls}): {url}")
                    start_time = time.time()
                    found = inject_payloads(url, payloads, url_index, total_urls, context, vulnerable_payload_count, output_queue, encoding)
                    elapsed_time = time.time() - start_time
                    sleep_time = max(0, target_scan_time - elapsed_time)
                    time.sleep(sleep_time)
                    results.extend(found)
            return results
        finally:
            context.close()  # ✅ Clean up shared context
            browser.close()

def xss_scan(urls, payloads, output_file=None, num_threads=1, encoding="none"):
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
        def write_output():
            with open(output_file, 'a') as f:
                while True:
                    url = output_queue.get()
                    if url is None:
                        output_queue.task_done()
                        break
                    f.write(url + '\n')
                    f.flush()
                    output_queue.task_done()
        writer_thread = threading.Thread(target=write_output)
        writer_thread.start()

    urls_with_index = list(enumerate(urls, start=1))
    chunk_size = ceil(len(urls) / num_threads)
    chunks = [urls_with_index[i:i + chunk_size] for i in range(0, len(urls_with_index), chunk_size)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(playwright_worker_thread, idx, chunk, payloads, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding)
                   for idx, chunk in enumerate(chunks)]
        for future in concurrent.futures.as_completed(futures):
            all_vulnerable.extend(future.result())

    if output_queue:
        output_queue.put(None)
        writer_thread.join()

    print(Fore.GREEN + f"\nTotal XSS Vulnerabilities Found: {vulnerable_payload_count[0]}")
    return all_vulnerable

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Scanner using Playwright and Chromium")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="File with URLs to scan")
    group.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-p", "--payloads", required=True, help="File with XSS payloads")
    parser.add_argument("-o", "--output", help="Output file to save vulnerable URLs")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads")
    parser.add_argument(
    "-e", "--encoding",
    default="none",
    help="Encoding method for payloads (options: none, url, base64, unicode, altc, html, nullk, nulle)"
)
    args = parser.parse_args()

    # Input: file, URL, or stdin
    if args.file:
        with open(os.path.expanduser(args.file), "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.url:
        urls = [args.url.strip()]
    elif not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        parser.error("one of the arguments -f/--file -u/--url is required (or pipe URLs to stdin)")

    with open(os.path.expanduser(args.payloads), "r") as f:
        payloads = [line.strip() for line in f if line.strip()]

    xss_scan(urls, payloads, output_file=args.output, num_threads=args.threads, encoding=args.encoding)
