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
import requests
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

def is_vulnerable_by_playwright(method, url, payload, context):
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
        if method == "GET":
            page.goto(url, wait_until="domcontentloaded")
        elif method in ["POST", "PUT", "PATCH"]:
            data = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
            page.goto(urlsplit(url)._replace(query='').geturl(), wait_until="domcontentloaded")
            page.evaluate("(data) => fetch(window.location.href, {method: '%s', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams(data)});" % method.upper(), data)
        page.wait_for_timeout(1500)
        content = page.content()
        if payload in content:
            xss_triggered = True
        page.close()
        return xss_triggered
    except Exception as e:
        logging.error(f"Error during scan: {e}")
        return False

def inject_payloads(url, payloads, url_index, total_urls, context, vulnerable_payload_count, output_queue=None, encoding="none", methods=["GET"]):
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
            for method in methods:
                print(Fore.MAGENTA + f"Method: {method.upper()}")
                if is_vulnerable_by_playwright(method.upper(), new_url, payload, context):
                    vulnerable_urls.append(new_url)
                    print(Fore.WHITE + "[✓] XSS Vulnerable: " + Back.GREEN + new_url + Back.RESET)
                    vulnerable_payload_count[0] += 1
                    if output_queue:
                        output_queue.put(new_url)
                else:
                    print(Fore.RED + f"[✗] Not Vulnerable: {new_url}")
                print()
    return vulnerable_urls

def get_argument_parser():
    parser = argparse.ArgumentParser(description="XSS Scanner using Playwright and Chromium")
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("-f", "--file", help="File containing list of URLs to scan")
    parser.add_argument("-p", "--payloads", required=True, help="File with XSS payloads")
    parser.add_argument("-o", "--output", help="File to write vulnerable URLs")
    parser.add_argument("-e", "--encoding", choices=["none", "url", "base64", "unicode", "altc", "html", "nullk", "nulle"], default="none", help="Payload encoding method")
    parser.add_argument("-x", "--methods", help="Comma-separated HTTP methods to test (e.g., get,post,put,patch)")
    return parser

def main():
    parser = get_argument_parser()
    args = parser.parse_args()

    methods = args.methods.split(",") if args.methods else ["GET"]
    methods = [m.strip().upper() for m in methods]

    if args.file:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.url:
        urls = [args.url]
    elif not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        print("[-] Error: No URL or file provided.")
        sys.exit(1)

    with open(args.payloads, 'r') as f:
        payloads = [line.strip() for line in f if line.strip()]

    vulnerable_payload_count = [0]
    output_queue = queue.Queue() if args.output else None

    def write_output():
        with open(args.output, 'a') as f:
            while True:
                url = output_queue.get()
                if url is None:
                    output_queue.task_done()
                    break
                f.write(url + '\n')
                f.flush()
                output_queue.task_done()

    writer_thread = threading.Thread(target=write_output) if args.output else None
    if writer_thread:
        writer_thread.start()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        try:
            for index, url in enumerate(urls, start=1):
                print(Fore.YELLOW + f"\nURL({index}/{len(urls)}): {url}")
                inject_payloads(url, payloads, index, len(urls), context, vulnerable_payload_count, output_queue, args.encoding, methods)
        finally:
            context.close()
            browser.close()

    if output_queue:
        output_queue.put(None)
        writer_thread.join()

if __name__ == "__main__":
    main()
