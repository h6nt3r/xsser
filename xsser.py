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

# ---------------- Banner ----------------
def print_banner(silent=False):
    """
    Print a stylish italic banner unless silent is True.
    Uses ANSI italic escape sequence; terminals that don't support italics will ignore it.
    """
    if silent:
        return
    italic = '\x1B[3m'
    reset_all = '\x1B[0m'
    print()
    print(Fore.CYAN + italic + "Developed by h6nt3r" + reset_all)
    print()
    disclaimer = (
        "[!] legal disclaimer: Usage of xsser for attacking targets without prior mutual consent is illegal. "
        "It is the end user's responsibility to obey all applicable local, state and federal laws. "
        "Developers assume no liability and are not responsible for any misuse or damage caused by this program"
    )
    print(Fore.YELLOW + italic + disclaimer + reset_all)
    print()

# ----------------------------------------

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

def inject_payloads(url, payloads, url_index, total_urls, driver, vulnerable_payload_count, output_queue=None, encoding="none", methods=["get"], verbose=True, silent=False):
    """
    Try payloads for each parameter. Report alert/prompt/confirm-based vulnerabilities.
    When `silent` is True only prints the vulnerable/not vulnerable lines.
    """
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
        # Show parameter header only when not silent
        if not silent:
            print(Fore.BLUE + f"Parameter({scan_index}/{len(scan_keys)}): {key}")

        for payload_index, payload in enumerate(payloads, start=1):
            encoded_payload = encode_payload(payload, encoding)
            for method in methods:
                # Verbose details only when not silent
                if not silent and verbose:
                    print(Fore.MAGENTA + f"Method: {method.upper()}")
                    print(Fore.CYAN + f"Payload({payload_index}/{len(payloads)}): {encoded_payload}")

                test_params = query_params.copy()
                test_params[key] = [encoded_payload]
                new_query = "&".join(f"{k}={v[0]}" for k, v in test_params.items())
                new_url = urlunsplit((scheme, netloc, path, new_query, fragment))

                if is_vulnerable(new_url, payload, driver, method, verbose=verbose, silent=silent):
                    # Always print vulnerable line (both silent and verbose modes)
                    print(Fore.WHITE + "[\u2713] XSS Found: " + Back.GREEN + new_url + Back.RESET)
                    vulnerable_urls.append(new_url)
                    vulnerable_payload_count[0] += 1
                    if output_queue:
                        output_queue.put(new_url)
                else:
                    # Print Not Vulnerable in both silent and verbose modes
                    print(Fore.RED + f"[\u2717] Not Vulnerable: {new_url}")
                if not silent and verbose:
                    print()
    return vulnerable_urls

from selenium.common.exceptions import WebDriverException

def is_vulnerable(url, payload, driver, method="get", verbose=True, silent=False):
    """
    Return True if an alert/prompt/confirm dialog appears.
    Enhanced detection:
    - Uses CDP pre-injected JS flag (if available) to catch very-early dialogs
    - Aggressive polling of driver.switch_to.alert during load and after fetch fallback
    - Fallback injection via execute_script after navigation/fetch so that sites where CDP failed still get hooked
    """
    try:
        from selenium.common.exceptions import NoAlertPresentException
        from urllib.parse import urlsplit, urlunsplit, quote

        # short page load timeout so we don't hang (some drivers may not support)
        try:
            driver.set_page_load_timeout(10)
        except Exception:
            pass

        # Reset to blank
        try:
            driver.get("data:,")
        except Exception:
            pass

        # More robust JS hook used both for CDP and execute_script fallback
        js_dialog_hook = r"""
            (function(){
                try {
                    // always set default flags
                    Object.defineProperty(window, '__xsser_dialog_shown', {value:false, writable:true, configurable:true});
                    Object.defineProperty(window, '__xsser_dialog_type', {value:null, writable:true, configurable:true});
                    Object.defineProperty(window, '__xsser_dialog_text', {value:null, writable:true, configurable:true});
                } catch(e){}
                try {
                    function installHook(){
                        try {
                            ['alert','prompt','confirm'].forEach(function(fn){
                                try {
                                    var orig = window[fn];
                                    if (typeof orig !== 'function') return;
                                    window[fn] = function(){
                                        try {
                                            window.__xsser_dialog_shown = true;
                                            window.__xsser_dialog_type = fn;
                                            try { window.__xsser_dialog_text = arguments[0]; } catch(e){}
                                        } catch(e){}
                                        try {
                                            return orig.apply(this, arguments);
                                        } catch(e){
                                            // if orig.apply fails, just return undefined to avoid breaking page
                                            return undefined;
                                        }
                                    };
                                } catch(e){}
                            });
                        } catch(e){}
                    }
                    // try immediate install
                    installHook();
                    // also expose a function to reinstall if page replaced scripts later
                    try {
                        window.__xsser_install_dialog_hook = installHook;
                    } catch(e){}
                } catch(e){}
            })();
        """

        def poll_for_dialogs(total_wait=7.0, poll_interval=0.15):
            """
            Poll for either the CDP-injected flag or native alert via switch_to.alert.
            Returns True when detected and tries to accept/dismiss.
            """
            end_time = time.time() + total_wait
            while time.time() < end_time:
                # 1) Check JS-injected flag (if script was added to new documents)
                try:
                    flagged = False
                    try:
                        flagged = driver.execute_script("return (typeof window.__xsser_dialog_shown !== 'undefined') && window.__xsser_dialog_shown === true;")
                    except Exception:
                        flagged = False
                    if flagged:
                        # Try to close native dialog if present (best-effort)
                        try:
                            alert = driver.switch_to.alert
                            try:
                                _ = alert.text
                            except Exception:
                                pass
                            try:
                                alert.accept()
                            except Exception:
                                try:
                                    alert.dismiss()
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        return True
                except Exception:
                    # ignore and continue to next check
                    pass

                # 2) Check native alert/prompt/confirm via switch_to.alert
                try:
                    alert = driver.switch_to.alert
                    try:
                        _ = alert.text
                    except Exception:
                        pass
                    try:
                        alert.accept()
                    except Exception:
                        try:
                            alert.dismiss()
                        except Exception:
                            pass
                    return True
                except NoAlertPresentException:
                    # no alert yet
                    pass
                except Exception:
                    # unexpected exception; ignore and continue
                    pass

                time.sleep(poll_interval)
            return False

        # If GET: do a non-blocking navigation that allows polling while loading
        if method == "get":
            try:
                driver.get(url)
            except Exception:
                # ignore navigation exceptions; we'll poll and also try fetch fallback
                if not silent and verbose:
                    logging.debug("GET navigation raised exception; continuing to poll and attempt fallback.")

            # Fallback: try execute_script to install hook in current page (in case CDP wasn't available)
            try:
                driver.execute_script(js_dialog_hook)
            except Exception:
                # some pages may not allow execute_script until fully loaded; ignore
                pass

            # Poll aggressively during page load (covers very-early dialogs)
            if poll_for_dialogs(total_wait=7.0, poll_interval=0.15):
                return True

            # Fallback: use fetch+document.write to render response (helps in some cases)
            try:
                parsed = urlsplit(url)
                endpoint_with_query = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ''))
                js_fetch_and_write = f"""
                    fetch({json.dumps(endpoint_with_query)}, {{
                        method: "GET",
                        credentials: "include"
                    }})
                    .then(r => r.text())
                    .then(html => {{
                        try {{
                            document.open();
                            document.write(html);
                            document.close();
                        }} catch (e) {{
                            document.body.innerHTML = html;
                        }}
                        try {{
                            // try to reinstall hook in the freshly written document
                            if (typeof window.__xsser_install_dialog_hook === 'function') {{
                                try {{ window.__xsser_install_dialog_hook(); }} catch(e){{}}
                            }} else {{
                                // if not present, add inline hook
                                (function(){{
                                    try {{
                                        ['alert','prompt','confirm'].forEach(function(fn){{
                                            try {{
                                                var orig = window[fn];
                                                if (typeof orig !== 'function') return;
                                                window[fn] = function(){{
                                                    try {{ window.__xsser_dialog_shown = true; window.__xsser_dialog_type = fn; window.__xsser_dialog_text = arguments[0]; }} catch(e){{}}
                                                    try {{ return orig.apply(this, arguments); }} catch(e){{ return undefined; }}
                                                }};
                                            }} catch(e){{}}
                                        }});
                                    }} catch(e){{}}
                                }})();
                            }}
                        }} catch(e){{}}
                    }})
                    .catch(e => {{ /* ignore */ }});
                """
                try:
                    driver.execute_script(js_fetch_and_write)
                except Exception:
                    pass
                # Also try to ensure hook is present after fetch fallback
                try:
                    driver.execute_script(js_dialog_hook)
                except Exception:
                    pass

                # Poll after fetch fallback
                if poll_for_dialogs(total_wait=4.0, poll_interval=0.15):
                    return True
            except Exception:
                pass

            return False

        else:
            # Non-GET methods: use fetch to send body and document.write response
            parsed = urlsplit(url)
            endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
            data = parsed.query  # already param1=...&param2=... format

            js_fetch_and_write = f"""
                fetch({json.dumps(endpoint)}, {{
                    method: {json.dumps(method.upper())},
                    headers: {{
                        "Content-Type": "application/x-www-form-urlencoded"
                    }},
                    body: {json.dumps(data)},
                    credentials: "include"
                }})
                .then(r => r.text())
                .then(html => {{
                    try {{
                        document.open();
                        document.write(html);
                        document.close();
                    }} catch (e) {{
                        document.body.innerHTML = html;
                    }}
                    try {{
                        if (typeof window.__xsser_install_dialog_hook === 'function') {{
                            try {{ window.__xsser_install_dialog_hook(); }} catch(e){{}}
                        }}
                    }} catch(e){{}}
                }})
                .catch(e => {{ /* ignore */ }});
            """
            try:
                driver.execute_script(js_fetch_and_write)
            except Exception:
                if not silent and verbose:
                    logging.debug("Error executing fetch script for non-GET.")
            # Try to ensure hook present
            try:
                driver.execute_script(js_dialog_hook)
            except Exception:
                pass
            # Poll after fetch
            if poll_for_dialogs(total_wait=6.0, poll_interval=0.15):
                return True
            return False

    except Exception as e:
        msg = str(e).lower()
        if 'not attached to an active page' in msg:
            if not silent:
                logging.warning(f"[!] Skipping unstable page (lost context): {url}")
        else:
            if not silent:
                logging.error(f"Error during scan: {e}")
        return False

def scan_url(driver, url, payloads, url_index, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods, verbose=True, silent=False):
    try:
        with rate_limit_semaphore:
            if not silent:
                print(Fore.YELLOW + f"\nURL({url_index}/{total_urls}): {url}")
            start_time = time.time()
            found = inject_payloads(url, payloads, url_index, total_urls, driver, vulnerable_payload_count, output_queue, encoding, methods, verbose=verbose, silent=silent)
            elapsed_time = time.time() - start_time
            sleep_time = max(0, target_scan_time - elapsed_time)
            time.sleep(sleep_time)
            return found
    except Exception as e:
        if not silent:
            logging.error(f"Thread error for URL {url}: {e}")
        return []

def worker_thread(thread_id, urls, payloads, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods, verbose=True, silent=False):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

    options = Options()
    # try to set non-blocking load so we can poll while loading
    try:
        options.page_load_strategy = 'none'
    except Exception:
        pass

    options.add_argument('--headless=new')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-extensions')
    options.add_argument('--window-size=1280,720')
    prefs = {
        # You may adjust images setting; allow images by default to help onerror triggers
        "profile.managed_default_content_settings.images": 1,
        "profile.managed_default_content_settings.stylesheets": 2,
        "profile.managed_default_content_settings.fonts": 2,
        "profile.managed_default_content_settings.media_stream": 2
    }
    options.add_experimental_option("prefs", prefs)

    # Install driver (will download if needed)
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    # --- CDP pre-injection: try to add a script that marks very-early dialogs ---
    try:
        cdp_source = r"""
            (function(){
                try {
                    window.__xsser_dialog_shown = false;
                    window.__xsser_dialog_text = null;
                    function wrap(name){
                        try {
                            var orig = window[name];
                            window[name] = function(){
                                try {
                                    window.__xsser_dialog_shown = true;
                                    try { window.__xsser_dialog_text = arguments[0]; } catch(e){}
                                } catch(e){}
                                try {
                                    return orig.apply(this, arguments);
                                } catch(e){}
                            };
                        } catch(e){}
                    }
                    ['alert','prompt','confirm'].forEach(wrap);
                } catch(e){}
            })();
        """
        # primary: add to evaluate on new document so very-early dialogs get hooked
        try:
            driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': cdp_source})
        except Exception:
            try:
                # fallback attempt
                driver.execute_cdp_cmd('Runtime.evaluate', {'expression': cdp_source})
            except Exception:
                pass
    except Exception:
        # ignore if CDP is not available
        pass

    try:
        results = []
        for url_index, url in urls:
            result = scan_url(driver, url, payloads, url_index, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods, verbose=verbose, silent=silent)
            results.extend(result)
        return results
    finally:
        try:
            driver.quit()
        except Exception:
            pass

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

def xss_scan(urls, payloads, output_file=None, num_threads=1, encoding="none", methods=["get"], verbose=True, silent=False):
    from threading import BoundedSemaphore
    from math import ceil

    all_vulnerable = []
    vulnerable_payload_count = [0]
    total_urls = len(urls)

    # target scans per sec per thread logic (preserved from original)
    target_scans_per_second_per_thread = 10.0 / max(1, num_threads)
    target_scan_time = 1.0 / target_scans_per_second_per_thread

    rate_limit_semaphore = BoundedSemaphore(value=num_threads)
    output_queue = queue.Queue() if output_file else None

    if output_file:
        writer_thread = threading.Thread(target=write_output_queue, args=(output_queue, output_file))
        writer_thread.daemon = True
        writer_thread.start()

    urls_with_index = list(enumerate(urls, start=1))
    chunk_size = ceil(len(urls_with_index) / num_threads)
    chunks = [urls_with_index[i:i + chunk_size] for i in range(0, len(urls_with_index), chunk_size)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(worker_thread, i, chunk, payloads, total_urls, vulnerable_payload_count, output_queue, rate_limit_semaphore, target_scan_time, encoding, methods, verbose, silent)
            for i, chunk in enumerate(chunks)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                all_vulnerable.extend(future.result())
            except Exception as e:
                if not silent:
                    logging.error(f"Thread error: {e}")

    if output_file:
        output_queue.put(None)
        writer_thread.join()

    if not silent:
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
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode: only show [✓] XSS Found and [✗] Not Vulnerable lines")
    args = parser.parse_args()

    if not os.path.isfile(args.payloads):
        print(Fore.RED + f"[!] Payload file not found: {args.payloads}")
        exit(1)

    with open(args.payloads, 'r', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip()]

    urls = []
    if args.url:
        urls.append(args.url.strip())
    elif args.file:
        if not os.path.isfile(args.file):
            print(Fore.RED + f"[!] URL file not found: {args.file}")
            exit(1)
        with open(args.file, 'r', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]
    elif not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        print(Fore.RED + "[!] Please provide a URL via -u, -f, or stdin piping.")
        exit(1)

    methods = [m.strip().lower() for m in args.methods.split(",")]
    silent_mode = bool(args.silent)

    # Print banner unless silent mode is enabled
    print_banner(silent=silent_mode)

    # Call scan; verbose is True by default everywhere unless silent_mode is True
    xss_scan(urls, payloads, output_file=args.output, num_threads=args.threads, encoding=args.encoding, methods=methods, verbose=True, silent=silent_mode)
