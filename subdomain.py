from bs4 import BeautifulSoup
import argparse
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import time
import re
import logging


#most updated version

def resolve_subdomain(sub, base_domain):
    full_domain = f"{sub}.{base_domain}"
    try:
        ip = socket.gethostbyname(full_domain)
        logging.info(f"[DNS ] {full_domain} -> {ip}")
        return full_domain
    except socket.gaierror:
        return None


def check_https(subdomain):
    url = f"https://{subdomain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    try:
        response = requests.get(url, timeout=3, headers=headers)
        if response.status_code < 500:
            logging.info(f"[LIVE ] {url} ({response.status_code})")
            return url
    except requests.exceptions.RequestException:
        pass
    return None




def bing_enum(domain, known_subdomains=None, max_pages=2):
    """
    Passive subdomain enumeration using Bing search
    """
    if known_subdomains is None:
        known_subdomains = set()

    logging.info("\n[+] Stage 2: Scraping Bing for subdomains")
    new_subs = set()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    # Regex fallback (VERY important for Bing)
    domain_regex = re.compile(
        rf"(?:https?://)?([\w.-]+\.{re.escape(domain)})",
        re.IGNORECASE
    )

    for page in range(1, max_pages + 1):
        # Build Bing query
        query = f"site:{domain} -www.{domain}"

        for sub in known_subdomains:
            query += f" -site:{sub}"

        encoded_query = urllib.parse.quote(query)
        first = (page - 1) * 10 + 1
        url = f"https://www.bing.com/search?q={encoded_query}&first={first}"

        logging.info(f"[DEBUG] Bing query: {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=8)
            if resp.status_code != 200:
                logging.info("[!] Bing returned non-200 response")
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]

                # Decode Bing redirect URLs
                if href.startswith("/url?"):
                    qs = urllib.parse.parse_qs(
                        urllib.parse.urlparse(href).query
                    )
                    href = qs.get("q", [""])[0]

                candidates = set()

                # 1️ Extract from URL
                parsed = urllib.parse.urlparse(href)
                if parsed.netloc:
                    candidates.add(parsed.netloc.lower())

                # 2 Regex fallback (from href + visible text)
                text = href + " " + a.get_text(" ", strip=True)
                for match in domain_regex.findall(text):
                    candidates.add(match.lower())

                # Validate subdomains
                for sub in candidates:
                    if sub.endswith("." + domain):
                        if not sub.startswith("www.") and sub not in known_subdomains:
                            if sub not in new_subs:
                                new_subs.add(sub)
                                logging.info(f"[Bing] Found: {sub}")

        except Exception as e:
            logging.info(f"[!] Bing error: {e}")

        time.sleep(1.5)  # polite delay

    return list(new_subs)

def crtsh_enum(domain):
    logging.info("\n[+] Stage 3: Querying crt.sh for certificates")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=30)
        data = response.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split('\n'):
                if sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub.strip())
        for sub in subdomains:
            logging.info(f"[crt.sh ] Found: {sub}")
        return list(subdomains)
    except Exception as e:
        logging.info(f"[!] crt.sh error: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Hybrid Subdomain Enumerator")
    parser.add_argument('-d', '--domain', required=True, help='Base domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', default='subdomains.txt', help='Path to subdomain wordlist')
    parser.add_argument('-log', '--logfile', default='scann.txt', help='File to save scan results')
    parser.add_argument('--threads', type=int, default=20, help='Number of threads (default: 20)')
    args = parser.parse_args()

    all_subdomains = []

    # to write in both file and terminal
    logging.basicConfig(
    level=logging.INFO, #Sets the minimum severity of messages to show (INFO and above). It filters out DEBUG messages.
    format="%(message)s",  # it will only store the messages not log time and other things
    handlers=[ # it tells where to send logs
        logging.FileHandler(args.logfile, mode='w'),  #write logs to file
        logging.StreamHandler() # write logs to terminal
    ]
)
    
    logging.info("starting subdomain enumeration .....")
    logging.info(f"[INPUT] Domain selected : {args.domain}")
    logging.info("Do you want to run brute-force with wordlist? (yes/no)")
    run_brute = input().strip().lower()
    logging.info(f"[INPUT] Brute-force selected: {run_brute}")

    if run_brute == "yes":
        if args.wordlist:
            with open(args.wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        else:
            subdomains = ["api", "gist", "docs", "support", "status", "nodeload"]

        logging.info("\n[+] Stage 1: Resolving DNS (Brute-force)")
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_dns = {executor.submit(resolve_subdomain, sub, args.domain): sub for sub in subdomains}
            resolved_subdomains = [future.result() for future in as_completed(future_to_dns) if future.result()]

        logging.info(f"\n[*] Total Resolved Subdomains: {len(resolved_subdomains)}")
        all_subdomains.extend(resolved_subdomains)
    else:
        logging.info("\n[+] Skipping brute-force DNS resolution.")
        resolved_subdomains = []

    bing_results = bing_enum(args.domain, all_subdomains)
    crt_results = crtsh_enum(args.domain)
    all_subdomains.extend(bing_results)
    all_subdomains.extend(crt_results)
    all_subdomains = list(set(all_subdomains))  # deduplicate

    logging.info(f"\n[*] Total Unique Subdomains Found: {len(all_subdomains)}")

    logging.info("Do you want to scan for HTTPS live URLs? (yes/no)")
    c = input().strip().lower()
    logging.info(f"[INPUT] HTTPS check selected: {c}")
    if c == 'yes':
        logging.info("\n[+] Stage 4: Checking HTTPS Availability")
        live_subdomains = []
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_https = {executor.submit(check_https, sub): sub for sub in all_subdomains}
            for future in as_completed(future_to_https):
                result = future.result()
                if result:
                    live_subdomains.append(result)

        logging.info(f"\n[*] Live HTTPS Subdomains Found: {len(live_subdomains)}")

       
        print(f"\n[**] Live subdomains saved to {args.logfile}")
    else:
        print("---------------------- Exit -------------------------------")


if __name__ == "__main__":
    main()

