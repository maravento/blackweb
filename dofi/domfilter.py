#!/usr/bin/env python3
# maravento.com

## Domain Filter Script

# What it does:
# - Downloads public suffix TLDs from multiple sources.
# - Removes invalid or duplicate TLDs.
# - Filters domains to ensure they end with a valid TLD.
# - Excludes duplicates from previously validated domains.
# - Outputs results to a file.

# Requirements:
# - Python 3.12.3

# Usage:
# Replace 'mylst.txt' with the name of your domain list
# python3 domfilter.py --input mylst.txt

# Optional parameters:
# By default, output goes to 'output.txt' and removed lines to 'removed.txt'.
# Customize output with:
# python3 domfilter.py --input mylst.txt --output outlst.txt --removed removelst.txt
# SSL verification can be disabled (not recommended) with --no-verify-ssl

# Important:
# Ensure the input list has no 'http://', 'https://', or 'www.' prefixes.

# TLD:
# Includes ccTLDs, gTLDs, sTLDs, eTLDs, and 4LDs.
# Created file: tlds.txt
# Sources:
# https://data.iana.org/TLD/tlds-alpha-by-domain.txt
# https://github.com/maravento/blackweb/blob/master/bwupdate/lst/tldsappx.txt
# https://github.com/publicsuffix/list/blob/master/public_suffix_list.dat
# https://www.whoisxmlapi.com/support/supported_gtlds.php

import requests
import re
from pathlib import Path
import warnings
from urllib3.exceptions import InsecureRequestWarning
import argparse
import sys
import os
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
TLDS_FILE = SCRIPT_DIR / "tlds.txt"
SOURCETLD_FILE = SCRIPT_DIR / "sourcetld.txt"
MIN_TLD_COUNT = 500

# TLD
def download_public_suffix(url: str, output_file: Path, verify_ssl: bool) -> None:
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
    try:
        response = requests.get(url, timeout=10, verify=verify_ssl, headers=headers)
        response.raise_for_status()
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(response.text)
    except requests.RequestException as e:
        print(f"ERROR {url}: {str(e)}")

def process_tlds_file(input_file: Path = SOURCETLD_FILE, output_file: Path = TLDS_FILE) -> int:
    processed_lines = set()
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip().lower()
            if (not line or
                line.startswith('//') or
                line.startswith('#') or
                line.startswith('!')):
                continue
            if line.startswith('*.'):
                line = line[2:]
            if re.search(r'[^a-z0-9_.-]', line):
                continue
            line = line.lstrip('.')
            if not line.startswith('.'):
                line = '.' + line
            processed_lines.add(line)
    with open(output_file, 'w', encoding='utf-8') as f:
        for line in sorted(processed_lines):
            f.write(line + '\n')
    return len(processed_lines)

def generate_tlds(verify_ssl: bool = True):
    # Check if tlds.txt already exists
    if TLDS_FILE.exists() and TLDS_FILE.stat().st_size > 0:
        count = sum(1 for _ in TLDS_FILE.open(encoding='utf-8'))
    else:
        SOURCETLD_FILE.write_text("")
        urls = [
            'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
            'https://raw.githubusercontent.com/maravento/blackweb/refs/heads/master/bwupdate/lst/tldsappx.txt',
            'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat',
            'https://www.whoisxmlapi.com/support/supported_tlds.php?ts=gp',
        ]
        count = 0
        try:
            for url in urls:
                download_public_suffix(url, SOURCETLD_FILE, verify_ssl)
            count = process_tlds_file()
        finally:
            if SOURCETLD_FILE.exists():
                SOURCETLD_FILE.unlink()

    if not TLDS_FILE.exists() or TLDS_FILE.stat().st_size == 0:
        sys.exit("ERROR: tlds.txt is empty. All TLD sources failed to download.")

    if count < MIN_TLD_COUNT:
        sys.exit(
            f"ERROR: only {count} TLDs were collected (expected at least "
            f"{MIN_TLD_COUNT}). One or more TLD sources likely failed to "
            f"download; check connectivity and retry."
        )

# DOMAINS FILTER
def should_keep_domain(domain: str, valid_domains: set, tlds: set) -> bool:
    clean_domain = domain.lstrip('.')  # Remove the dot at the beginning, if it has one
    partial = ''
    tld = ''
    found = False
    for part in reversed(clean_domain.split('.')):
        partial = '.' + part + partial
        if partial in tlds:
            found = True
            tld = partial

    if not found or tld == domain:
        return False

    partial = ''
    for part in reversed(clean_domain[:-len(tld)].split(".")):
        partial = '.' + part + partial

        if partial + tld in valid_domains:
            return False

    return True

def load_tlds(tlds_file) -> set:
    try:
        with open(tlds_file, 'r', encoding='utf-8') as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        sys.exit(f"ERROR: TLD file '{tlds_file}' not found.")

def load_capture(capture_file) -> list:
    try:
        with open(capture_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        sys.exit(f"ERROR: input file '{capture_file}' not found.")

# Normalize input to a temporary copy (leaves the user's original file untouched)
def add_dot_if_missing(filename: str) -> str:
    with open(filename, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    fd, tmp_path = tempfile.mkstemp(prefix="domfilter_", suffix=".tmp")
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if not line.startswith('.'):
                line = '.' + line
            file.write(line + '\n')
    return tmp_path


def process_domains(input_file: str, tlds: set, output_file: str = None, removed_file: str = None):
    domains = load_capture(input_file)
    valid_domains = set()
    other_domains = set()

    domains.sort(key=lambda domain: len(domain))

    for domain in domains:
        if should_keep_domain(domain, valid_domains, tlds):
            valid_domains.add(domain)
        else:
            other_domains.add(domain)

    with open(output_file, 'w', encoding='utf-8') if output_file else sys.stdout as output:
        content = "\n".join(sorted(valid_domains))
        output.write(content + "\n" if content else "")

    with open(removed_file, 'w', encoding='utf-8') if removed_file else sys.stderr as output:
        content = "\n".join(sorted(other_domains))
        output.write(content + "\n" if content else "")

# MAIN
def main():
    parser = argparse.ArgumentParser(description="Generate TLD list and filter domains.")
    parser.add_argument('--input', required=False, default=None, help="Path to the capture file.")
    parser.add_argument('--output', help="Path to the output file (optional).", default="output.txt", type=str)
    parser.add_argument('--removed', help="Path to the output file for removed domains (optional).", default="removed.txt", type=str)
    parser.add_argument('--no-verify-ssl', action='store_true', help="Disable SSL verification when downloading TLD sources (not recommended).")
    args = parser.parse_args()

    if not args.input:
        print("WARNING: --input is required. Usage: domfilter.py --input <file>")
        sys.exit(1)

    verify_ssl = not args.no_verify_ssl
    if not verify_ssl:
        warnings.simplefilter('ignore', InsecureRequestWarning)
        print("WARNING: SSL verification disabled for TLD downloads.")

    # add .dot (operates on a temp copy, original input file is never modified)
    tmp_input = add_dot_if_missing(args.input)
    try:
        # generate tlds.txt
        generate_tlds(verify_ssl)

        # Load TLDs and process domains
        tlds = load_tlds(TLDS_FILE)

        process_domains(tmp_input, tlds, args.output, args.removed)
    finally:
        os.remove(tmp_input)

if __name__ == "__main__":
    main()
