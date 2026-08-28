#!/bin/bash
# maravento.com
#
################################################################################
#
# Check Sources
# Download and search Blackweb source lists for a domain
#
# NOTE on logging:
# - Writes to checksources.log (append-only, no rotation configured by
#   this script). Set up logrotate for this file if disk usage matters.
# - To clear it manually: truncate -s 0 checksources.log
#
################################################################################

set -uo pipefail

# logging
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$SCRIPT_DIR/checksources.log"
log() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" | tee -a "$log_file" 2>/dev/null || true
}

# check no-root
if [ "$(id -u)" == "0" ]; then
    log "ERROR: This script should not be run as root -- abort"
    exit 1
fi

# prevent overlapping runs
SCRIPT_LOCK="/var/lock/$(basename "$0" .sh).lock"
exec 200>"$SCRIPT_LOCK"
if ! flock -n 200; then
    log "ERROR: script $(basename "$0") is already running -- abort"
    exit 1
fi

# DEPENDENCIES
for dep in wget tar util-linux; do
    if ! dpkg -s "$dep" &>/dev/null; then
        log "ERROR: dependency '$dep' is not installed -- abort"
        exit 1
    fi
done

log "checksources start..."

# CHECK INTERNET
check_internet() {
    local max_attempts="${1:-24}" attempt=1

    while (( attempt <= max_attempts )); do
        if getent hosts www.google.com >/dev/null 2>&1; then
            log "INFO: internet is available"
            return 0
        fi
        log "INFO: waiting for internet ($attempt/$max_attempts)"
        attempt=$((attempt + 1))
        sleep 5
    done

    return 1
}

if ! check_internet; then
    log "ERROR: no internet connection -- abort"
    exit 1
fi

wgetd='wget -q -c --show-progress --no-check-certificate --retry-connrefused --timeout=10 --tries=4'

# Temporary working directory
if [ -d downloaded_lists ] && [ -n "$(ls -A downloaded_lists 2>/dev/null)" ]; then
    echo
    echo "=== Check Sources ==="
    echo "[?] Existing downloaded lists found."
    echo "    1) Search only (reuse existing lists)"
    echo "    2) Re-download all lists"
    echo "    3) Exit"
    read -p "Choose an option [1/2/3]: " menu_opt
    echo
    if [[ "$menu_opt" == "3" ]]; then
        log "[!] Cancelled by user. Exiting."
        exit 0
    elif [[ "$menu_opt" == "2" ]]; then
        rm -rf downloaded_lists >/dev/null 2>&1
        mkdir -p downloaded_lists
    elif [[ "$menu_opt" != "1" ]]; then
        log "ERROR: Invalid option."
        exit 1
    fi
else
    rm -rf downloaded_lists >/dev/null 2>&1
    mkdir -p downloaded_lists
fi

if [[ "$menu_opt" != "1" ]]; then
    # Download bwupdate.sh
    log "[*] Downloading source list..."
    $wgetd -O downloaded_lists/bwupdate_src.sh https://raw.githubusercontent.com/maravento/blackweb/refs/heads/master/bwupdate/bwupdate.sh

    # Extract URLs from # SOURCES block
    log "[*] Extracting URLs..."
    sed -n '/# SOURCES/,/# END_SOURCES/p' downloaded_lists/bwupdate_src.sh | \
    grep -E "^[[:space:]]*blurls '" | \
    sed -E "s/^.*blurls '//; s/' && sleep 1.*$//" > urls.txt

    # Manually add special tar.gz URL
    echo "http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz" >> urls.txt

    # Download each list
    log "[*] Downloading lists..."
    while IFS= read -r url; do
        filename=$(echo "$url" | sed -E 's~https?://~~; s~/~-~g')
        log "[+] Downloading: $filename"
        if ! $wgetd -O "downloaded_lists/$filename" "$url"; then
            log "[!] Download failed, skipping: $url"
            continue
        fi

        # If it's a .tar.gz file, extract it into its own subfolder
        if [[ "$filename" == *.tar.gz ]]; then
            log "[*] Extracting: $filename"
            extract_dir="downloaded_lists/${filename%.tar.gz}_extracted"
            mkdir -p "$extract_dir"
            if tar -xzf "downloaded_lists/$filename" -C "$extract_dir"; then
                rm -f "downloaded_lists/$filename"
            else
                log "[!] Extraction failed, keeping: $filename"
            fi
        fi
    done < urls.txt
fi

echo
# Ask for domain (retry on empty/invalid input instead of discarding the downloads)
while true; do
    read -p "[?] Enter domain to search, or 'q' to quit (e.g: kickass.to): " domain
    echo
    if [[ "$domain" == "q" ]]; then
        log "[!] Cancelled by user. Exiting."
        exit 0
    fi
    if [[ -z "$domain" ]]; then
        log "[!] No domain entered. Try again."
        continue
    fi
    if ! echo "$domain" | grep -qP '^[a-zA-Z0-9._-]+$'; then
        log "[!] Invalid domain format. Try again."
        continue
    fi
    break
done

# Search for domain in all files
log "[*] Searching for '$domain'..."
found=0
while IFS= read -r url; do
    filename=$(echo "$url" | sed -E 's~https?://~~; s~/~-~g')
    if [[ "$filename" == *.tar.gz ]]; then
        extract_dir="downloaded_lists/${filename%.tar.gz}_extracted"
        if [ -d "$extract_dir" ] && grep -rqiE "^${domain}$" "$extract_dir" 2>/dev/null; then
            log "[+] Domain found in: $url (extracted)"
            found=1
        fi
    else
        if grep -qiE "^${domain}$" "downloaded_lists/$filename" 2>/dev/null; then
            log "[+] Domain found in: $url"
            found=1
        fi
    fi
done < urls.txt

if [[ $found -eq 0 ]]; then
    log "[!] Domain not found."
fi

log "checksources done at: $(date)"
