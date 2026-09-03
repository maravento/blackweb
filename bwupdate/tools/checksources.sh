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

# ------------------------------------------------------------------------------
# REQUIREMENTS
# ------------------------------------------------------------------------------

# logging
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$script_dir/checksources.log"
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$log_file" 2>/dev/null || true
}

# check no-root
if [ "$(id -u)" == "0" ]; then
    log "ERROR: This script should not be run as root -- abort"
    exit 1
fi

# prevent overlapping runs
script_lock="/var/lock/$(basename "$0" .sh).lock"
exec 200>"$script_lock"
if ! flock -n 200; then
    log "ERROR: script $(basename "$0") is already running -- abort"
    exit 1
fi

# dependencies
for dep_pkg in wget tar util-linux; do
    if ! dpkg -s "$dep_pkg" &>/dev/null; then
        log "ERROR: '$dep_pkg' is not installed -- abort"
        exit 1
    fi
done

# check internet
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

log "checksources start..."

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

wget_opts='wget -q -c --show-progress --no-check-certificate --retry-connrefused --timeout=10 --tries=4'

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

download_lists() {
    rm -rf downloaded_lists >/dev/null 2>&1
    mkdir -p downloaded_lists/lists

    log "[*] Downloading source list..."
    $wget_opts -O downloaded_lists/bwupdate_src.sh https://raw.githubusercontent.com/maravento/blackweb/refs/heads/master/bwupdate/bwupdate.sh

    log "[*] Extracting URLs..."
    sed -n '/# SOURCES_START/,/# SOURCES_END/p' downloaded_lists/bwupdate_src.sh | \
    grep -E "^[[:space:]]*blurls '" | \
    sed -E "s/^.*blurls '//; s/' && sleep 1.*$//" > downloaded_lists/urls.txt

    echo "http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz" >> downloaded_lists/urls.txt

    log "[*] Downloading lists..."
    while IFS= read -r source_url; do
        download_file=$(echo "$source_url" | sed -E 's~https?://~~; s~/~-~g')
        log "[+] Downloading: $download_file"
        if ! $wget_opts -O "downloaded_lists/lists/$download_file" "$source_url"; then
            log "[!] Download failed, skipping: $source_url"
            continue
        fi

        if [[ "$download_file" == *.tar.gz ]]; then
            log "[*] Extracting: $download_file"
            extract_dir="downloaded_lists/lists/${download_file%.tar.gz}_extracted"
            mkdir -p "$extract_dir"
            if tar -xzf "downloaded_lists/lists/$download_file" -C "$extract_dir"; then
                rm -f "downloaded_lists/lists/$download_file"
            else
                log "[!] Extraction failed, keeping: $download_file"
            fi
        fi
    done < downloaded_lists/urls.txt
}

search_lists() {
    while true; do
        read -r -p "[?] Enter domain to search, or 'q' to quit (e.g: kickass.to): " search_domain
        echo
        if [[ "$search_domain" == "q" ]] || [[ -z "$search_domain" ]]; then
            return 0
        fi
        if ! echo "$search_domain" | grep -qP '^[a-zA-Z0-9._-]+$'; then
            log "[!] Invalid domain format. Try again."
            continue
        fi
        break
    done

    log "[*] Searching for '$search_domain'..."
    domain_found=0
    while IFS= read -r source_url; do
        download_file=$(echo "$source_url" | sed -E 's~https?://~~; s~/~-~g')
        if [[ "$download_file" == *.tar.gz ]]; then
            extract_dir="downloaded_lists/lists/${download_file%.tar.gz}_extracted"
            if [ -d "$extract_dir" ] && grep -rqiE "^${search_domain}$" "$extract_dir" 2>/dev/null; then
                log "[+] Domain found in: $source_url (extracted)"
                domain_found=1
            fi
        else
            if grep -qiE "^${search_domain}$" "downloaded_lists/lists/$download_file" 2>/dev/null; then
                log "[+] Domain found in: $source_url"
                domain_found=1
            fi
        fi
    done < downloaded_lists/urls.txt

    if [[ $domain_found -eq 0 ]]; then
        log "[!] Domain not found."
    fi

    echo
    read -r -p "Press Enter to return to the menu... "
}

if [ ! -d downloaded_lists/lists ] || [ -z "$(ls -A downloaded_lists/lists 2>/dev/null)" ]; then
    download_lists
fi

while true; do
    echo
    echo "=== Check Sources ==="
    echo "    1) Search domain"
    echo "    2) Download all lists again"
    echo "    3) Exit"
    read -r -p "Choose an option [1/2/3]: " menu_opt
    echo
    case "$menu_opt" in
        1) search_lists ;;
        2) download_lists ;;
        3) log "[!] Cancelled by user. Exiting."
           break ;;
        "") ;;
        *) log "ERROR: Invalid option." ;;
    esac
done

# ------------------------------------------------------------------------------
# END
# ------------------------------------------------------------------------------

log "checksources done at: $(date)"
