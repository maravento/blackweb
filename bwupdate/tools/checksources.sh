#!/bin/bash
# maravento.com
#
################################################################################
#
# Check Sources
# Download and search Blackweb source lists for a domain
#
################################################################################

echo "Checking sources for domain matches. Wait..."
printf "\n"

wgetd='wget -q -c --show-progress --no-check-certificate --retry-connrefused --timeout=10 --tries=4'

# Temporary working directory
mkdir -p downloaded_lists

# Download bwupdate.sh
echo "[*] Downloading source list..."
$wgetd -O bwupdate.sh https://raw.githubusercontent.com/maravento/blackweb/refs/heads/master/bwupdate/bwupdate.sh

# Extract URLs from # SOURCES block
echo "[*] Extracting URLs..."
sed -n '/# SOURCES/,/# END_SOURCES/p' bwupdate.sh | \
grep -E "blurls '" | \
sed -E "s/^.*blurls '//; s/' && sleep 1.*$//" > urls.txt

# Manually add special tar.gz URL
echo "http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz" >> urls.txt

# Download each list
echo "[*] Downloading lists..."
while IFS= read -r url; do
    filename=$(echo "$url" | sed -E 's~https?://~~; s~/~-~g')
    echo "[+] Downloading: $filename"
    if ! $wgetd -O "downloaded_lists/$filename" "$url"; then
        echo "[!] Download failed, skipping: $url"
        continue
    fi

    # If it's a .tar.gz file, extract it
    if [[ "$filename" == *.tar.gz ]]; then
        echo "[*] Extracting: $filename"
        if tar -xzf "downloaded_lists/$filename" -C downloaded_lists/; then
            rm -rf "downloaded_lists/$filename"
        else
            echo "[!] Extraction failed, keeping: $filename"
        fi
    fi
done < urls.txt

clear
echo
# Ask for domain
read -p "[?] Enter domain to search (e.g: kickass.to): " domain
echo

if [[ -z "$domain" ]]; then
    echo "[!] No domain entered. Exiting."
    exit 1
fi

if ! echo "$domain" | grep -qP '^[a-zA-Z0-9._-]+$'; then
    echo "[!] Invalid domain format. Exiting."
    exit 1
fi

# Search for domain in all files
echo "[*] Searching for '$domain'..."
found=0
while IFS= read -r url; do
    filename=$(echo "$url" | sed -E 's~https?://~~; s~/~-~g')
    if grep -qiF "$domain" "downloaded_lists/$filename"; then
        echo "[+] Domain found in: $url"
        found=1
    fi
done < urls.txt

if [[ $found -eq 0 ]]; then
    echo "[!] Domain not found."
fi

echo Done
