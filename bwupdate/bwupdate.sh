#!/usr/bin/env bash
# shellcheck disable=SC2086,SC2046,SC2016,SC2001,SC2004,SC2154,SC2039,SC2145,SC2059

# Script Name: Blackweb Project Updater
# Description: This script downloads and updates blacklists for Squid proxy server.
# Language: spa-eng

# Translation Arrays (English and Spanish)
declare -a bw01=("This process can take. Be patient..." "Este proceso puede tardar. Sea paciente...")
declare -a bw02=("Downloading Blackweb..." "Descargando Blackweb...")
declare -a bw03=("Downloading Blocklists..." "Descargando Listas de Bloqueo...")
declare -a bw04=("Downloading Allowlist..." "Descargando Listas de Permitidos...")
declare -a bw05=("Capturing Domains..." "Capturando Dominios...")
declare -a bw06=("Joining Lists..." "Uniendo Listas...")
declare -a bw07=("Debugging Domains..." "Depurando Dominios...")
declare -a bw08=("Debugging Punycode-IDN..." "Depurando Punycode-IDN...")
declare -a bw09=("1st DNS Loockup..." "1ra Busqueda DNS...")
declare -a bw10=("2nd DNS Loockup..." "2da Busqueda DNS...")
declare -a bw11=("Adding Debug Blacklist..." "Agregando Debug Blacklist...")
declare -a bw12=("Exclude TLD..." "Excluir TLD...")
declare -a bw13=("Restarting Squid..." "Reiniciando Squid...")
declare -a bw14=("Check on your desktop Squid-Error.txt" "Verifique en su escritorio Squid-Error.txt")

# Determine Language (English or Spanish)
if [[ "${LANG:0:2}" == "en" ]]; then
  en=0 # English index
else
  en=1 # Spanish index
fi

# Dependency Check Function
check_dependencies() {
  local missing_pkgs=""
  for pkg in wget git curl libnotify-bin perl tar rar unrar unzip zip gzip python3 idn2 iconv; do # python-is-python3 replaced by python3
    if ! command -v "$pkg" &>/dev/null; then
      missing_pkgs+="$pkg "
    fi
  done

  if [[ -n "$missing_pkgs" ]]; then
    echo "Error: The following dependencies are missing: $missing_pkgs"
    echo "Please install them before running this script."
    exit 1
  fi
}

# Download File Function with Error Handling
download_file() {
  local url="$1"
  local output="$2"
  wget -q -c --show-progress --no-check-certificate --retry-connrefused --timeout=10 --tries=4 "$url" -O "$output"
  if [[ $? -ne 0 ]]; then
    echo "Error: Failed to download $url"
    return 1
  fi
  return 0
}

# Download and Extract Tarball Function
download_and_extract() {
  local url="$1"
  local target_dir="$2"
  local filename=$(basename "$url")
  local download_path="bwtmp/$filename"

  if ! download_file "$url" "$download_path"; then
    echo "Error: Failed to download $url"
    return 1
  fi

  mkdir -p "$target_dir"
  tar -C "$target_dir" -zxvf "$download_path" &>/dev/null
  if [[ $? -ne 0 ]]; then
    echo "Error: Failed to extract $filename"
    return 1
  fi
  rm -f "$download_path"
  return 0
}

# Capture domains from a file
capture_domains() {
    local input_file="$1"
    grep -oiE "$regexd" "$input_file"
}

# Main Script
check_dependencies

# Variables
bwupdate="$(pwd)/bwupdate"
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
xdesktop=$(xdg-user-dir DESKTOP)
route="/etc/acl"

# Create Directory
sudo mkdir -p "$route"

clear
echo
echo "Blackweb Project"
echo "${bw01[$en]}"

# Clone or Update Blackweb Repository
if [ ! -d "$bwupdate" ]; then
  echo "${bw02[$en]}"
  mkdir -p "$bwupdate"
  cd "$bwupdate" || exit 1
  git clone https://github.com/maravento/blackweb.git .
  if [ $? -ne 0 ]; then
    echo "Error: Failed to clone Blackweb repository"
    exit 1
  fi
else
  echo "Updating Blackweb..."
  cd "$bwupdate" || exit 1
  git pull origin master
  if [ $? -ne 0 ]; then
    echo "Error: Failed to update Blackweb repository"
  fi
fi

# Create Temporary Directory
mkdir -p bwtmp

# Download Blocklists
echo "${bw03[$en]}"

# Function to download blocklist URLs
blurls() {
  local url="$1"
  local filename=$(echo "$url" | awk -F/ '{print $NF}' | sed 's/[^a-zA-Z0-9._-]/_/g')
  local output="bwtmp/$filename"

  if download_file "$url" "$output"; then
    echo "Downloaded: $url"
  else
    echo "ERROR: $url"
  fi
}

# List of blocklist URLs
declare -a blocklist_urls=(
'https://adaway.org/hosts.txt'
'https://adblock.gardar.net/is.abp.txt'
'https://bitbucket.org/ethanr/dns-blacklists/raw/master/bad_lists/Mandiant_APT1_Report_Appendix_D.txt'
'https://easylist-downloads.adblockplus.org/advblock.txt'
'https://easylist-downloads.adblockplus.org/antiadblockfilters.txt'
'https://easylist-downloads.adblockplus.org/easylistchina.txt'
'https://easylist-downloads.adblockplus.org/easylistlithuania+easylist.txt'
'https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw/77eee956303e8d6ff2f4df61d3e2c0b60d023268/MS-2'
'https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt'
'https://github.com/WaLLy3K/notrack/raw/master/malicious-sites.txt'
'https://gitlab.com/malware-filter/urlhaus-filter/-/raw/master/urlhaus-filter.txt'
'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt'
'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt'
'https://hblock.molinero.dev/hosts_domains.txt'
'https://hole.cert.pl/domains/domains.txt'
'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt'
'https://hostsfile.mine.nu/hosts0.txt'
'https://hostsfile.org/Downloads/hosts.txt'
'https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt'
'https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt'
'https://openphish.com/feed.txt'
'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt'
'https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt'
'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml'
'https://phishing.army/download/phishing_army_blocklist_extended.txt'
'https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt'
'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt'
'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt'
'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts'
'https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt'
'https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt'
'https://raw.githubusercontent.com/BBcan177/minerchk/master/hostslist.txt'
'https://raw.githubusercontent.com/BBcan177/referrer-spam-blacklist/master/spammers.txt'
'https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt'
'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts'
'https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt'
'https://raw.githubusercontent.com/BlackJack8/webannoyances/master/ultralist.txt'
'https://raw.githubusercontent.com/blocklistproject/Lists/master/everything.txt'
'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list'
'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list'
'https://raw.githubusercontent.com/chainapsis/phishing-block-list/main/block-list.txt'
'https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt'
'https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/GHHbD_perma_ban_list.txt'
'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt'
'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/dom-bl.txt'
'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt'
'https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt'
'https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt'
'https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt'
'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts'
'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts'
'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts'
'https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt'
'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt'
'https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt'
'https://raw.githubusercontent.com/HexxiumCreations/threat-list/gh-pages/hexxiumthreatlist.txt'
'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt'
'https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv'
'https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts'
'https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv'
'https://raw.githubusercontent.com/liamja/Prebake/master/obtrusive.txt'
'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt'
'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/domains'
'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list'
'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list'
'https://raw.githubusercontent.com/NanoAdblocker/NanoFilters/master/NanoFilters/NanoBase.txt'
'https://raw.githubusercontent.com/neodevpro/neodevhost/master/domain'
'https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt'
'https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf'
'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt'
'https://raw.githubusercontent.com/piperun/iploggerfilter/master/filterlist'
'https://raw.githubusercontent.com/quedlin/blacklist/master/domains'
'https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt'
'https://raw.githubusercontent.com/Rpsl/adblock-leadgenerator-list/master/list/list.txt'
'https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat'
'https://raw.githubusercontent.com/ryanbr/fanboy-adblock/master/fake-news.txt'
'https://raw.githubusercontent.com/sayomelu/nothingblock/master/filter.txt'
'https://raw.githubusercontent.com/scamaNet/blocklist/main/blocklist.txt'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Adult'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Cryptocurrency'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Dating'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Gambling'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Risk'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Scam'
'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/UrlShortener'
'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts'
'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts'
'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts'
'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts'
'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts'
'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
'https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt'
'https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list'
'https://raw.githubusercontent.com/txthinking/bypass/master/china_domain.txt'
'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0'
'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts1'
'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts2'
'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts3'
'https://raw.githubusercontent.com/vokins/yhosts/master/hosts'
'https://raw.githubusercontent.com/yourduskquibbles/webannoyances/master/ultralist.txt'
'https://raw.githubusercontent.com/yous/YousList/master/youslist.txt'
'https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts'
'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt'
'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt'
'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt'
'https://someonewhocares.org/hosts/hosts'
'https://sysctl.org/cameleon/hosts'
'http://stanev.org/abp/adblock_bg.txt'
'https://v.firebog.net/hosts/AdguardDNS.txt'
'https://v.firebog.net/hosts/Admiral.txt'
'https://v.firebog.net/hosts/Easylist.txt'
'https://v.firebog.net/hosts/Easyprivacy.txt'
'https://v.firebog.net/hosts/Kowabit.txt'
'https://v.firebog.net/hosts/neohostsbasic.txt'
'https://v.firebog.net/hosts/Prigent-Ads.txt'
'https://v.firebog.net/hosts/Prigent-Crypto.txt'
'https://v.firebog.net/hosts/Prigent-Malware.txt'
'https://v.firebog.net/hosts/RPiList-Malware.txt'
'https://v.firebog.net/hosts/static/w3kbl.txt'
'https://winhelp2002.mvps.org/hosts.txt'
'https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt'
'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt'
'https://www.taz.net.au/Mail/SpamDomains'
'https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt'
'https://zerodot1.gitlab.io/CoinBlockerLists/list_optional.txt'
'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt'
'https://zoso.ro/pages/rolist.txt'
'https://raw.githubusercontent.com/eallion/uBlacklist-subscription-compilation/refs/heads/main/uBlacklist.txt'
)

# Loop through URLs and download them
for url in "${blocklist_urls[@]}"; do
  blurls "$url" &
  sleep 1
done
wait

echo "OK"

# Download Big Blocklists
echo "Downloading big blocklists..."

# Downloading DSI and UT-Capitole blacklists
if ! download_and_extract 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' bwtmp && \
   ! download_and_extract 'ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/blacklists.tar.gz' bwtmp; then
  echo "ut-capitole.fr download failed. Switching to alt repo..."
  cd bwtmp
  download_file https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolderdl.py gitfolderdl.py
  chmod +x gitfolderdl.py
  python gitfolderdl.py "https://github.com/olbat/ut1-blacklists/tree/master/blacklists"
  rm gitfolderdl.py
  find . -type f -name "*.gz" -print0 | while IFS= read -r -d $'\0' gzfile; do
    gunzip "$gzfile"
    if [ $? -ne 0 ]; then
      echo "Error unzipping: $gzfile"
    fi
  done
  cd ..
fi

# Downloading Folder
cd bwtmp
download_file https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolderdl.py gitfolderdl.py
chmod +x gitfolderdl.py
python gitfolderdl.py "https://github.com/pengelana/blocklist/tree/master/src/blacklist"
rm gitfolderdl.py
cd ..
echo "OK"

# Download Allowlist URLs
echo "${bw04[$en]}"

# Download world_universities_and_domains
univ() {
  local url="$1"
  if curl -k -X GET --connect-timeout 10 --retry 1 -I "$url" &>/dev/null; then
    download_file "$url" - | grep -oiE "$regexd" | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u >> lst/controlwl.txt
  else
    echo "ERROR: $url"
  fi
}
mkdir -p lst
univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json'
echo "OK"

# Capturing Domains
echo "${bw05[$en]}"

# Capturing
find bwtmp -type f -not -iname "*pdf" -execdir grep -oiE "$regexd" {} \; > cap1
piconv -f cp1252 -t UTF-8 <cap1 > cap2
iconv -f UTF-8 -t WINDOWS-1252 cap2 > cap3
sed -r 's:(^\.*?(www|ftp|ftps|ftpes|sftp|pop|pop3|smtp|imap|http|https)[^.]*?\.|^\.\.?)::gi' cap3 | sed -r '/[^a-zA-Z0-9.-]/d; /^[^a-zA-Z0-9.]/d; /[^a-zA-Z0-9]$/d; /^[[:space:]]*$/d; /[[:space:]]/d; /^[[:space:]]*#/d; /[^[:print:]]/d; /\.{2,}/d' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > capture.txt
echo "OK"

# Join and Update List
echo "${bw06[$en]}"
sed '/^$/d; /#/d' lst/{controlwl,invalid}.txt | sed 's/[^[:print:]\n]//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > urls.txt
echo "OK"

# Debugging Domains
echo "${bw07[$en]}"
grep -Fvxf urls.txt capture.txt | sed 's/[^[:print:]\n]//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > cleancapture.txt
download_file https://raw.githubusercontent.com/maravento/vault/master/dofi/domfilter.py domfilter.py
python domfilter.py --input cleancapture.txt
grep -Fvxf urls.txt output.txt | grep -P "^[\x00-\x7F]+$" | sort -u > outparse
echo "OK"

# Debugging IDN
echo "${bw08[$en]}"
sed '/[^.]\{64\}/d' outparse | grep -vP '[A-Z]' | grep -vP '(^|\.)-|-($|\.)' | sed 's/^\.//g' | sort -u > idnlst
{ LC_ALL=C grep -v '[^[:print:]]' idnlst ; grep -P "[^[:ascii:]]" idnlst | idn2 ; } | sort -u > finalclean
echo "OK"

# DNS Lookup - Split into functions to improve readability and maintainability.
dns_lookup() {
    local input_file="$1"
    local output_file="$2"
    local temp_file="temp_dns_lookup_$RANDOM"

    # Remove existing temp file
    rm -f "$temp_file"

    echo "Starting DNS lookup for $input_file..."
    sed 's/^\.//g' "$input_file" | sort -u > step

    if [ -s "$output_file" ]; then
        awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' "$output_file" step |
            xargs -I {} -P "$pp" sh -c "if host {} >/dev/null 2>&1; then echo HIT {}; else echo FAULT {}; fi" >> "$temp_file"
    else
        cat step |
            xargs -I {} -P "$pp" sh -c "if host {} >/dev/null 2>&1; then echo HIT {}; else echo FAULT {}; fi" >> "$temp_file"
    fi

    sed '/^FAULT/d' "$temp_file" | awk '{print $2}' | awk '{print "." $1}' | sort -u > hit_temp
    sed '/^HIT/d' "$temp_file" | awk '{print $2}' | awk '{print "." $1}' | sort -u > fault_temp

    # Append hit to hit.txt and fault to fault.txt
    sort -u -m hit_temp hit.txt -o hit.txt
    sort -u -m fault_temp fault.txt -o fault.txt

    # Clean up temporary files
    rm -f hit_temp fault_temp "$temp_file" step

    echo "DNS lookup completed for $input_file."
}

# Perform the first DNS lookup
if [ ! -e "$bwupdate"/dnslookup2 ]; then
    echo "${bw09[$en]}"
    dns_lookup "finalclean" "dnslookup1"
    echo "OK"
fi

sleep 10

# Perform the second DNS lookup
echo "${bw10[$en]}"
dns_lookup "fault.txt" "dnslookup2"
echo "OK"

# Debug Blacklist
echo "${bw11[$en]}"
sed '/^$/d; /#/d' lst/controlbl.txt | sort -u >> hit.txt

# Clean hit
grep -vi -f <(sed 's:^\(.*\)$:.\\\1\$:' lst/controlbl.txt) hit.txt | sed -r '/[^a-z0-9.-]/d' | sort -u > blackweb_tmp

# TLD Final Filter
echo "${bw12[$en]}"
regex_ext=$(grep -v '^#' lst/allowtlds.txt | sed 's/$/\$/' | tr '\n' '|')
new_regex_ext="${regex_ext%|}"

# Apply TLD filter
grep -E -v "$new_regex_ext" blackweb_tmp | grep -P "^[\x00-\x7F]+$" | sort -u > blackweb_tmp2

# Compare against tlds.txt
comm -23 <(sort blackweb_tmp2) <(sort tlds.txt) > blackweb.txt

echo "OK"

# Reload Squid-Cache
echo "${bw13[$en]}"

# Copy blackweb to path
sudo cp -f blackweb.txt "$route"/blackweb.txt

# Squid Reload
sudo squid -k reconfigure 2>sqerror
sleep 20
sudo grep "$(date +%Y/%m/%d)" /var/log/squid/cache.log | sed -r "/\.(log|conf|crl|js|state)/d" | grep -oiE "$regexd" >> sqerror
sort -o sqerror -u sqerror
python tools/debugerror.py
sort -o final -u final
mv -f final blackweb.txt
sudo cp -f blackweb.txt "$route"/blackweb.txt
sudo squid -k reconfigure 2>"$xdesktop"/SquidErrors.txt

# Clean up
cd ..
rm -rf "$bwupdate"

# End Message
sudo bash -c 'echo "BlackWeb Done: $(date)" | tee -a /var/log/syslog'
echo "${bw14[$en]}"

exit 0
