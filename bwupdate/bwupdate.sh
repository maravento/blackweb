#!/bin/bash
# maravento.com
#
################################################################################
#
# BlackWeb Update
# FILE: bwupdate/bwupdate.sh
#
# USAGE:
# ./bwupdate.sh
#
# LOG: bwupdate.log, in the directory where this script is located
#      Emptied at the start of every run, holds the last execution only
#
################################################################################

set -uo pipefail

# ------------------------------------------------------------------------------
# REQUIREMENTS
# ------------------------------------------------------------------------------

# no-root check
if [ "$(id -u)" == "0" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: This script should not be run as root -abort" >&2
    exit 1
fi

# prevent overlapping runs
script_lock="/var/lock/$(basename "$0" .sh).lock"
(umask 077; : >> "$script_lock") || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: cannot open $(basename "$script_lock") -abort" >&2
    exit 1
}
exec 200>"$script_lock"
if ! flock -n 200; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: script $(basename "$0") is already running -abort" >&2
    exit 1
fi

# logging
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$script_dir/bwupdate.log"
{ > "$log_file"; } 2>/dev/null || true
log() {
    local log_msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$log_msg" >> "$log_file" 2>/dev/null || true
    if [[ "$1" == ERROR:* ]]; then
        echo "$log_msg" >&2
    else
        echo "$log_msg"
    fi
}

# Function: Report whether a package is installed, not merely residual
package_installed() {
    [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" = installed ]
}

# dependencies
for dep_pkg in wget curl tar gzip idn2 python3 bind9-host findutils grep sed coreutils python3-requests util-linux file libc-bin sudo iproute2; do
    if ! package_installed "$dep_pkg"; then
        log "ERROR: dependency '$dep_pkg' is not installed -abort"
        exit 1
    fi
done

# dependencies (squid or squid-openssl)
if ! package_installed squid && ! package_installed squid-openssl; then
    log "ERROR: 'squid' or 'squid-openssl' is not installed -abort"
    exit 1
fi

# check ipv4 interfaces
list_ifaces() {
    ip -br link show 2>/dev/null | awk '$1 != "lo" {sub(/@.*/, "", $1); printf "%s %s\n", $1, ($2 == "UP") ? "UP" : "DOWN"}'
}

list_ipv4_ifaces() {
    local iface state
    while read -r iface state; do
        [ "$state" = UP ] || continue
        if ip -4 -o addr show dev "$iface" scope global 2>/dev/null \
            | awk '$4 != "" {found=1} END {exit !found}'; then
            printf '%s\n' "$iface"
        fi
    done < <(list_ifaces)
}

check_ipv4_interfaces() {
    local max_attempts=24 attempt=1

    while (( attempt <= max_attempts )); do
        if [ -n "$(list_ipv4_ifaces)" ]; then
            return 0
        fi
        if (( attempt == 1 )); then
            log "INFO: waiting for an interface with IPv4..."
        fi
        attempt=$((attempt + 1))
        sleep 5
    done

    log "ERROR: no interface with IPv4 -abort"
    exit 1
}

# check internet
check_internet() {
    local max_attempts=24 attempt=1

    while (( attempt <= max_attempts )); do
        if getent hosts www.google.com >/dev/null 2>&1; then
            return 0
        fi
        if (( attempt == 1 )); then
            log "INFO: waiting for internet..."
        fi
        attempt=$((attempt + 1))
        sleep 5
    done

    log "ERROR: no internet connection -abort"
    exit 1
}

check_ipv4_interfaces
check_internet

# ------------------------------------------------------------------------------
# CHECKS
# ------------------------------------------------------------------------------

squid_conf="/etc/squid/squid.conf"

# Edit /etc/squid/squid.conf and add lines:
# acl blackweb dstdomain -i "/path_to/blackweb.txt"
# http_access deny blackweb
check_squid_acl() {
    if ! grep -qE '^[[:space:]]*acl[[:space:]]+blackweb[[:space:]]+dstdomain([[:space:]]|$)' "$squid_conf"; then
        log "ERROR: 'acl blackweb dstdomain' not found -abort"
        exit 1
    fi
    if ! grep -qE '^[[:space:]]*http_access[[:space:]]+deny[[:space:]]+blackweb([[:space:]]|$)' "$squid_conf"; then
        log "ERROR: 'http_access deny blackweb' not found -abort"
        exit 1
    fi
}

check_squid_status() {
    squid_is_active() {
        if command -v systemctl &>/dev/null; then
            systemctl is-active --quiet squid
        else
            sudo service squid status &>/dev/null
        fi
    }

    squid_start() {
        if command -v systemctl &>/dev/null; then
            sudo systemctl start squid
        else
            sudo service squid start
        fi
    }

    if ! squid_is_active; then
        log "INFO: squid is not active, starting it"
        squid_start
        for wait_attempt in $(seq 1 30); do
            squid_is_active && break
            sleep 2
        done
        if ! squid_is_active; then
            log "ERROR: squid failed to start -abort"
            exit 1
        fi
        log "INFO: squid was not active, started -fixed"
    fi
}

check_squid_acl
check_squid_status

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

cd "$script_dir" || { log "ERROR: cannot enter bwupdate path -abort"; exit 1; }
repo_dir="$script_dir/bwupdate"
wget_opts="wget -q -c --no-check-certificate --retry-connrefused --timeout=10 --tries=4"
trap 'rm -rf bwtmp urls.txt stage1.txt stage2.txt capture.txt cleancapture.txt output.txt removed.txt blackweb_tmp.txt blackweb_tmp2.txt sqerror.txt final.txt gitfolder.py domfilter.py sourcetld.txt; exit 130' INT TERM
# path to acl (change it to the directory of your preference)
acl_dir="/etc/acl"
if [ ! -d "$acl_dir" ]; then
    sudo mkdir -p -m 755 -- "$acl_dir" || {
        log "ERROR: cannot create $(basename "$acl_dir") -abort"
        exit 1
    }
fi

log "EVENT: bwupdate start..."

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

# check dnslookup1.txt
if [ ! -e "$repo_dir"/dnslookup1.txt ]; then

    # delete old repository
    rm -rf "$repo_dir" >/dev/null 2>&1

    # download blackweb
    $wget_opts https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolder.py -O gitfolder.py || {
        log "PARTIAL: https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolder.py"
        exit 1
    }
    log "SAVED: gitfolder.py"
    chmod +x gitfolder.py
    python3 gitfolder.py https://github.com/maravento/blackweb/bwupdate || {
        log "ERROR: gitfolder.py failed to clone bwupdate -abort"
        exit 1
    }
    python3 gitfolder.py https://github.com/maravento/blackweb/dofi || {
        log "ERROR: gitfolder.py failed to clone dofi -abort"
        exit 1
    }
    rm gitfolder.py &>/dev/null
    if [ -s "$repo_dir/lst/debugwl.txt" ] && [ -s "$repo_dir/lst/allowtlds.txt" ]; then
        cd "$repo_dir" || {
            log "ERROR: cannot enter bwupdate path -abort"
            exit 1
        }
    else
        log "ERROR: gitfolder.py clone failed or incomplete -abort"
        exit 1
    fi
    mkdir -p bwtmp >/dev/null 2>&1 || {
        log "ERROR: cannot create bwtmp -abort"
        exit 1
    }

    # downloading blocklist URLS
    # download files
    blurls() {
        local source_url="$1"
        local download_file target_file name_suffix http_code
        local user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

        download_file=$(basename "${source_url%%\?*}" | sed 's/[^a-zA-Z0-9._-]/_/g')
        target_file="bwtmp/$download_file"

        # incremental suffix
        name_suffix=1
        while [ -e "$target_file" ]; do
            if [[ "$download_file" == *.* ]]; then
                target_file="bwtmp/${download_file%.*}_$name_suffix.${download_file##*.}"
            else
                target_file="bwtmp/${download_file}_$name_suffix"
            fi
            ((name_suffix++))
        done

        # check with curl
        http_code=$(curl -k -s -o /dev/null -w '%{http_code}' -I -L -A "$user_agent" --connect-timeout 5 --max-time 15 --retry 1 "$source_url")
        case "$http_code" in
            2*|405) ;;
            000) log "TIMEOUT: $source_url"; return 1 ;;
            5*)  log "BUSY: $http_code $source_url"; return 1 ;;
            404|410)   log "BROKEN: $http_code $source_url"; return 1 ;;
            *)   log "HTTP_ERROR: $http_code $source_url"; return 1 ;;
        esac

        # download with curl
        if curl -k -L -s \
                --connect-timeout 10 --retry 3 \
                --speed-limit 1024 --speed-time 30 \
                --user-agent "$user_agent" \
                "$source_url" -o "$target_file"; then
            log "SAVED: $(basename "${source_url%%\?*}")"
        else
            log "PARTIAL: $source_url"
            return 1
        fi
    }
    # SOURCES_START
    blurls 'https://adaway.org/hosts.txt' && sleep 1
    blurls 'https://adblock.gardar.net/is.abp.txt' && sleep 1
    blurls 'https://bitbucket.org/ethanr/dns-blacklists/raw/master/bad_lists/Mandiant_APT1_Report_Appendix_D.txt' && sleep 1
    blurls 'https://easylist-downloads.adblockplus.org/advblock.txt' && sleep 1
    blurls 'https://easylist-downloads.adblockplus.org/antiadblockfilters.txt' && sleep 1
    blurls 'https://easylist-downloads.adblockplus.org/easylistchina.txt' && sleep 1
    blurls 'https://easylist-downloads.adblockplus.org/easylistlithuania+easylist.txt' && sleep 1
    blurls 'https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw/77eee956303e8d6ff2f4df61d3e2c0b60d023268/MS-2' && sleep 1
    blurls 'https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt' && sleep 1
    blurls 'https://github.com/WaLLy3K/notrack/raw/master/malicious-sites.txt' && sleep 1
    blurls 'https://gitlab.com/malware-filter/urlhaus-filter/-/raw/master/urlhaus-filter.txt' && sleep 1
    blurls 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt' && sleep 1
    blurls 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt' && sleep 1
    blurls 'https://hblock.molinero.dev/hosts_domains.txt' && sleep 1
    blurls 'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt' && sleep 1
    blurls 'https://hostsfile.mine.nu/hosts0.txt' && sleep 1
    blurls 'https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt' && sleep 1
    blurls 'https://openphish.com/feed.txt' && sleep 1
    blurls 'https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt' && sleep 1
    blurls 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
    blurls 'https://phishing.army/download/phishing_army_blocklist_extended.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/BBcan177/minerchk/master/hostslist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/BBcan177/referrer-spam-blacklist/master/spammers.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/BlackJack8/webannoyances/master/ultralist.txt' && sleep 1
    # blurls 'https://raw.githubusercontent.com/blocklistproject/Lists/master/everything.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/chainapsis/phishing-block-list/main/block-list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/GHHbD_perma_ban_list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/dom-bl.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/eallion/uBlacklist-subscription-compilation/refs/heads/main/uBlacklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/HexxiumCreations/threat-list/gh-pages/hexxiumthreatlist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv' && sleep 1
    blurls 'https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/kaabir/AdBlock_Hosts/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/kevle1/Xiaomi-Telemetry-Blocklist/master/xiaomiblock.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/liamja/Prebake/master/obtrusive.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/domains' && sleep 1
    blurls 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/NanoAdblocker/NanoFilters/master/NanoFilters/NanoBase.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/neodevpro/neodevhost/master/domain' && sleep 1
    blurls 'https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf' && sleep 1
    blurls 'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/piperun/iploggerfilter/master/filterlist' && sleep 1
    blurls 'https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Rpsl/adblock-leadgenerator-list/master/list/list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat' && sleep 1
    blurls 'https://raw.githubusercontent.com/ryanbr/fanboy-adblock/master/fake-news.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/scamaNet/blocklist/main/blocklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Adult' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Cryptocurrency' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Dating' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Gambling' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Malware' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Risk' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Scam' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Shock' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Tracking' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Typo' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/UrlShortener' && sleep 1
    blurls 'https://raw.githubusercontent.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/main/Files/hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/sumatipru/squid-blacklist/refs/heads/master/blacklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/txthinking/bypass/master/china_domain.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts1' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts2' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts3' && sleep 1
    blurls 'https://raw.githubusercontent.com/yourduskquibbles/webannoyances/master/ultralist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/yous/YousList/master/youslist.txt' && sleep 1
    blurls 'https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts' && sleep 1
    blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt' && sleep 1
    blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt' && sleep 1
    blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt' && sleep 1
    blurls 'https://someonewhocares.org/hosts/hosts' && sleep 1
    blurls 'https://sysctl.org/cameleon/hosts' && sleep 1
    blurls 'http://stanev.org/abp/adblock_bg.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/AdguardDNS.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Admiral.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Easylist.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Easyprivacy.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Kowabit.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/neohostsbasic.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Prigent-Ads.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Prigent-Crypto.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/Prigent-Malware.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/RPiList-Malware.txt' && sleep 1
    blurls 'https://v.firebog.net/hosts/static/w3kbl.txt' && sleep 1
    blurls 'https://winhelp2002.mvps.org/hosts.txt' && sleep 1
    blurls 'https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt' && sleep 1
    blurls 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt' && sleep 1
    blurls 'https://zoso.ro/pages/rolist.txt' && sleep 1
    # SOURCES_END

    # downloading big blocklists
    targz() {
        local source_url="$1"
        local download_file extract_dir http_code
        # check with curl
        http_code=$(curl -k -s -o /dev/null -w '%{http_code}' -I -L --connect-timeout 5 --max-time 15 --retry 1 "$source_url")
        case "$http_code" in
            2*|405) ;;
            000) log "TIMEOUT: $source_url"; return 1 ;;
            5*)  log "BUSY: $http_code $source_url"; return 1 ;;
            404|410)   log "BROKEN: $http_code $source_url"; return 1 ;;
            *)   log "HTTP_ERROR: $http_code $source_url"; return 1 ;;
        esac
        # filename clean
        download_file=$(basename "${source_url%%\?*}")
        # download
        if ! $wget_opts "$source_url" -O "bwtmp/$download_file"; then
            log "PARTIAL: $source_url"
            return 1
        fi
        log "SAVED: $download_file"
        # create directory and extract
        extract_dir="bwtmp/$(basename "$download_file" .tar.gz)_$(date +%s)"
        mkdir -p "$extract_dir"
        if ! tar -C "$extract_dir" -zxf "bwtmp/$download_file" >/dev/null 2>&1; then
            log "WARNING: cannot extract $download_file -fallback"
            return 1
        fi
        # clean
        rm -f "bwtmp/$download_file"
        return 0
    }
    if ! targz 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz'; then
        log "WARNING: ut-capitole.fr download failed -fallback"
        cd bwtmp || { log "ERROR: cannot enter bwtmp path -abort"; exit 1; }
        if $wget_opts https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolder.py -O gitfolder.py >/dev/null 2>&1; then
            log "SAVED: gitfolder.py"
            chmod +x gitfolder.py
            python3 gitfolder.py "https://github.com/olbat/ut1-blacklists/tree/master/blacklists"
        else
            log "PARTIAL: https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolder.py"
        fi
        rm gitfolder.py &>/dev/null
        find . -type f -name "*.gz" | while read -r gz_file; do
            if ! gunzip "$gz_file" >/dev/null 2>&1; then
                log "WARNING: cannot extract $(basename "$gz_file") from fallback -alert"
            fi
        done
        cd ..
    fi

    # download world_universities_and_domains
    univ() {
        local source_url="$1"
        local http_code
        # check with curl
        http_code=$(curl -k -s -o /dev/null -w '%{http_code}' -I -L --connect-timeout 5 --max-time 15 --retry 1 "$source_url")
        case "$http_code" in
            2*|405) ;;
            000) log "TIMEOUT: $source_url"; return 1 ;;
            5*)  log "BUSY: $http_code $source_url"; return 1 ;;
            404|410)   log "BROKEN: $http_code $source_url"; return 1 ;;
            *)   log "HTTP_ERROR: $http_code $source_url"; return 1 ;;
        esac
        # download
        if ! $wget_opts "$source_url" -O - \
            | grep -oiE "([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}" \
            | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' \
            | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' \
            | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' \
            | sort -u >> lst/debugwl.txt; then
            log "PARTIAL: $source_url"
            return 1
        fi
        log "SAVED: $(basename "${source_url%%\?*}")"
    }
    univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json' && sleep 1

    log "EVENT: IDN Capture and Debugging..."
    grep_err="$(mktemp)" || { log "ERROR: cannot create domain extraction error file -abort"; exit 1; }
    find bwtmp -type f -not -iname "*pdf" \
      -execdir sh -c 'grep -oiE "([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}" "$1"; [ "$?" -gt 1 ] && printf x >> "$2"; exit 0' _ {} "$grep_err" \; \
    | sed -r 's:(^\.*?(www|ftp|ftps|ftpes|sftp|pop|pop3|smtp|imap|http|https)[^.]*?\.|^\.\.)::gi' \
    | sed -r '/[^a-zA-Z0-9.-]/d; /^[^a-zA-Z0-9.]/d; /[^a-zA-Z0-9]$/d; /^[[:space:]]*$/d; /[[:space:]]/d; /^[[:space:]]*#/d; /\.{2,}/d' \
    | sort -u > stage1.txt
    pipe_status=("${PIPESTATUS[@]}")
    if [ "${pipe_status[0]}" -ne 0 ] || [ "${pipe_status[1]}" -ne 0 ] ||
        [ "${pipe_status[2]}" -ne 0 ] || [ "${pipe_status[3]}" -ne 0 ] ||
        [ -s "$grep_err" ]; then
        rm -f "$grep_err"
        log "ERROR: cannot capture domains from bwtmp -abort"
        exit 1
    fi
    rm -f "$grep_err"
    if [ ! -s stage1.txt ]; then
        log "ERROR: stage1.txt is empty -abort"
        exit 1
    fi
    # RFC 1035 partial
    sed '/[^.]\{64\}/d' stage1.txt \
    | grep -vP '[A-Z]' \
    | grep -vP '(^|\.)-|-($|\.)' \
    | sed 's/^\.//g' \
    | sort -u > stage2.txt
    pipe_status=("${PIPESTATUS[@]}")
    if [ "${pipe_status[0]}" -ne 0 ] || [ "${pipe_status[1]}" -gt 1 ] ||
        [ "${pipe_status[2]}" -gt 1 ] || [ "${pipe_status[3]}" -ne 0 ] ||
        [ "${pipe_status[4]}" -ne 0 ]; then
        log "ERROR: cannot apply RFC 1035 to stage1.txt -abort"
        exit 1
    fi
    if [ ! -s stage2.txt ]; then
        log "ERROR: stage2.txt is empty -abort"
        exit 1
    fi
    # debugging IDN
    idn_src="$(mktemp)" || { log "ERROR: cannot create temporary for stage2.txt -abort"; exit 1; }
    LC_ALL=C grep -v '[^[:print:]]' stage2.txt > "$idn_src"
    if [ "$?" -gt 1 ]; then
        rm -f "$idn_src"
        log "ERROR: cannot prepare IDN input from stage2.txt -abort"
        exit 1
    fi
    grep -P "[^[:ascii:]]" stage2.txt | idn2 >> "$idn_src"
    pipe_status=("${PIPESTATUS[@]}")
    if [ "${pipe_status[0]}" -gt 1 ] || [ "${pipe_status[1]}" -ne 0 ]; then
        rm -f "$idn_src"
        log "ERROR: cannot convert IDN entries -abort"
        exit 1
    fi
    grep -P '^[\x00-\x7F]+$' "$idn_src" \
      | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' \
      | sort -u > capture.txt
    pipe_status=("${PIPESTATUS[@]}")
    rm -f "$idn_src"
    if [ "${pipe_status[0]}" -gt 1 ] || [ "${pipe_status[1]}" -ne 0 ] ||
        [ "${pipe_status[2]}" -ne 0 ]; then
        log "ERROR: cannot build capture.txt -abort"
        exit 1
    fi
    if [ ! -s capture.txt ]; then
        log "ERROR: capture.txt is empty -abort"
        exit 1
    fi

    log "EVENT: Joining Lists..."
    sed '/^$/d; /#/d' lst/{debugwl,invalid}.txt | sed 's/[^[:print:]\n]//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > urls.txt
    pipe_status=("${PIPESTATUS[@]}")
    if [ "${pipe_status[0]}" -ne 0 ] || [ "${pipe_status[1]}" -ne 0 ] ||
        [ "${pipe_status[2]}" -ne 0 ] || [ "${pipe_status[3]}" -ne 0 ] ||
        [ "${pipe_status[4]}" -ne 0 ]; then
        log "ERROR: cannot join debugwl.txt and invalid.txt -abort"
        exit 1
    fi
    if [ ! -s urls.txt ]; then
        log "ERROR: urls.txt is empty -abort"
        exit 1
    fi

    log "EVENT: Debugging Domains..."
    grep -Fvxf urls.txt capture.txt | sed 's/[^[:print:]\n]//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > cleancapture.txt
    pipe_status=("${PIPESTATUS[@]}")
    if [ "${pipe_status[0]}" -gt 1 ] || [ "${pipe_status[1]}" -ne 0 ] ||
        [ "${pipe_status[2]}" -ne 0 ] || [ "${pipe_status[3]}" -ne 0 ] ||
        [ "${pipe_status[4]}" -ne 0 ]; then
        log "ERROR: cannot debug capture.txt -abort"
        exit 1
    fi
    if [ ! -s cleancapture.txt ]; then
        log "ERROR: cleancapture.txt is empty -abort"
        exit 1
    fi
    cp "$script_dir/dofi/domfilter.py" "$repo_dir/domfilter.py" || {
        log "ERROR: cannot copy domfilter.py -abort"
        exit 1
    }
    python3 domfilter.py --input cleancapture.txt || {
        log "ERROR: domfilter.py failed -abort"
        exit 1
    }
    if [ ! -s output.txt ]; then
        log "ERROR: output.txt is empty -abort"
        exit 1
    fi
    grep -Fvxf urls.txt output.txt | grep -P "^[\x00-\x7F]+$" | sort -u > dnsinput.txt
    pipe_status=("${PIPESTATUS[@]}")
    if [ "${pipe_status[0]}" -gt 1 ] || [ "${pipe_status[1]}" -gt 1 ] ||
        [ "${pipe_status[2]}" -ne 0 ]; then
        log "ERROR: cannot build dnsinput.txt -abort"
        exit 1
    fi
    if [ ! -s dnsinput.txt ]; then
        log "ERROR: dnsinput.txt is empty -abort"
        exit 1
    fi
else
    cd "$repo_dir" || {
        log "ERROR: cannot enter bwupdate path -abort"
        exit 1
    }
fi

# ------------------------------------------------------------------------------
# DNS LOOKUP
# ------------------------------------------------------------------------------

# FAULT: Nonexistent or failed domain
# HIT: Resolved (existent) domain
#
# WARNING: High resource consumption!
# This script uses parallel DNS queries. Adjust concurrency to avoid saturating your CPU or network.
#
# Xargs Parallel Limit:
# The practical limit for parallel jobs with xargs is usually high (at least 127; check your system with: xargs --show-limits)
#
# Number of parallel processes (PROCS) = Logical CPUs x multiplier
# The multiplier (e.g., 2, 4) controls how aggressively to parallelize. More isn't always better.
#
# +-------------------------------------------------------+
# | How to determine your CPU configuration (Linux only): |
# +-------------------------------------------------------+
# Physical cores: grep '^core id' /proc/cpuinfo | sort -u | wc -l
# Logical CPUs (threads): nproc
#
# Recommended:
# parallel_procs=$(($(nproc))) # Conservative (network-friendly)
# parallel_procs=$(($(nproc) * 2)) # Balanced
# parallel_procs=$(($(nproc) * 4)) # Aggressive (default)
# parallel_procs=$(($(nproc) * 8)) # Extreme (8 or higher, use with caution)
#
# Example: Core i5 with 4 physical cores and 8 threads (Hyper-Threading)
# nproc -> 8
# parallel_procs=$((8 * 4)) -> 32 parallel queries
#
# Adjust based on:
# - Your CPU
# - Your network (bandwidth/latency)
# - Desired balance between speed and system load
parallel_procs=$(($(nproc) * 4))

stop_progress() {
    kill "$progress_pid" 2>/dev/null
    echo
}

# step 1:
if [ ! -e "$repo_dir"/dnslookup2.txt ]; then
    log "EVENT: 1st DNS Lookup..."
    if ! { sed 's/^\.//g' dnsinput.txt | sort -u > step1.txt; }; then
        log "ERROR: cannot prepare step1.txt -abort"
        exit 1
    fi
    if [ ! -s step1.txt ]; then
        log "ERROR: step1.txt is empty -abort"
        exit 1
    fi
    total_domains=$(wc -l < step1.txt)
    (
        while sleep 1; do
            processed_count=$(wc -l < dnslookup1.txt 2>/dev/null || echo 0)
            percent_done=$(awk -v p="$processed_count" -v t="$total_domains" 'BEGIN { if (t > 0) printf "%.2f", (p/t)*100; else print 100 }')
            printf "Processed: %d / %d (%s%%)\r" "$processed_count" "$total_domains" "$percent_done"
        done
    ) &
    progress_pid=$!
    if ! { if [ -s dnslookup1.txt ]; then
        awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup1.txt step1.txt
    else
        cat step1.txt
    fi | xargs -I {} -P "$parallel_procs" sh -c 'if host -W 1 -- "$1" >/dev/null 2>&1; then echo "HIT $1"; else echo "FAULT $1"; fi' _ {} >> dnslookup1.txt; }; then
        stop_progress
        log "ERROR: 1st DNS lookup failed -abort"
        exit 1
    fi
    stop_progress

    if ! { sed '/^FAULT/d' dnslookup1.txt | awk '{print $2}' | awk '{print "." $1}' | sort -u > hit.txt &&
        sed '/^HIT/d' dnslookup1.txt | awk '{print $2}' | awk '{print "." $1}' | sort -u >> fault.txt &&
        sort -o fault.txt -u fault.txt; }; then
        log "ERROR: cannot classify DNS results as hit or fault -abort"
        exit 1
    fi
fi

sleep 5

# step 2:
log "EVENT: 2nd DNS Lookup..."
if ! { sed 's/^\.//g' fault.txt | sort -u > step2.txt; }; then
    log "ERROR: cannot prepare step2.txt -abort"
    exit 1
fi
if [ -s step2.txt ]; then
    total_domains=$(wc -l < step2.txt)
    (
        while sleep 1; do
            processed_count=$(wc -l < dnslookup2.txt 2>/dev/null || echo 0)
            percent_done=$(awk -v p="$processed_count" -v t="$total_domains" 'BEGIN { if (t > 0) printf "%.2f", (p/t)*100; else print 100 }')
            printf "Processed: %d / %d (%s%%)\r" "$processed_count" "$total_domains" "$percent_done"
        done
    ) &
    progress_pid=$!
    if ! { if [ -s dnslookup2.txt ]; then
        awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup2.txt step2.txt
    else
        cat step2.txt
    fi | xargs -I {} -P "$parallel_procs" sh -c 'if host -W 2 -- "$1" >/dev/null 2>&1; then echo "HIT $1"; else echo "FAULT $1"; fi' _ {} >> dnslookup2.txt; }; then
        stop_progress
        log "ERROR: 2nd DNS lookup failed -abort"
        exit 1
    fi
    stop_progress
else
    log "INFO: no unresolved domains from 1st lookup -skip"
fi
touch dnslookup2.txt

if ! { sed '/^FAULT/d' dnslookup2.txt | awk '{print $2}' | awk '{print "." $1}' | sort -u >> hit.txt &&
    sed '/^HIT/d' dnslookup2.txt | awk '{print $2}' | awk '{print "." $1}' | sort -u > fault.txt; }; then
    log "ERROR: cannot classify DNS results as hit or fault -abort"
    exit 1
fi

log "EVENT: Adding Debug Blacklist..."
if ! { sed '/^$/d; /#/d' lst/debugbl.txt | sort -u >> hit.txt; }; then
    log "ERROR: cannot read debugbl.txt -abort"
    exit 1
fi
# clean hit
bl_filter="$(mktemp)" || { log "ERROR: cannot create debugbl.txt filter -abort"; exit 1; }
if ! sed 's/\./\\./g; s:^\(.*\)$:.\1\$:' lst/debugbl.txt > "$bl_filter"; then
    rm -f "$bl_filter"
    log "ERROR: cannot prepare debugbl.txt filter -abort"
    exit 1
fi
grep -vi -f "$bl_filter" hit.txt | sed -r '/[^a-z0-9.-]/d' | sort -u > blackweb_tmp.txt
pipe_status=("${PIPESTATUS[@]}")
rm -f "$bl_filter"
if [ "${pipe_status[0]}" -gt 1 ] || [ "${pipe_status[1]}" -ne 0 ] ||
    [ "${pipe_status[2]}" -ne 0 ]; then
    log "ERROR: cannot apply debugbl.txt to hit.txt -abort"
    exit 1
fi
if [ ! -s blackweb_tmp.txt ]; then
    log "ERROR: blackweb_tmp.txt is empty -abort"
    exit 1
fi

# TLD final filter (Exclude AllowTLDs .gov, .mil, etc., delete TLDs and NO-ASCII lines)
log "EVENT: Exclude TLD..."
if ! tld_pattern=$(grep -v '^#' lst/allowtlds.txt | sed 's/\./\\./g; s/$/\$/' | tr '\n' '|'
    pipe_status=("${PIPESTATUS[@]}")
    [ "${pipe_status[0]}" -le 1 ] && [ "${pipe_status[1]}" -eq 0 ] &&
        [ "${pipe_status[2]}" -eq 0 ]); then
    log "ERROR: cannot read allowtlds.txt -abort"
    exit 1
fi
tld_pattern_clean="${tld_pattern%|}"
if [ -z "$tld_pattern_clean" ]; then
    cp blackweb_tmp.txt blackweb_tmp2.txt
else
    grep -E -v "$tld_pattern_clean" blackweb_tmp.txt | sort -u > blackweb_tmp2.txt
fi
if [ ! -s blackweb_tmp2.txt ]; then
    log "ERROR: blackweb_tmp2.txt is empty -abort"
    exit 1
fi
sorted_tmp2="$(mktemp)" || { log "ERROR: cannot create temporary for blackweb_tmp2.txt -abort"; exit 1; }
sorted_tlds="$(mktemp)" || { rm -f "$sorted_tmp2"; log "ERROR: cannot create temporary for tlds.txt -abort"; exit 1; }
if ! { sort blackweb_tmp2.txt > "$sorted_tmp2" && sort tlds.txt > "$sorted_tlds" &&
    comm -23 "$sorted_tmp2" "$sorted_tlds" > blackweb.txt; }; then
    rm -f "$sorted_tmp2" "$sorted_tlds"
    log "ERROR: cannot exclude TLD list -abort"
    exit 1
fi
rm -f "$sorted_tmp2" "$sorted_tlds"
if [ ! -s blackweb.txt ]; then
    log "ERROR: blackweb.txt is empty -abort"
    exit 1
fi

# ------------------------------------------------------------------------------
# RELOAD
# ------------------------------------------------------------------------------

log "EVENT: Squid Reload..."
# copy blaclweb to path
sudo install -m 644 -o root -g root blackweb.txt "$acl_dir"/blackweb.txt || {
    log "ERROR: cannot copy blackweb.txt to $acl_dir -abort"
    exit 1
}
# Squid Reload
check_squid_status
sudo bash -c 'squid -k reconfigure' 2>sqerror.txt || {
    log "ERROR: squid reconfigure failed with preview -abort"
    exit 1
}
sleep 20
cache_today="$(mktemp)" || { log "ERROR: cannot create cache.log temporary -abort"; exit 1; }
sudo bash -c 'grep "$(date +%Y/%m/%d)" /var/log/squid/cache.log' > "$cache_today"
if [ "$?" -gt 1 ]; then
    rm -f "$cache_today"
    log "ERROR: cannot read /var/log/squid/cache.log -abort"
    exit 1
fi
sed -r "/\.(log|conf|crl|js|state)/d" "$cache_today" \
    | grep -oiE "([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}" >> sqerror.txt
pipe_status=("${PIPESTATUS[@]}")
rm -f "$cache_today"
if [ "${pipe_status[0]}" -ne 0 ] || [ "${pipe_status[1]}" -gt 1 ]; then
    log "ERROR: cannot debug cache.log entries -abort"
    exit 1
fi
sed -i 's/^/./' sqerror.txt
sort -o sqerror.txt -u sqerror.txt
python3 tools/debugerror.py || {
    log "ERROR: debugerror.py failed -abort"
    exit 1
}
sort -o final.txt -u final.txt
if [ ! -s final.txt ]; then
    log "ERROR: final.txt is empty -abort"
    exit 1
fi

# convert to UTF-8 and keep only ASCII lines
file_encoding=$(file -bi final.txt | sed 's/.*charset=//')
case "$file_encoding" in
    binary|unknown*|"") file_encoding="UTF-8" ;;
esac
iconv -f "$file_encoding" -t UTF-8//IGNORE final.txt \
    | grep -P '^[\x00-\x7F]+$' \
    | grep -P '^\.[a-z0-9][a-z0-9._-]*$' \
    | grep -vP '\s' \
    | sort -u > blackweb.txt
pipe_status=("${PIPESTATUS[@]}")
if [ "${pipe_status[0]}" -ne 0 ] || [ "${pipe_status[1]}" -gt 1 ] ||
    [ "${pipe_status[2]}" -gt 1 ] || [ "${pipe_status[3]}" -gt 1 ] ||
    [ "${pipe_status[4]}" -ne 0 ]; then
    log "ERROR: cannot convert final.txt to UTF-8 -abort"
    exit 1
fi

# validation
if [ ! -s blackweb.txt ]; then
    log "ERROR: blackweb.txt is empty -abort"
    exit 1
fi
total_domains=$(wc -l < blackweb.txt)
log "INFO: blackweb.txt OK, $total_domains valid lines"

# cp to squid
sudo install -m 644 -o root -g root blackweb.txt "$acl_dir"/blackweb.txt || {
    log "ERROR: cannot copy blackweb.txt to $acl_dir -abort"
    exit 1
}
check_squid_status
sudo bash -c 'squid -k reconfigure' 2> "$script_dir/SquidErrors.txt" || {
    log "ERROR: squid reconfigure failed with blackweb.txt -abort"
    exit 1
}

cd .. || {
    log "ERROR: cannot enter bwupdate path -abort"
    exit 1
}

# ------------------------------------------------------------------------------
# END
# ------------------------------------------------------------------------------

log "EVENT: bwupdate done"
log "INFO: Check SquidErrors.txt"
