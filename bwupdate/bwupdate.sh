#!/usr/bin/env bash
# Language spa-eng
bw01=("This process can take. Be patient..." "Este proceso puede tardar. Sea paciente...")
bw02=("Downloading Blackweb..." "Descargando Blackweb...")
bw03=("Downloading Blocklists..." "Descargando Listas de Bloqueo...")
bw04=("Downloading Allowlist..." "Descargando Listas de Permitidos...")
bw05=("Capturing Domains..." "Capturando Dominios...")
bw06=("Joining Lists..." "Uniendo Listas...")
bw07=("Debugging Domains..." "Depurando Dominios...")
bw08=("Debugging PunycodeIDN..." "Depurando Punycode-IDN...")
bw09=("1st DNS Loockup..." "1ra Busqueda DNS...")
bw10=("2nd DNS Loockup..." "2da Busqueda DNS...")
bw11=("Adding Debug Blacklist..." "Agregando Debug Blacklist...")
bw12=("Exclude TLD..." "Excluir TLD...")
bw13=("Restarting Squid..." "Reiniciando Squid...")
bw14=("Check on your desktop Squid-Error.txt" "Verifique en su escritorio Squid-Error.txt")
test "${LANG:0:2}" == "en"
en=$?

# DEPENDENCIES
pkgs='wget git curl libnotify-bin perl tar rar unrar unzip zip gzip python-is-python3 idn2'
for pkg in $pkgs; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        echo "Error: $pkg is not installed. Abort."
        exit 1
    fi
done
if ! command -v iconv >/dev/null 2>&1; then
    echo "Error: iconv is not installed. Abort."
    exit 1
fi

# VARIABLES
bwupdate=$(pwd)/bwupdate
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
wgetd='wget -q -c --show-progress --no-check-certificate --retry-connrefused --timeout=10 --tries=4'
xdesktop=$(xdg-user-dir DESKTOP)
# PATH_TO_ACL (Change it to the directory of your preference)
route="/etc/acl"
# CREATE PATH
if [ ! -d "$route" ]; then sudo mkdir -p "$route"; fi

clear
echo
echo "Blackweb Project"
echo "${bw01[${en}]}"

# CHECK DNSLOOKUP1
if [ ! -e "$bwupdate"/dnslookup1 ]; then

    # DELETE OLD REPOSITORY
    if [ -d "$bwupdate" ]; then rm -rf "$bwupdate"; fi

    # DOWNLOAD BLACKWEB
    echo "${bw02[${en}]}"
    $wgetd https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolderdl.py -O gitfolderdl.py
    chmod +x gitfolderdl.py
    python gitfolderdl.py https://github.com/maravento/blackweb/bwupdate
    if [ -d "$bwupdate" ]; then
        cd "$bwupdate" || {
            echo "Access Error: $bwupdate"
            exit 1
        }
    else
        echo "Does not exist: $bwupdate"
        exit 1
    fi
    mkdir -p bwtmp >/dev/null 2>&1
    echo "OK"

    # DOWNLOADING BLOCKLST URLS
    echo "${bw03[${en}]}"
    # download files
    function blurls() {
        curl -k -X GET --connect-timeout 10 --retry 1 -I "$1" &>/dev/null
        if [ $? -eq 0 ]; then
            filename=$(echo "$1" | awk -F/ '{print $NF}' | sed 's/[^a-zA-Z0-9._-]/_/g')
            $wgetd "$1" -O "bwtmp/$filename"
        else
            echo "ERROR $1"
        fi
    }
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
    blurls 'https://hole.cert.pl/domains/domains.txt' && sleep 1
    blurls 'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt' && sleep 1
    blurls 'https://hostsfile.mine.nu/hosts0.txt' && sleep 1
    blurls 'https://hostsfile.org/Downloads/hosts.txt' && sleep 1
    blurls 'https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt' && sleep 1
    blurls 'https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt' && sleep 1
    blurls 'https://openphish.com/feed.txt' && sleep 1
    blurls 'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt' && sleep 1
    blurls 'https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt' && sleep 1
    blurls 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
    blurls 'https://phishing.army/download/phishing_army_blocklist_extended.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/BBcan177/minerchk/master/hostslist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/BBcan177/referrer-spam-blacklist/master/spammers.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/BlackJack8/webannoyances/master/ultralist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/blocklistproject/Lists/master/everything.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/chainapsis/phishing-block-list/main/block-list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/GHHbD_perma_ban_list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/dom-bl.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/HexxiumCreations/threat-list/gh-pages/hexxiumthreatlist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv' && sleep 1
    blurls 'https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv' && sleep 1
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
    blurls 'https://raw.githubusercontent.com/quedlin/blacklist/master/domains' && sleep 1
    blurls 'https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Rpsl/adblock-leadgenerator-list/master/list/list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat' && sleep 1
    blurls 'https://raw.githubusercontent.com/ryanbr/fanboy-adblock/master/fake-news.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/sayomelu/nothingblock/master/filter.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/scamaNet/blocklist/main/blocklist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Adult' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Cryptocurrency' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Dating' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Gambling' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Risk' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Scam' && sleep 1
    blurls 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/UrlShortener' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/txthinking/bypass/master/china_domain.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts1' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts2' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts3' && sleep 1
    blurls 'https://raw.githubusercontent.com/vokins/yhosts/master/hosts' && sleep 1
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
    blurls 'https://www.taz.net.au/Mail/SpamDomains' && sleep 1
    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt' && sleep 1
    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list_optional.txt' && sleep 1
    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt' && sleep 1
    blurls 'https://zoso.ro/pages/rolist.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/eallion/uBlacklist-subscription-compilation/refs/heads/main/uBlacklist.txt' && sleep 1
   
    # DOWNLOADING BIG BLOCKLISTS
    function targz() {
        local url="$1"
        $wgetd "$url" && for F in *.tar.gz; do
            R=$RANDOM
            mkdir -p bwtmp/$R
            tar -C bwtmp/$R -zxvf "$F" -i
        done >/dev/null 2>&1
        return $?
    }

    if ! targz 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' && \
       ! targz 'ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/blacklists.tar.gz'; then
        echo "ut-capitole.fr download failed. Switching to alt repo..."
        cd bwtmp
        $wgetd https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolderdl.py -O gitfolderdl.py >/dev/null 2>&1
        chmod +x gitfolderdl.py
        python gitfolderdl.py "https://github.com/olbat/ut1-blacklists/tree/master/blacklists"
        rm gitfolderdl.py &>/dev/null
        find . -type f -name "*.gz" | while read gzfile; do
            gunzip "$gzfile" >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                echo "Error unzipping: $gzfile"
            fi
        done
        cd ..
    fi
    
    # DOWNLOADING FOLDER
    cd bwtmp
    $wgetd https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolderdl.py -O gitfolderdl.py >/dev/null 2>&1
    chmod +x gitfolderdl.py
    python gitfolderdl.py "https://github.com/pengelana/blocklist/tree/master/src/blacklist"
    rm gitfolderdl.py &>/dev/null
    cd ..
    echo "OK"

    # DOWNLOADING ALLOWLST URLS
    echo "${bw04[${en}]}"
    # download world_universities_and_domains
    function univ() {
        curl -k -X GET --connect-timeout 10 --retry 1 -I "$1" &>/dev/null
        if [ $? -eq 0 ]; then
            $wgetd "$1" -O - | grep -oiE $regexd | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u >> lst/debugwl.txt
        else
            echo ERROR "$1"
        fi
    }
    univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json' && sleep 1
    echo "OK"
    
    # CAPTURING DOMAINS
    echo "${bw05[${en}]}"
    # capturing
    find bwtmp -type f -not -iname "*pdf" -execdir grep -oiE $regexd {} \; > cap1
    piconv -f cp1252 -t UTF-8 <cap1 > cap2
    iconv -f UTF-8 -t WINDOWS-1252 cap2 > cap3
    sed -r 's:(^\.*?(www|ftp|ftps|ftpes|sftp|pop|pop3|smtp|imap|http|https)[^.]*?\.|^\.\.?)::gi' cap3 | sed -r '/[^a-zA-Z0-9.-]/d; /^[^a-zA-Z0-9.]/d; /[^a-zA-Z0-9]$/d; /^[[:space:]]*$/d; /[[:space:]]/d; /^[[:space:]]*#/d; /[^[:print:]]/d; /\.{2,}/d' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > capture.txt
    # EXPERIMENTAL
    # remote
    #sed '/^$/d; /#/d' lst/remote.txt | sort -u >> capture.txt
    # web3
    #sed '/^$/d; /#/d' lst/web3.txt | sort -u >> capture.txt
    # uniq capture.txt
    #sort -o capture.txt -u capture.txt
    echo "OK"

    # JOIN AND UPDATE LIST
    echo "${bw06[${en}]}"
    sed '/^$/d; /#/d' lst/{debugwl,invalid}.txt | sed 's/[^[:print:]\n]//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > urls.txt
    echo "OK"
    
    # DEBUGGING DOMAINS
    echo "${bw07[${en}]}"
    grep -Fvxf urls.txt capture.txt | sed 's/[^[:print:]\n]//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{if ($1 !~ /^\./) print "." $1; else print $1}' | sort -u > cleancapture.txt
    $wgetd https://raw.githubusercontent.com/maravento/vault/refs/heads/master/scripts/python/domfilter.py -O domfilter.py >/dev/null 2>&1
    python domfilter.py --input cleancapture.txt
    grep -Fvxf urls.txt output.txt | grep -P "^[\x00-\x7F]+$" | sort -u > outparse
    echo "OK"

    # DEBUGGING IDN
    echo "${bw08[${en}]}"
    sed '/[^.]\{64\}/d' outparse | grep -vP '[A-Z]' | grep -vP '(^|\.)-|-($|\.)' | sed 's/^\.//g' | sort -u > idnlst
    { LC_ALL=C grep -v '[^[:print:]]' idnlst ; grep -P "[^[:ascii:]]" idnlst | idn2 ; } | sort -u > finalclean
    echo "OK"
else
    cd "$bwupdate"
fi

# DNS LOCKUP
# FAULT: Unexist/Fail domain
# HIT: Exist domain
# pp = parallel processes
# WARNING: high resource consumption!
# Xargs Limit: The limit is at least 127 on all systems (and on the author’s system it is 2147483647)
# For more information, run: xargs --show-limits
pp="100"

# STEP 1:
if [ ! -e "$bwupdate"/dnslookup2 ]; then
    echo "${bw09[${en}]}"
    sed 's/^\.//g' finalclean | sort -u > step1
    if [ -s dnslookup1 ]; then
        awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup1 step1
    else
        cat step1
    fi | xargs -I {} -P "$pp" sh -c "if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi" >> dnslookup1
    sed '/^FAULT/d' dnslookup1 | awk '{print $2}' | awk '{print "." $1}' | sort -u > hit.txt
    sed '/^HIT/d' dnslookup1 | awk '{print $2}' | awk '{print "." $1}' | sort -u >> fault.txt
    sort -o fault.txt -u fault.txt
    echo "OK"
fi

sleep 10

# STEP 2:
echo "${bw10[${en}]}"
sed 's/^\.//g' fault.txt | sort -u > step2
if [ -s dnslookup2 ]; then
    awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup2 step2
else
    cat step2
fi | xargs -I {} -P "$pp" sh -c "if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi" >> dnslookup2
sed '/^FAULT/d' dnslookup2 | awk '{print $2}' | awk '{print "." $1}' | sort -u >> hit.txt
sed '/^HIT/d' dnslookup2 | awk '{print $2}' | awk '{print "." $1}' | sort -u > fault.txt
echo "OK"

# DEBUG BLACKLIST
echo "${bw11[${en}]}"
# add debug blacklist
sed '/^$/d; /#/d' lst/debugbl.txt | sort -u >> hit.txt
# clean hit
grep -vi -f <(sed 's:^\(.*\)$:.\\\1\$:' lst/debugbl.txt) hit.txt | sed -r '/[^a-z0-9.-]/d' | sort -u > blackweb_tmp
echo "OK"

# EXCLUDE DOMAINS WITH ALLOW TLDS (.gov, .mil, etc.) AND DELETE NO-ASCII AND TLDs lines
echo "${bw12[${en}]}"
regex_ext=$(grep -v '^#' lst/allowtlds.txt | sed 's/$/\$/' | tr '\n' '|')
new_regex_ext="${regex_ext%|}"
grep -E -v "$new_regex_ext" blackweb_tmp | grep -P "^[\x00-\x7F]+$" | sort -u > blackweb_tmp2
comm -23 <(sort blackweb_tmp2) <(sort tlds.txt) > blackweb.txt
# Optional
#grep -E "$new_regex_ext" blackweb_tmp > delete_tld
echo "OK"

# RELOAD SQUID-CACHE
echo "${bw13[${en}]}"
# copy blaclweb to path
sudo cp -f blackweb.txt "$route"/blackweb.txt >/dev/null 2>&1
# Squid Reload
# Edit /etc/squid/squid.conf and add lines:
# acl blackweb dstdomain -i "/path_to/blackweb.txt"
# http_access deny blackweb
sudo bash -c 'squid -k reconfigure' 2>sqerror && sleep 20
sudo bash -c 'grep "$(date +%Y/%m/%d)" /var/log/squid/cache.log | sed -r "/\.(log|conf|crl|js|state)/d" | grep -oiE "$regexd"' >> sqerror
sort -o sqerror -u sqerror
python tools/debug_error.py
sort -o final -u final
mv -f final blackweb.txt
sudo cp -f blackweb.txt "$route"/blackweb.txt >/dev/null 2>&1
sudo bash -c 'squid -k reconfigure' 2>"$xdesktop"/SquidErrors.txt

# DELETE REPOSITORY (Optional)
cd ..
if [ -d "$bwupdate" ]; then rm -rf "$bwupdate"; fi

# END
sudo bash -c 'echo "BlackWeb Done: $(date)" | tee -a /var/log/syslog'
echo "${bw14[${en}]}"
