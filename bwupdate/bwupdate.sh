#!/usr/bin/env bash
# Language spa-eng
bw01=("This process can take. Be patient..." "Este proceso puede tardar. Sea paciente...")
bw02=("Installing Dependencies..." "Instalando Dependencias...")
bw03=("Checking Bandwidth..." "Verificando Ancho de Banda...")
bw04=("Downloading Blackweb..." "Descargando Blackweb...")
bw05=("Downloading Blocklists..." "Descargando Listas de Bloqueo...")
bw06=("Downloading Allowlist..." "Descargando Listas de Permitidos...")
bw07=("TLD Update..." "Actualizando TLD...")
bw08=("Capturing Domains..." "Capturando Dominios...")
bw09=("Joining Lists..." "Uniendo Listas...")
bw10=("Debugging Domains..." "Depurando Dominios...")
bw11=("Validating TLD..." "Validando TLD...")
bw12=("Debugging PunycodeIDN..." "Depurando Punycode-IDN...")
bw13=("1st DNS Loockup..." "1ra Busqueda DNS...")
bw14=("2nd DNS Loockup..." "2da Busqueda DNS...")
bw15=("Adding Debug Blacklist..." "Agregando Debug Blacklist...")
bw16=("Exclude TLD..." "Excluir TLD...")
bw17=("Restarting Squid..." "Reiniciando Squid...")
bw18=("Check on your desktop Squid-Error.txt" "Verifique en su escritorio Squid-Error.txt")
test "${LANG:0:2}" == "en"
en=$?

# VARIABLES
bwupdate=$(pwd)/bwupdate
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
wgetd='wget -q -c --no-check-certificate --retry-connrefused --timeout=10 --tries=4'
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
    echo "${bw04[${en}]}"
    wget https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolderdl.py
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

    # DOWNLOADING BLOCK URLS
    echo "${bw05[${en}]}"
    # download files
    function blurls() {
        curl -k -X GET --connect-timeout 10 --retry 1 -I "$1" &>/dev/null
        if [ $? -eq 0 ]; then
            $wgetd "$1" -O - >> bwtmp/bw
        else
            echo ERROR "$1"
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
    blurls 'https://raw.githubusercontent.com/bigdargon/notabugLV/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/chainapsis/phishing-block-list/main/block-list.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/dom-bl.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/domains' && sleep 1
    blurls 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list' && sleep 1
    blurls 'https://raw.githubusercontent.com/neodevpro/neodevhost/master/domain' && sleep 1
    blurls 'https://raw.githubusercontent.com/pengelana/blocklist/master/src/domain.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt' && sleep 1
    blurls 'https://raw.githubusercontent.com/ryanbr/fanboy-adblock/master/fake-news.txt' && sleep 1
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
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts1' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts2' && sleep 1
    blurls 'https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts3' && sleep 1
    blurls 'https://raw.githubusercontent.com/vokins/yhosts/master/hosts' && sleep 1
    blurls 'https://raw.githubusercontent.com/yous/YousList/master/youslist.txt' && sleep 1
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

    # DOWNLOADING BIG BLOCKLISTS
    function targz() {
        curl -k -X GET --connect-timeout 10 --retry 1 -I "$1" &>/dev/null
        if [ $? -eq 0 ]; then
            $wgetd "$1" && for F in *.tar.gz; do
                R=$RANDOM
                mkdir bwtmp/$R
                tar -C bwtmp/$R -zxvf "$F" -i
            done >/dev/null 2>&1
        else
            echo ERROR "$1"
        fi
    }
    targz 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' && sleep 2
    echo "OK"

    # DOWNLOADING ALLOW URLS
    echo "${bw06[${en}]}"
    # download world_universities_and_domains
    function univ() {
        curl -k -X GET --connect-timeout 10 --retry 1 -I "$1" &>/dev/null
        if [ $? -eq 0 ]; then
            $wgetd "$1" -O - | grep -oiE $regexd | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' | awk '{print "."$1}' | sort -u >> lst/debugwl.txt
        else
            echo ERROR "$1"
        fi
    }
    univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json' && sleep 1
    echo "OK"

    # UPDATE TLDS
    echo "${bw07[${en}]}"
    function publicsuffix() {
        curl -k -X GET --connect-timeout 10 --retry 1 -I "$1" &>/dev/null
        if [ $? -eq 0 ]; then
            $wgetd "$1" -O - >> lst/sourcetlds.txt
        else
            echo ERROR "$1"
        fi
    }
    publicsuffix 'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat'
    publicsuffix 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
    publicsuffix 'https://www.whoisxmlapi.com/support/supported_gtlds.php'
    grep -v "//" lst/sourcetlds.txt | sed '/^$/d; /#/d' | grep -v -P "[^a-z0-9_.-]" | sed 's/^\.//' | awk '{print "." $1}' | sort -u > tlds.txt
    echo "OK"

    # CAPTURING DOMAINS
    echo "${bw08[${en}]}"
    # capturing
    find bwtmp -type f -not -iname "*pdf" -execdir grep -oiE $regexd {} \; > captmp1
    piconv -f cp1252 -t UTF-8 <captmp1 > captmp2
    sed -r 's:(^\.*?(www|ftp|ftps|ftpes|sftp|pop|pop3|smtp|imap|http|https)[^.]*?\.|^\.\.?)::gi' captmp2 | sed -r '/[^a-z0-9.-]/d' | sed -r '/^.\W+/d' | awk '{print "." $1}' > capture
    echo "OK"

    # JOIN AND UPDATE LIST
    echo "${bw09[${en}]}"
    sed '/^$/d; /#/d' lst/{debugwl,invalid}.txt | sort -u > urls.txt
    # unblock remote
    #sed '/^$/d; /#/d' lst/remote.txt | sort -u >> urls.txt
    # block remote
    #sed '/^$/d; /#/d' lst/remote.txt | sort -u >> capture
    # unblock web3 (experimental)
    #sed '/^$/d; /#/d' lst/web3.txt | sort -u >> urls.txt
    # block web3 (experimental)
    #sed '/^$/d; /#/d' lst/web3.txt | sort -u >> capture
    # uniq capture
    sort -o capture -u capture
    echo "OK"

    # DEBUGGING DOMAINS
    echo "${bw10[${en}]}"
    grep -Fvxf <(cat {urls,tlds}.txt) <(python tools/parse_domain.py | awk '{print "." $1}') | sort -u > outparse
    echo "OK"

    # DEBUGGING TLDS
    echo "${bw11[${en}]}"
    # debugging by domain extensions (option 1)
    #grep -x -f <(sed 's/\./\\./g;s/^/.*/' tlds.txt) <(grep -v -F -x -f tlds.txt outparse) | sed -r '/[^a-z0-9.-]/d' | sort -u > cleantlds
    # debugging by domain extensions (option 2)
    sed 's/\./\\./g;s/^/.*/' tlds.txt > escaped_tlds.txt
    grep -v -F -x -f tlds.txt outparse > filtered_outparse.txt
    # slow part. wait...
    grep -x -f escaped_tlds.txt filtered_outparse.txt > matched_lines.txt
    sed -r '/[^a-z0-9.-]/d' matched_lines.txt | sort -u > cleantlds
    echo "OK"

    # DEBUGGING IDN
    echo "${bw12[${en}]}"
    sed '/[^.]\{64\}/d' cleantlds | grep -vP '[A-Z]' | grep -vP '(^|\.)-|-($|\.)' | grep -vP '^\.?[^-]{2}--' | grep -Pv '\-{3,}' | sed 's/^\.//g' | sort -u > idnlst
    grep --color='auto' -P "[^[:ascii:]]" idnlst | idn2 >> idnlst
    grep --color='auto' -P "[^[:ascii:]]" idnlst > idntmp
    grep -Fvxf <(cat idntmp) idnlst | sort -u > cleanidn
    #grep -vi -f <(sed 's:^\(.*\)$:^\\\1\$:' idntmp) idnlst | sort -u > cleanidn
    grep -Fvxf <(cat tlds.txt) cleanidn | sed -r '/[^a-z0-9.-]/d' | sort -u > cleandns
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
pp="50"

# STEP 1:
if [ ! -e "$bwupdate"/dnslookup2 ]; then
    echo "${bw13[${en}]}"
    sed 's/^\.//g' cleandns | sort -u > step1
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
echo "${bw14[${en}]}"
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
echo "${bw15[${en}]}"
# add debug blacklist
sed '/^$/d; /#/d' lst/debugbl.txt | sort -u >> hit.txt
# clean hit
grep -vi -f <(sed 's:^\(.*\)$:.\\\1\$:' lst/debugbl.txt) hit.txt | sed -r '/[^a-z0-9.-]/d' | sort -u > blackweb_tmp
# convert to hosts file (optional)
#sed -r "s:^\.(.*):127.0.0.1 \1:g" lst/debugbl.txt | sort -u > lst/hosts.txt
echo "OK"

# EXCLUDE ALLOW TLDS
echo "${bw16[${en}]}"
regex_ext=$(grep -v '^#' lst/allowtlds.txt | sed 's/$/\$/' | tr '\n' '|')
new_regex_ext="${regex_ext%|}"
grep -E -v "$new_regex_ext" blackweb_tmp > blackweb.txt
grep -E "$new_regex_ext" blackweb_tmp > delete_tld
echo "OK"

# RELOAD SQUID-CACHE
echo "${bw17[${en}]}"
# copy blaclweb to path
sudo cp -f blackweb.txt "$route"/blackweb.txt >/dev/null 2>&1
# Squid Reload
# First Edit /etc/squid/squid.conf and add lines:
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
echo "${bw18[${en}]}"
