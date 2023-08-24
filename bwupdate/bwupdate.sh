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
bw15=("3rd DNS Loockup..." "3ra Busqueda DNS...")
bw16=("Adding Additional Blocklist..." "Agregando Blocklist Adicionales...")
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

# CHECKING DOWNLOAD BANDWIDTH (Optional)
# https://raw.githubusercontent.com/maravento/gateproxy/master/conf/scripts/bandwidth.sh
echo "${bw03[${en}]}"
dlmin="1.00"
mb="Mbit/s"
dl=$(curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python - --simple --no-upload | grep 'Download:')
resume=$(curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python - --simple)
dlvalue=$(echo "$dl" | awk '{print $2}')
dlmb=$(echo "$dl" | awk '{print $3}')

function bandwidth(){
    if (( $(echo "$dlvalue $dlmin" | awk '{print ($1 < $2)}') )); then
		    echo "WARNING! Bandwidth Download Slow: $dlvalue $dlmb < $dlmin $mb (min value)"
		    notify-send "WARNING! Bandwidth Download Slow:" "$dlvalue $dlmb < $dlmin $mb (min value)" -i checkbox
	    else
		    echo "OK"
    fi
}

if [[ "$mb" == "$dlmb" ]]; then
		bandwidth
	else
		echo "Incorrect Value. Abort: $resume"
		notify-send "Incorrect Value. Abort:" "$resume" -i checkbox
		exit

clear
echo "Blackweb Project"
echo "${bw01[${en}]}"

# CHECK DNSLOOKUP1
if [ ! -e "$bwupdate"/dnslookup1 ]; then

    # DELETE OLD REPOSITORY
    if [ -d "$bwupdate" ]; then rm -rf "$bwupdate"; fi

    # DOWNLOAD BLACKWEB
    echo "${bw04[${en}]}"
    svn export "https://github.com/maravento/blackweb/trunk/bwupdate" >/dev/null 2>&1
    cd "$bwupdate"
    mkdir -p bwtmp >/dev/null 2>&1
    echo "OK"

    # DOWNLOADING BLOCKURLS
    echo "${bw05[${en}]}"
    # download files
    function blurls() {
    wget --no-check-certificate --timeout=10 --tries=1 --method=HEAD "$1" &>/dev/null
    if [ $? -eq 0 ]; then
		    $wgetd "$1" -O - >> bwtmp/bw
	    else
		    echo ERROR "$1"
    fi
    }
	    blurls 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
	    blurls 'https://adaway.org/hosts.txt' && sleep 1
	    blurls 'https://adblock.gardar.net/is.abp.txt' && sleep 1
	    blurls 'https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt' && sleep 1
	    blurls 'https://easylist-downloads.adblockplus.org/advblock.txt' && sleep 1
	    blurls 'https://easylist-downloads.adblockplus.org/antiadblockfilters.txt' && sleep 1
	    blurls 'https://easylist-downloads.adblockplus.org/easylistchina.txt' && sleep 1
	    blurls 'https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw/77eee956303e8d6ff2f4df61d3e2c0b60d023268/MS-2' && sleep 1
	    blurls 'https://github.com/WaLLy3K/notrack/raw/master/malicious-sites.txt' && sleep 1
	    blurls 'https://gitlab.com/malware-filter/urlhaus-filter/-/raw/master/urlhaus-filter.txt' && sleep 1
	    blurls 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt' && sleep 1
	    blurls 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt' && sleep 1
	    blurls 'https://hblock.molinero.dev/hosts_domains.txt' && sleep 1
	    blurls 'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt' && sleep 1
	    blurls 'https://hostsfile.mine.nu/hosts0.txt' && sleep 1
	    blurls 'https://hostsfile.org/Downloads/hosts.txt' && sleep 1
	    blurls 'http://someonewhocares.org/hosts/hosts' && sleep 1
	    blurls 'https://openphish.com/feed.txt' && sleep 1
	    blurls 'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt' && sleep 1
	    blurls 'https://phishing.army/download/phishing_army_blocklist_extended.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/BBcan177/minerchk/master/hostslist.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/BBcan177/referrer-spam-blacklist/master/spammers.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/BlackJack8/webannoyances/master/ultralist.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list' && sleep 1
	    blurls 'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list' && sleep 1
	    blurls 'https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/GHHbD_perma_ban_list.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/dom-bl.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/gfmaster/adblock-korea-contrib/master/filter.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/HexxiumCreations/threat-list/gh-pages/hexxiumthreatlist.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv' && sleep 1
	    blurls 'https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv' && sleep 1
	    blurls 'https://raw.githubusercontent.com/liamja/Prebake/master/obtrusive.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/domains' && sleep 1
	    blurls 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list' && sleep 1
	    blurls 'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list' && sleep 1
	    blurls 'https://raw.githubusercontent.com/NanoAdblocker/NanoFilters/master/NanoFilters/NanoBase.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf' && sleep 1
	    blurls 'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/piperun/iploggerfilter/master/filterlist' && sleep 1
	    blurls 'https://raw.githubusercontent.com/quedlin/blacklist/master/domains' && sleep 1
	    blurls 'https://raw.githubusercontent.com/Rpsl/adblock-leadgenerator-list/master/list/list.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat' && sleep 1
	    blurls 'https://raw.githubusercontent.com/ryanbr/fanboy-adblock/master/fake-news.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/sayomelu/nothingblock/master/filter.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' && sleep 1
	    blurls 'https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt' && sleep 1
	    blurls 'https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list' && sleep 1
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
	    blurls 'http://stanev.org/abp/adblock_bg.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/AdguardDNS.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Admiral.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Easylist.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Easyprivacy.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Kowabit.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Prigent-Ads.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Prigent-Crypto.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/Prigent-Malware.txt' && sleep 1
	    blurls 'https://v.firebog.net/hosts/static/w3kbl.txt' && sleep 1
	    blurls 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt' && sleep 1
	    blurls 'http://sysctl.org/cameleon/hosts' && sleep 1
	    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts' && sleep 1
	    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser' && sleep 1
	    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts_optional' && sleep 1
	    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt' && sleep 1
	    blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt' && sleep 1
	    blurls 'https://zoso.ro/pages/rolist.txt' && sleep 1
	    blurls 'http://winhelp2002.mvps.org/hosts.txt' && sleep 1
	    blurls 'http://www.joewein.net/dl/bl/dom-bl-base.txt' && sleep 1
	    blurls 'http://www.joewein.net/dl/bl/dom-bl.txt' && sleep 1
	    blurls 'http://www.malwaredomainlist.com/hostslist/hosts.txt' && sleep 1
	    blurls 'http://www.taz.net.au/Mail/SpamDomains' && sleep 1

    # DOWNLOADING BIG BLOCKLISTS
    function targz() {
    wget --no-check-certificate --timeout=10 --tries=1 --method=HEAD "$1" &>/dev/null
    if [ $? -eq 0 ]; then
		    $wgetd "$1" && for F in *.tar.gz; do R=$RANDOM ; mkdir bwtmp/$R ; tar -C bwtmp/$R -zxvf "$F" -i; done >/dev/null 2>&1
	    else
		    echo ERROR "$1"
    fi
    }
	    targz 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' && sleep 2
    echo "OK"

    # DOWNLOADING ALLOWURLS
    echo "${bw06[${en}]}"
    # download world_universities_and_domains
    function univ() {
    wget --no-check-certificate --timeout=10 --tries=1 --method=HEAD "$1" &>/dev/null
    if [ $? -eq 0 ]; then
		    $wgetd "$1" -O - | grep -oiE $regexd | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' | awk '{print "."$1}' | sort -u >> lst/allowurls.txt
	    else
		    echo ERROR "$1"
    fi
    }
	    univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json' && sleep 1
    echo "OK"

    # UPDATE TLDS
    echo "${bw07[${en}]}"
    function publicsuffix() {
    wget --no-check-certificate --timeout=10 --tries=1 --method=HEAD "$1" &>/dev/null
    if [ $? -eq 0 ]; then
		    $wgetd "$1" -O - >> lst/sourcetlds.txt
	    else
		    echo ERROR "$1"
    fi
    }
	    publicsuffix 'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat'
	    publicsuffix 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
	    publicsuffix 'https://www.whoisxmlapi.com/support/supported_gtlds.php'
    grep -v "//" lst/sourcetlds.txt | sed '/^$/d; /#/d' | grep -v -P "[^a-z0-9_.-]" |  sed 's/^\.//' |  awk '{print "." $1}' |  sort -u > tlds.txt
    echo "OK"

    # CAPTURING DOMAINS
    echo "${bw08[${en}]}"
    # capturing
    find bwtmp -type f -not -iname "*pdf" -execdir grep -oiE $regexd {} \; > captmp1
    piconv -f cp1252 -t UTF-8 < captmp1 > captmp2
    sed -r 's:(^\.*?(www|ftp|ftps|ftpes|sftp|pop|pop3|smtp|imap|http|https)[^.]*?\.|^\.\.?)::gi' captmp2 | sed -r '/[^a-z0-9.-]/d' | sed -r '/^.\W+/d' | awk '{print "." $1}' | sort -u > capture
    echo "OK"

    # JOIN AND UPDATE LIST
    echo "${bw09[${en}]}"
    # create urls.txt
    sed '/^$/d; /#/d' lst/{allowurls,invalid}.txt | sort -u > urls.txt
    # unblock remote
    #sed '/^$/d; /#/d' lst/remote.txt | sort -u >> urls.txt
    # block remote
    #sed '/^$/d; /#/d' lst/remote.txt | sort -u >> capture
    # convert to hosts file (optional)
    #sed -r "s:^\.(.*):127.0.0.1 \1:g" lst/blockurls.txt | sort -u > lst/hosts.txt
    # uniq capture
    sort -o capture -u capture
    echo "OK"

    # DEBUGGING DOMAINS
    echo "${bw10[${en}]}"
    # parse domains
    #cat lst/fault.tar.gz* | tar xzf -
    #grep -Fvxf <(cat {urls,tlds,fault}.txt) <(python tools/parse_domain.py | awk '{print "." $1}') | sort -u > outparse
    grep -Fvxf <(cat {urls,tlds}.txt) <(python tools/parse_domain.py | awk '{print "." $1}') | sort -u > outparse
    echo "OK"

    # DEBUGGING TLDS
    echo "${bw11[${en}]}"
    # check tlds
    grep -x -f <(sed 's/\./\\./g;s/^/.*/' tlds.txt) <(grep -v -F -x -f tlds.txt outparse) | sed -r '/[^a-z0-9.-]/d' | sort -u > cleantlds
    echo "OK"

    # DEBUGGING IDN
    echo "${bw12[${en}]}"
    sed '/[^.]\{64\}/d' cleantlds | grep -vP '[A-Z]' | grep -vP '(^|\.)-|-($|\.)' | grep -vP '^\.?[^-]{2}--' | grep -Pv '\-{3,}' | sed 's/^\.//g' | sort -u > idnlst
    grep --color='auto' -P "[^[:ascii:]]" idnlst | idn2 >> idnlst
    grep --color='auto' -P "[^[:ascii:]]" idnlst > idntmp
    grep -Fvxf <(cat idntmp) idnlst | sort -u > cleanidn
    #grep -vi -f <(sed 's:^\(.*\)$:^\\\1\$:' idntmp) idnlst | sort -u > cleanidn
    grep -Fvxf <(cat {urls,tlds}.txt) cleanidn | sed -r '/[^a-z0-9.-]/d' | sort -u > cleandns
    echo "OK"
  else
    cd "$bwupdate"
fi

# DNS LOCKUP
# FAULT: Unexist/Fail domain
# HIT: Exist domain
# pp = parallel processes (high resource consumption!)
pp="200"

# STEP 1:
if [ ! -e "$bwupdate"/dnslookup2 ]; then
    echo "${bw13[${en}]}"
    sed 's/^\.//g' cleandns | sort -u > step1
    if [ -s dnslookup1 ] ; then
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
if [ ! -e "$bwupdate"/dnslookup3 ]; then
    echo "${bw14[${en}]}"
    sed 's/^\.//g' fault.txt | sort -u > step2
    if [ -s dnslookup2 ] ; then
		    awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup2 step2
	    else
		    cat step2
    fi | xargs -I {} -P "$pp" sh -c "if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi" >> dnslookup2
    sed '/^FAULT/d' dnslookup2 | awk '{print $2}' | awk '{print "." $1}' | sort -u >> hit.txt
    sed '/^HIT/d' dnslookup2 | awk '{print $2}' | awk '{print "." $1}' | sort -u > fault.txt
    echo "OK"
fi

sleep 10

# STEP 3:
echo "${bw15[${en}]}"
sed 's/^\.//g' fault.txt | sort -u > step3
if [ -s dnslookup3 ] ; then
		awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup3 step3
	else
		cat step3
fi | xargs -I {} -P "$pp" sh -c "if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi" >> dnslookup3
sed '/^FAULT/d' dnslookup3 | awk '{print $2}' | awk '{print "." $1}' | sort -u >> hit.txt
sed '/^HIT/d' dnslookup3 | awk '{print $2}' | awk '{print "." $1}' | sort -u > fault.txt
echo "OK"

# ADD BLOCKLIST
echo "${bw16[${en}]}"
# add blockurls
sed '/^$/d; /#/d' lst/blockurls.txt | sort -u >> hit.txt
# clean hit
grep -vi -f <(sed 's:^\(.*\)$:.\\\1\$:' lst/blockurls.txt) hit.txt | sed -r '/[^a-z0-9.-]/d' | sort -u > blackweb.txt
echo "OK"

# RELOAD SQUID-CACHE
echo "${bw17[${en}]}"
# copy blaclweb to path
sudo cp -f blackweb.txt "$route"/blackweb.txt >/dev/null 2>&1
# Squid Reload
# First Edit /etc/squid/squid.conf and add lines:
# acl blackweb dstdomain -i "/path_to/blackweb.txt"
# http_access deny blackweb
sudo bash -c 'squid -k reconfigure' 2> sqerror && sleep 20
sudo bash -c 'grep "$(date +%Y/%m/%d)" /var/log/squid/cache.log | sed -r "/\.(log|conf|crl|js|state)/d" | grep -oiE "$regexd"' >> sqerror
sort -o sqerror -u sqerror
python tools/debug_error.py
sort -o final -u final
mv -f final blackweb.txt
sudo cp -f blackweb.txt "$route"/blackweb.txt >/dev/null 2>&1
sudo bash -c 'squid -k reconfigure' 2> "$xdesktop"/SquidErrors.txt

# DELETE REPOSITORY (Optional)
cd ..
if [ -d "$bwupdate" ]; then rm -rf "$bwupdate"; fi

# END
sudo bash -c 'echo "Blackweb Done: $(date)" | tee -a /var/log/syslog'
notify-send "Blackweb Update Done" "$(date)" -i checkbox
echo "${bw18[${en}]}"
