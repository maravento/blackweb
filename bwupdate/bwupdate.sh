#!/bin/bash
# ------------------------------------
# Update Blackweb
# By: Alej Calero and Jhonatan Sneider
# maravento.com
# ------------------------------------
# Language spa-eng
cm1=("Este proceso puede tardar. Sea paciente..." "This process can take. Be patient...")
cm2=("Descargando Blackweb..." "Downloading Blackweb...")
cm7=("Descargando Listas Negras..." "Downloading Blacklists...")
cm8=("Descargando Listas Blancas..." "Downloading Whitelist...")
cm9=("Actualizando TLD..." "TLD Update...")
cm10=("Capturando Dominios..." "Capturing Domains...")
cm11=("Uniendo Listas..." "Joining Lists...")
cm12=("Depurando Dominios..." "Debugging Domains...")
cm13=("Validando TLD..." "Validating TLD...")
cm14=("Depurando Punycode-IDN..." "Debugging PunycodeIDN...")
cm15=("Búsqueda de DNS..." "DNS Loockup...")
cm16=("Agregando Blacklist Adicionales..." "Adding Additional Blacklist...")
cm17=("Reiniciando Squid..." "Restarting Squid...")
cm18=("Terminado" "Done")
cm19=("Verifique en su escritorio Squid-Error.txt" "Check on your desktop Squid-Error.txt")
cm20=("Verificando Ancho de Banda..." "Checking Bandwidth...")

test "${LANG:0:2}" == "es"
es=$?
clear
echo
echo "Blackweb Project"
echo "${cm1[${es}]}"
# VARIABLES
bwupdate=$(pwd)/bwupdate
date=`date +%d/%m/%Y" "%H:%M:%S`
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
wgetd="wget -q -c --retry-connrefused -t 0"
xdesktop=$(xdg-user-dir DESKTOP)
# PATH_TO_ACL (Change it to the directory of your preference)
route=/etc/acl

# DELETE OLD REPOSITORY
if [ -d $bwupdate ]; then rm -rf $bwupdate; fi
# CREATE PATH
if [ ! -d $route ]; then mkdir -p $route; fi

# CHECKING DOWNLOAD BANDWIDTH (Optional)
# https://raw.githubusercontent.com/maravento/gateproxy/master/conf/scripts/bandwidth.sh
echo
echo "${cm20[${es}]}"
dlmin="1.00"
mb="Mbit/s"
dl=$(curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python - --simple --no-upload | grep 'Download:')
resume=$(curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python - --simple)
dlvalue=$(echo $dl | awk '{print $2}')
dlmb=$(echo $dl | awk '{print $3}')

function download(){
if (( $(echo "$dlvalue $dlmin" | awk '{print ($1 < $2)}') )); then
    	echo "WARNING! Bandwidth Download Slow: $dlvalue $dlmb < $dlmin $mb (min value)"
        notify-send "WARNING! Bandwidth Download Slow: $dlvalue $dlmb < $dlmin $mb (min value)"
    else
        echo "OK"
fi
}

if [[ $mb == $dlmb ]]; then
		download
	else
		echo "Incorrect Value. Abort: $resume"
		notify-send "Incorrect Value. Abort: $resume"
		exit
fi

# DOWNLOAD BLACKWEB
echo
echo "${cm2[${es}]}"
svn export "https://github.com/maravento/blackweb/trunk/bwupdate" >/dev/null 2>&1
cd $bwupdate
mkdir -p bwtmp >/dev/null 2>&1
echo "OK"

# DOWNLOADING BLACKURLS
echo
echo "${cm7[${es}]}"
# download files
function blurls() {
	$wgetd "$1" -O - >> bwtmp/bw
}
	blurls 'http://adaway.org/hosts.txt' && sleep 1
	blurls 'http://cybercrime-tracker.net/all.php' && sleep 1
	blurls 'http://malc0de.com/bl/ZONES' && sleep 1
	blurls 'http://margevicius.lt/easylistlithuania.txt' && sleep 1
	blurls 'http://mirror1.malwaredomains.com/files/justdomains' && sleep 1
	blurls 'http://osint.bambenekconsulting.com/feeds/dga-feed.txt' && sleep 1
	blurls 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
	blurls 'https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt' && sleep 1
	blurls 'https://data.netlab.360.com/feeds/dga/dga.txt' && sleep 1
	blurls 'https://easylist-downloads.adblockplus.org/malwaredomains_full.txt' && sleep 1
	blurls 'https://github.com/WaLLy3K/notrack/raw/master/malicious-sites.txt' && sleep 1
	blurls 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt' && sleep 1
	blurls 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt' && sleep 1
	blurls 'https://hblock.molinero.dev/hosts_domains.txt' && sleep 1
	blurls 'https://hexxiumcreations.github.io/threat-list/hexxiumthreatlist.txt' && sleep 1
	blurls 'https://hostsfile.mine.nu/hosts0.txt' && sleep 1
	blurls 'https://hosts-file.net/ad_servers.txt' && sleep 1
	blurls 'https://hosts-file.net/emd.txt' && sleep 1
	blurls 'https://hosts-file.net/exp.txt' && sleep 1
	blurls 'https://hosts-file.net/grm.txt' && sleep 1
	blurls 'https://hosts-file.net/psh.txt' && sleep 1
	blurls 'https://hostsfile.org/Downloads/hosts.txt' && sleep 1
	blurls 'https://hosts.ubuntu101.co.za/domains.list' && sleep 1
	blurls 'https://mirror.cedia.org.ec/malwaredomains/domains.txt' && sleep 1
	blurls 'https://mirror.cedia.org.ec/malwaredomains/immortal_domains.txt' && sleep 1
	blurls 'https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt' && sleep 1
	blurls 'http://someonewhocares.org/hosts/hosts' && sleep 1
	blurls 'https://openphish.com/feed.txt' && sleep 1
	blurls 'https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt' && sleep 1
	blurls 'https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt' && sleep 1
	blurls 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt' && sleep 1
	blurls 'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt' && sleep 1
	blurls 'https://ransomwaretracker.abuse.ch/downloads/TC_C2_DOMBL.txt' && sleep 1
	blurls 'https://ransomwaretracker.abuse.ch/downloads/TL_C2_DOMBL.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/iPv4Hosts.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Miscellaneous%20(Hosts)' && sleep 1
	blurls 'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list' && sleep 1
	blurls 'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list' && sleep 1
	blurls 'https://raw.githubusercontent.com/CHEF-KOCH/BarbBlock-filter-list/master/HOSTS.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/List.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/gfmaster/adblock-korea-contrib/master/filter.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv' && sleep 1
	blurls 'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/PULL_REQUESTS/domains.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list' && sleep 1
	blurls 'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list' && sleep 1
	blurls 'https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf' && sleep 1
	blurls 'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/quedlin/blacklist/master/domains' && sleep 1
	blurls 'https://raw.githubusercontent.com/quidsup/notrack/master/malicious-sites.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt' && sleep 1
	blurls 'https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat' && sleep 1
	blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/tankmohit/UnifiedHosts/master/hosts.all' && sleep 1
	blurls 'https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list' && sleep 1
	blurls 'https://raw.githubusercontent.com/vokins/yhosts/master/hosts' && sleep 1
	blurls 'https://raw.githubusercontent.com/yous/YousList/master/youslist.txt' && sleep 1
	blurls 'https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts' && sleep 1
	blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt' && sleep 1
	blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt' && sleep 1
	blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/AdguardDNS.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Airelle-hrsk.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Airelle-trc.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/BillStearns.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Easylist.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Easyprivacy.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Kowabit.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Prigent-Ads.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Prigent-Malware.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Prigent-Phishing.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/Shalla-mal.txt' && sleep 1
	blurls 'https://v.firebog.net/hosts/static/w3kbl.txt' && sleep 1
	blurls 'https://www.dshield.org/feeds/suspiciousdomains_High.txt' && sleep 1
	blurls 'https://www.dshield.org/feeds/suspiciousdomains_Medium.txt' && sleep 1
	blurls 'https://www.squidblacklist.org/downloads/dg-ads.acl' && sleep 1
	blurls 'https://www.squidblacklist.org/downloads/dg-malicious.acl' && sleep 1
	blurls 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt' && sleep 1
	blurls 'http://sysctl.org/cameleon/hosts' && sleep 1
	blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser' && sleep 1
	blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts_optional' && sleep 1
	blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts' && sleep 1
	blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt' && sleep 1
	blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list_browser_UBO.txt' && sleep 1
	blurls 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt' && sleep 1
	blurls 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist' && sleep 1
	blurls 'http://winhelp2002.mvps.org/hosts.txt' && sleep 1
	blurls 'http://www.carl.net/spam/access.txt' && sleep 1
	blurls 'http://www.dshield.org/feeds/suspiciousdomains_Low.txt' && sleep 1
	blurls 'http://www.joewein.net/dl/bl/dom-bl-base.txt' && sleep 1
	blurls 'http://www.joewein.net/dl/bl/dom-bl.txt' && sleep 1
	blurls 'http://www.malwaredomainlist.com/hostslist/hosts.txt' && sleep 1
	blurls 'http://www.taz.net.au/Mail/SpamDomains' && sleep 1
	blurls 'https://raw.githubusercontent.com/jawz101/MobileAdTrackers/master/hosts' && sleep 1
	blurls 'https://280blocker.net/files/280blocker_domain.txt' && sleep 1
	blurls 'https://hosts.nfz.moe/full/hosts' && sleep 1

# download and fix hosts.txt blacklist (malformed UTF-8 character)
function blhosts() {
	$wgetd "$1" -O hosts.txt && piconv -f cp1252 -t UTF-8 < hosts.txt >> bwtmp/bw
}
	blhosts 'http://hosts-file.net/download/hosts.txt' && sleep 1

# download .tar.gz/.tgz
function targz() {
	$wgetd "$1" && for F in *.tar.gz; do R=$RANDOM ; mkdir bwtmp/$R ; tar -C bwtmp/$R -zxvf $F -i; done >/dev/null 2>&1
}
	targz 'http://www.shallalist.de/Downloads/shallalist.tar.gz' && sleep 2
	targz 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' && sleep 2

function tgz() {
	$wgetd "$1" && for F in *.tgz; do R=$RANDOM ; mkdir bwtmp/$R ; tar -C bwtmp/$R -zxvf $F -i; done >/dev/null 2>&1
}
	tgz 'http://squidguard.mesd.k12.or.us/blacklists.tgz' && sleep 2

echo "OK"

# DOWNLOADING WHITEURLS
echo
echo "${cm8[${es}]}"
# download world_universities_and_domains
function univ() {
	$wgetd "$1" -O - | grep -oiE "$regexd" | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' | awk '{print "."$1}' | sort -u >> lst/whiteurls.txt
}
	univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json' && sleep 1
echo "OK"

# UPDATE TLDS
echo
echo "${cm9[${es}]}"
function publicsuffix() {
	$wgetd "$1" -O - >> lst/sourcetlds.txt
}
	publicsuffix 'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat'
	publicsuffix 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
	publicsuffix 'https://www.whoisxmlapi.com/support/supported_gtlds.php'
grep -v "//" lst/sourcetlds.txt | sed '/^$/d; /#/d' | grep -v -P "[^a-z0-9_.-]" |  sed 's/^\.//' |  awk '{print "."$1}' |  sort -u > tlds.txt
echo "OK"

# CAPTURING DOMAINS
echo
echo "${cm10[${es}]}"
# capturing
find bwtmp -type f -execdir grep -oiE "$regexd" {} \; > captmp
sed -r 's:(^\.*?(www|ftp|http)[^.]*?\.|^\.\.?)::gi' captmp | sed -r '/[^a-z0-9.-]/d' | sed -r '/^.\W+/d' | awk '{print "."$1}' | sort -u > capture
echo "OK"

# JOIN LIST
echo
echo "${cm11[${es}]}"
# create urls.txt
sed '/^$/d; /#/d' lst/{whiteurls,invalid}.txt | sort -u > urls.txt
# add oldurls.txt to capture
tar -xvzf lst/oldurls.tar.gz -O >> capture 2> /dev/null
# unblock cloud/sync/telemetry
#sed '/^$/d; /#/d' lst/{cloudsync,remote,telemetry}.txt | sort -u >> urls.txt
# block cloud/sync/telemetry
#sed '/^$/d; /#/d' lst/{cloudsync,remote,telemetry}.txt | sort -u >> capture
# uniq capture
sort -o capture -u capture
echo "OK"

# DEBUGGING DOMAINS
echo
echo "${cm12[${es}]}"
# parse domains
#svn export "https://github.com/maravento/blackweb/trunk/bw" >/dev/null 2>&1
#cd $bwpath
cat lst/fault.tar.gz* | tar xzf -
grep -Fvxf <(cat {urls,tlds,fault}.txt) <(python tools/parse_domain.py | awk '{print "."$1}') | sort -u > outparse
echo "OK"

# DEBUGGING TLDS
echo
echo "${cm13[${es}]}"
# check tlds
grep -x -f <(sed 's/\./\\./g;s/^/.*/' tlds.txt) <(grep -v -F -x -f tlds.txt outparse) | sort -u > cleantlds
echo "OK"

# DEBUGGING IDN
echo
echo "${cm14[${es}]}"
sed '/[^.]\{64\}/d' cleantlds | grep -vP '[A-Z]' | grep -vP '(^|\.)-|-($|\.)' | grep -vP '^\.?[^-]{2}--' | grep -Pv '\-{3,}' | sed 's/^\.//g' | sort -u > idnlst
grep --color='auto' -P "[^[:ascii:]]" idnlst | idn2 >> idnlst
grep --color='auto' -P "[^[:ascii:]]" idnlst > idntmp
grep -Fvxf <(cat idntmp) idnlst | sort -u > cleanidn
#grep -vi -f <(sed 's:^\(.*\)$:^\\\1\$:' idntmp) idnlst | sort -u > cleanidn
echo "OK"

# DNS LOCKUP
echo
echo "${cm15[${es}]}"
# FAULT: Unexist/Fail domain
# HIT: Exist domain
ni="300"
# STEP 1:
grep -Fvxf <(cat {urls,tlds,fault}.txt) cleanidn | sort -u > cleandns
cat dnslookup > progress 2> /dev/null
cat cleandns | xargs -I {} -P $ni sh -c "if ! grep --quiet {} progress; then if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi; fi" >> dnslookup
sed '/^FAULT/d' dnslookup | awk '{print $2}' | awk '{print "."$1}' | sort -u > hit.txt
sed '/^HIT/d' dnslookup | awk '{print $2}' | awk '{print "."$1}' | sort -u >> fault.txt
sort -o fault.txt -u fault.txt
# STEP 2:
sed 's/^\.//g' fault.txt | sort -u > step2
cat dnslookup2 > progress2 2> /dev/null
cat step2 | xargs -I {} -P $ni sh -c "if ! grep --quiet {} progress2; then if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi; fi" >> dnslookup2
sed '/^FAULT/d' dnslookup2 | awk '{print $2}' | awk '{print "."$1}' | sort -u >> hit.txt
sed '/^HIT/d' dnslookup2 | awk '{print $2}' | awk '{print "."$1}' | sort -u > fault.txt
echo "OK"

# ADD BLACKLIST BLACKTLDS
echo
echo "${cm16[${es}]}"
# add blackurls, blacktlds
cat lst/{blackurls,blacktlds}.txt >> hit.txt
# clean hit
grep -vi -f <(sed 's:^\(.*\)$:.\\\1\$:' lst/{blackurls,blacktlds}.txt) hit.txt | sort -u > blackweb.txt
echo "OK"

# RELOAD SQUID-CACHE
echo
echo "${cm16[${es}]}"
# copy blaclweb to path
sudo cp -f blackweb.txt $route/blackweb.txt >/dev/null 2>&1
echo "OK"
# Squid Reload
# First Edit /etc/squid/squid.conf and add lines:
# acl blackweb dstdomain -i "/path_to/blackweb.txt"
# http_access deny blackweb
sudo bash -c 'squid -k reconfigure' 2> SquidError.txt
sudo bash -c 'grep "$(date +%Y/%m/%d)" /var/log/squid/cache.log | sed -r "/\.(log|conf|crl|js|state)/d" | grep -oiE "$regexd"' >> SquidError.txt
sort -o SquidError.txt -u SquidError.txt
python tools/debug_error.py
sudo cp -f final $route/blackweb.txt >/dev/null 2>&1
sudo bash -c 'squid -k reconfigure' 2> $xdesktop/SquidError.txt
sudo bash -c 'echo "Blackweb $date" >> /var/log/syslog'
# END
echo
echo "${cm18[${es}]}"
echo "${cm19[${es}]}"
notify-send "Blackweb Update: Done"
