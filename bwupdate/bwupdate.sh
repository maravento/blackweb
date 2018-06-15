#!/bin/bash
### BEGIN INIT INFO
# Provides:          bwupdate
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       Enable service provided by daemon
### END INIT INFO

# by:	maravento.com and novatoz.com

# Language spa-eng
cm1=("Este proceso puede tardar mucho tiempo. Sea paciente..." "This process can take a long time. Be patient...")
cm2=("Descargando Blackweb Update..." "Downloading Blackweb Update...")
cm7=("Descargando Listas Negras..." "Downloading Blacklists...")
cm8=("Descargando Listas Blancas..." "Downloading Whitelist...")
cm9=("Descargando TLDs, Dominios Invalidos, etc..." "Downloading TLDs, Invalids Domains, etc...")
cm10=("Capturando Dominios..." "Capturing Domains...")
cm11=("Depurando Blackweb..." "Debugging Blackweb...")
cm12=("Recargando Squid..." "Squid Reload...")
cm13=("Terminado" "Done")
cm14=("Verifique en su Escritorio: SquidError.txt" "Check on your Desktop: SquidError.txt")

test "${LANG:0:2}" == "es"
es=$?

clear
echo
echo "Blackweb Project"
echo "${cm1[${es}]}"

# VARIABLES
bwupdate=$(pwd)/bwupdate
route=/etc/acl
date=`date +%d/%m/%Y" "%H:%M:%S`
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
wgetd="wget -q -c --retry-connrefused -t 0"
xdesktop=$(xdg-user-dir DESKTOP)

# DELETE OLD REPOSITORY
if [ -d $bwupdate ]; then rm -rf $bwupdate; fi
# CREATE PATH
if [ ! -d $route ]; then mkdir -p $route; fi

# DOWNLOAD BLACKWEB
echo
echo "${cm2[${es}]}"
svn export "https://github.com/maravento/blackweb/trunk/bwupdate" >/dev/null 2>&1
cd $bwupdate && mkdir -p bwtmp >/dev/null 2>&1

echo "OK"

# DOWNLOADING BLACKURLS
echo
echo "${cm7[${es}]}"

# download files
function blurls() {
	$wgetd "$1" -O - >> bwtmp/bw.txt
}
		blurls 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
		blurls 'http://malwaredomains.lehigh.edu/files/justdomains' && sleep 1
                blurls 'https://easylist-downloads.adblockplus.org/malwaredomains_full.txt' && sleep 1
                blurls 'https://zeustracker.abuse.ch/blocklist.php?download=squiddomain' && sleep 1
                blurls 'http://winhelp2002.mvps.org/hosts.txt' && sleep 1
                blurls 'https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf' && sleep 1
                blurls 'http://www.joewein.net/dl/bl/dom-bl-base.txt' && sleep 1
                blurls 'http://www.joewein.net/dl/bl/dom-bl.txt' && sleep 1
                blurls 'http://www.malwaredomainlist.com/hostslist/hosts.txt' && sleep 1
                blurls 'http://adaway.org/hosts.txt' && sleep 1
                blurls 'https://openphish.com/feed.txt' && sleep 1
                blurls 'http://cybercrime-tracker.net/all.php' && sleep 1
                blurls 'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt' && sleep 1
                blurls 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt' && sleep 1
                blurls 'http://malc0de.com/bl/ZONES' && sleep 1
                blurls 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list' && sleep 1
                blurls 'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list' && sleep 1
                blurls 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt' && sleep 1
                blurls 'http://www.carl.net/spam/access.txt' && sleep 1
                blurls 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1
                blurls 'https://hosts.ubuntu101.co.za/domains.list' && sleep 1
                blurls 'https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt' && sleep 1
                blurls 'https://gutl.jovenclub.cu/wp-content/uploads/2017/05/blacklist.txt' && sleep 1
                blurls 'http://www.taz.net.au/Mail/SpamDomains' && sleep 1
                blurls 'http://osint.bambenekconsulting.com/feeds/dga-feed.txt' && sleep 1
                blurls 'https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt' && sleep 1
                blurls 'https://raw.githubusercontent.com/quedlin/blacklist/master/domains' && sleep 1
                blurls 'https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv' && sleep 1
                blurls 'http://www.dshield.org/feeds/suspiciousdomains_Low.txt' && sleep 1
                blurls 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt' && sleep 1

# download and fix hosts.txt blacklist (malformed UTF-8 character)
function blhosts() {
        $wgetd "$1" -O hosts.txt && piconv -f cp1252 -t UTF-8 < hosts.txt >> bwtmp/bw.txt
}
                blhosts 'http://hosts-file.net/download/hosts.txt' && sleep 1

# download .zip
function malwaredomains() {
        $wgetd "$1" && unzip -p domains.zip >> bwtmp/bw.txt
}
                malwaredomains 'http://www.malware-domains.com/files/domains.zip' && sleep 1

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

function univ() {
        $wgetd "$1" -O - | sed '/^$/d; / *#/d' | grep -oiE "$regexd" | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sed -r 's:(^.?(www|ftp)[[:alnum:]]?.|^..?)::gi' | awk '{print "."$1}' | sort -u >> whiteurls.txt
}
                univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json' && sleep 1

echo "OK"

# DOWNLOADING WHITETLDS AND INVALID DOMAINS
echo
echo "${cm9[${es}]}"

function iana() {
        $wgetd "$1" -O - | sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/' | sed '/^$/d; / *#/d' | sed 's/^/./' | sort -u >> whitetlds.txt
}
                iana 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt' && sleep 1

function publicsuffix() {
        $wgetd "$1" -O - | grep -v "//" | grep -ve "^$" | sed 's:\(.*\):\.\1:g' | sort -u | grep -v -P "[^a-z0-9_.-]" >> whitetlds.txt
}
                publicsuffix 'https://publicsuffix.org/list/public_suffix_list.dat' && sleep 1

function whoisxmlapi() {
        $wgetd "$1" -O - | grep -v -P "[^a-z0-9_.-]" | sed '/^$/d; / *#/d' | sort -u >> whitetlds.txt
}
                whoisxmlapi 'https://www.whoisxmlapi.com/support/supported_gtlds.php' && sleep 1

function centralrepo() {
        $wgetd "$1" -O - | sed -r 's:(^.?(www|ftp)[[:alnum:]]?.|^..?)::gi' | awk '{print "."$1}' | sort -u >> invalid.txt
}
                centralrepo 'https://raw.githubusercontent.com/mitchellkrogza/CENTRAL-REPO.Dead.Inactive.Whitelisted.Domains.For.Hosts.Projects/master/DOMAINS-dead.txt' && sleep 1

echo "OK"

# CAPTURING DOMAINS
echo
echo "${cm10[${es}]}"
find bwtmp -type f -execdir grep -oiE "$regexd" {} \; | sed '/[A-Z]/d' | sed '/0--/d' | sed -r '/[^a-zA-Z0-9.-]/d' | sed -r 's:(^\.*?(www|ftp|xxx|wvw)[^.]*?\.|^\.\.?)::gi' | awk '{print "."$1}' | sed -r '/^\.\W+/d' | sort -u > bl.txt && sleep 1

echo "OK"

# DEBUGGING BLACKWEB
echo
echo "${cm11[${es}]}"
# add white urls/tld/invalid
sed '/^$/d; / *#/d' whitetlds.txt | sort -u > tlds.txt
sed '/^$/d; / *#/d' {invalid,whiteurls,cloudsync,remoteurls}.txt | sort -u > urls.txt
# first debugging with python
python parse_domain.py > bwparse.txt
# add own black urls/tld
sed '/^$/d; / *#/d' {blackurls,blacktlds}.txt >> bwparse.txt && sort -o bwparse.txt -u bwparse.txt >/dev/null 2>&1
# second debugging with grep (fixing common errors)
grep -vi -f debug.txt bwparse.txt | sort -u > blackweb.txt
# COPY ACL TO PATH
cp -f blackweb.txt $route/blackweb.txt >/dev/null 2>&1

echo "OK"

# RELOAD SQUID
# First you must edit /etc/squid/squid.conf
# And add lines:
# acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
# http_access deny blackweb
echo
echo "${cm12[${es}]}"
squid -k reconfigure 2> $xdesktop/SquidError.txt && grep "$(date +%Y/%m/%d)" /var/log/squid/cache.log | grep -oiE "$regexd" | sed -r '/\.(log|conf|crl|js|state)/d' | sort -u >> $xdesktop/SquidError.txt && sort -o $xdesktop/SquidError.txt -u $xdesktop/SquidError.txt
echo "Blackweb for Squid: Done $date" >> /var/log/syslog

echo "OK"

# END
cd
rm -rf $bwupdate
echo
echo "${cm13[${es}]}"
echo "${cm14[${es}]}"
