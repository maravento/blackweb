#!/bin/bash
### BEGIN INIT INFO
# Provides:          blackweb update
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       blackweb for Squid
### END INIT INFO
# by:	             maravento.com and novatoz.com

# Language spa-eng
cm1=("Este proceso puede tardar mucho tiempo. Sea paciente..." "This process can take a long time. Be patient...")
cm2=("Verifique su conexion a internet" "Check your internet connection")
test "${LANG:0:2}" == "es"
es=$?

clear
echo
echo "Blackweb Project"
echo "${cm1[${es}]}"

# DATE
date=`date +%d/%m/%Y" "%H:%M:%S`

# PATH
bw=~/blackweb
route=/etc/acl

# DEL OLD REPOSITORY
if [ -d $bw ]; then rm -rf $bw; fi
rm -rf /etc/acl/{blackweb,blackdomains,whitedomains}.txt >/dev/null 2>&1

# GIT CLONE BLACLISTWEB
echo
echo "Download Blackweb..."
git clone --depth=1 https://github.com/maravento/blackweb.git  >/dev/null 2>&1
echo "OK"
echo
echo "Checking Sum..."
cd $bw/bl
cat blackweb.tar.gz* | tar xzf -
a=$(md5sum blackweb.txt | awk '{print $1}')
b=$(cat blackweb.md5 | awk '{print $1}')
	if [ "$a" = "$b" ]
	then 
		echo "Sum Matches"
		cd ..
		sed -e '/^#/d' blackurls.txt | sort -u >> bl/bls.txt
		rm -rf bl/blackweb.md5 bl/blackweb.tar.gz*
		echo "OK"
	else
		echo "Bad Sum. Abort"
		echo "${cm2[${es}]}"
		cd
		rm -rf $bw
		exit
fi

# DOWNLOAD BL
echo
echo "Download Public BLs..."

function bldownload() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | sort -u >> bl/bls.txt
}
	bldownload 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
	bldownload 'http://malwaredomains.lehigh.edu/files/justdomains' && sleep 1
	bldownload 'https://easylist-downloads.adblockplus.org/malwaredomains_full.txt' && sleep 1
	bldownload 'http://www.passwall.com/blacklist.txt' && sleep 1
	bldownload 'https://zeustracker.abuse.ch/blocklist.php?download=squiddomain' && sleep 1
	bldownload 'http://someonewhocares.org/hosts/hosts' && sleep 1
	bldownload 'http://winhelp2002.mvps.org/hosts.txt' && sleep 1
	bldownload 'https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf' && sleep 1
	bldownload 'http://www.joewein.net/dl/bl/dom-bl-base.txt' && sleep 1
	bldownload 'http://www.joewein.net/dl/bl/dom-bl.txt' && sleep 1
	bldownload 'http://www.malwaredomainlist.com/hostslist/hosts.txt' && sleep 1
	bldownload 'http://adaway.org/hosts.txt' && sleep 1
	bldownload 'https://openphish.com/feed.txt' && sleep 1
	bldownload 'http://cybercrime-tracker.net/all.php' && sleep 1
	bldownload 'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt' && sleep 1
	bldownload 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt' && sleep 1
	bldownload 'http://hosts-file.net/download/hosts.txt' && sleep 1
	bldownload 'http://osint.bambenekconsulting.com/feeds/dga-feed.txt' && sleep 1
	bldownload 'http://malc0de.com/bl/ZONES' && sleep 1
	bldownload 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1

function blzip() {
    wget -q -c --retry-connrefused -t 0 "$1" && unzip -p domains.zip >> bl/bls.txt
}
	blzip 'http://www.malware-domains.com/files/domains.zip' && sleep 1

function bltar() {
    wget -q -c --retry-connrefused -t 0 "$1" && for F in *.tar.gz; do R=$RANDOM ; mkdir bl/$R ; tar -C bl/$R -zxvf $F -i; done >/dev/null 2>&1
}
	bltar 'http://www.shallalist.de/Downloads/shallalist.tar.gz' && sleep 2
	bltar 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' && sleep 2

function blbig() {
    wget -q -c --retry-connrefused -t 0 "$1" -O bigblacklist.tar.gz && for F in bigblacklist.tar.gz; do R=$RANDOM ; mkdir bl/$R ; tar -C bl/$R -zxvf $F -i; done >/dev/null 2>&1
}
	blbig 'http://urlblacklist.com/cgi-bin/commercialdownload.pl?type=download&file=bigblacklist' && sleep 2

function blgz() {
    wget -q -c --retry-connrefused -t 0 "$1" && for F in *.tgz; do R=$RANDOM ; mkdir bl/$R ; tar -C bl/$R -zxvf $F -i; done >/dev/null 2>&1
}
	blgz 'http://squidguard.mesd.k12.or.us/blacklists.tgz' && sleep 2

echo "OK"

# DOWNLOAD WHITE TLDS-URLS
echo
echo "Download White TLDs-URLs..."

function iana() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/' | sed -e '/^#/d' | sed 's/^/./' | sort -u >> whitetlds.txt
}
	iana 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'

function suffix() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | grep -v "//" | grep -ve "^$" | sed 's:\(.*\):\.\1:g' | sort -u | grep -v -P "[^a-z0-9_.-]" >> whitetlds.txt
}
	suffix 'https://publicsuffix.org/list/public_suffix_list.dat'

function remoteurl() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | sed -e '/^#/d' | sort -u >> whiteurls.txt
}
	remoteurl 'https://raw.githubusercontent.com/maravento/remoteip/master/remoteurls.txt'

echo "OK"

# JOINT WHITELIST
echo
echo "Joint Whitelist..."
sed -e '/^#/d' {whitetlds,whiteurls}.txt | sort -u > clean.txt
echo "OK"

# CAPTURE AND DELETE OVERLAPPING DOMAINS
echo
echo "Capture Domains..."
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
find bl -type f -execdir egrep -oi "$regexd" {} \; | awk '{print "."$1}' | sort -u | sed 's:\(www\.\|WWW\.\|ftp\.\|/.*\)::g' > urls.txt
echo "OK"
echo
echo "Delete Overlapping Domains..."
chmod +x parse_domain.py
python parse_domain.py | sort -u > blackweb.txt
echo "OK"
echo
# COPY ACL TO PATH
cp -f blackweb.txt $route >/dev/null 2>&1
sed -e '/^#/d' blackdomains.txt >> $route/blackdomains.txt >/dev/null 2>&1 && sort -o $route/blackdomains.txt -u $route/blackdomains.txt >/dev/null 2>&1
sed -e '/^#/d' whitedomains.txt >> $route/whitedomains.txt >/dev/null 2>&1 && sort -o $route/whitedomains.txt -u $route/whitedomains.txt >/dev/null 2>&1
# LOG
echo "Blackweb for Squid: Done $date" >> /var/log/syslog
# END
cd
rm -rf $bw
echo "Done"
