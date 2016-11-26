#!/bin/bash
### BEGIN INIT INFO ###
# Provides:		Blackweb Update for Squid
# Required-Start:	$remote_fs $syslog
# Required-Stop:	$remote_fs $syslog
# Default-Start:	2 3 4 5
# Default-Stop:		0 1 6
# Short-Description:	Start daemon at boot time
# Description:		Enable service provided by daemon.
# Authors:		Maravento.com and Novatoz.com
# script/acl route:	/etc/init.d /etc/acl
### END INIT INFO ###
clear
echo
echo "Blackweb"
echo "This process can take a long time. Be patient..."
echo "Este proceso puede tardar mucho tiempo. Sea paciente..."
echo
bw=~/blackweb

# DEL OLD REPOSITORY
if [ -d $bw ]; then rm -rf $bw; fi

# GIT CLONE BLACLISTWEB
echo "Download Blackweb Project..."
git clone https://github.com/maravento/blackweb.git
echo "OK"

# CREATE DIR
if [ ! -d $bw/bl ]; then mkdir -p $bw/bl; fi
if [ ! -d /etc/acl ]; then mkdir -p /etc/acl; fi

# DOWNLOAD BL
echo "Download Public Bls..."
cd $bw
tar -C bl -xvzf blackweb.tar.gz >/dev/null 2>&1
sed -e '/^#/d' blackurls.txt | sort -u >> bl/bls.txt

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

# DOWNLOAD TLDS
echo "Download Public TLDs..."
cd $bw

function iana() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/' | sed -e '/^#/d' | sed 's/^/./' | sort -u >> ptlds.txt
}
	iana 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'

function suffix() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | grep -v "//" | grep -ve "^$" | sed 's:\(.*\):\.\1:g' | sort -u | grep -v -P "[^a-z0-9_.-]" >> ptlds.txt
}
	suffix 'https://publicsuffix.org/list/public_suffix_list.dat'

echo "OK"

# JOINT WHITELIST
echo "Joint Whitelist..."
cd $bw
sed -e '/^#/d' {ptlds,whiteurls,whitetlds}.txt | sort -u > tlds.txt
echo "OK"

# CAPTURE AND DELETE OVERLAPPING DOMAINS
echo "Capture Domains..."
cd $bw
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'
find bl -type f -execdir egrep -oi "$regexd" {} \; | awk '{print "."$1}' | sort -u | sed 's:\(www\.\|WWW\.\|www0\.\|www1\.\|www2\.\|www3\.\|www4\.\|www5\.\|www6\.\|www7\.\|www8\.\|www9\.\|www10\.\|www11\.\|www12\.\|www13\.\|www14\.\|www15\.\|www16\.\|www17\.\|www18\.\|www19\.\|www20\.\|www01\.\|www02\.\|www03\.\|www04\.\|www05\.\|www06\.\|www07\.\|www08\.\|www09\.\|ww1\.\|ww2\.\|ww3\.\|ww4\.\|ww5\.\|ww6\.\|ww7\.\|ww8\.\|ww9\.\|www1bpt\.\|wws\.\|wwcampus\.\|wwater\.\|wwwsshe\.\|wwwpub\.\|wwwstaff\.\|wwwstd\.\|wwwi\.\|wwwlb\.\|wwwfac\.\|wwwvet\.\|wwwscience\.\|wwwpathnet\.\|wwwshs1\.\|wwwlibrary\.\|wwwdb\.\|wws2\.\|www2a\.\|wwwdir\.\|ftp\.\|/.*\)::g' > bldomains.txt
echo "OK"

echo "Delete Overlapping..."
chmod +x parse_domain.py && python parse_domain.py | sort -u > blackweb.txt
cp -f {blackweb,blackdomains,whitedomains}.txt /etc/acl >/dev/null 2>&1
cd
rm -rf $bw

# LOG
date=`date +%d/%m/%Y" "%H:%M:%S`
echo "Blackweb Update for Squid: ejecucion $date" >> /var/log/syslog.log
echo "Done"
