#!/bin/bash
### BEGIN INIT INFO
# Provides:	     blackweb
# Required-Start:    $local_fs $remote_fs $network $syslog $named
# Required-Stop:     $local_fs $remote_fs $network $syslog $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts blackweb update
# Description:       starts blackweb using start-stop-daemon
### END INIT INFO

# by:	maravento.com and novatoz.com

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

# REGEXD
regexd='([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.){1,}(\.?[a-zA-Z]{2,}){1,}'

# DEL OLD REPOSITORY AND FILES
if [ -d $bw ]; then rm -rf $bw; fi

# GIT CLONE BLACLISTWEB
echo
echo "Download Blackweb..."
git clone --depth=1 https://github.com/maravento/blackweb.git  >/dev/null 2>&1
echo "OK"

# CHECKING SUM
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
		sed -e '/^#/d' blackurls.txt | sort -u >> bl/bltmp.txt
		rm bl/blackweb.md5 bl/blackweb.tar.gz*
		echo "OK"
	else
		echo "Bad Sum. Abort"
		echo "${cm2[${es}]}"
		cd
		rm -rf $bw
		exit
fi

# DOWNLOAD PUBLIC BLS
echo
echo "Download Public BLs..."

# FILES
function bldownload() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | sort -u >> bl/bltmp.txt
}
	bldownload 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml' && sleep 1
	bldownload 'http://malwaredomains.lehigh.edu/files/justdomains' && sleep 1
	bldownload 'https://easylist-downloads.adblockplus.org/malwaredomains_full.txt' && sleep 1
	bldownload 'https://zeustracker.abuse.ch/blocklist.php?download=squiddomain' && sleep 1
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
	bldownload 'https://db.aa419.org/fakebankslist.php' && sleep 1
	bldownload 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list' && sleep 1
	bldownload 'https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/.dev-tools/_strip_domains/domains.txt' && sleep 1
	bldownload 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt' && sleep 1
	bldownload 'http://www.taz.net.au/Mail/SpamDomains' && sleep 1
	bldownload 'http://www.carl.net/spam/access.txt' && sleep 1
	bldownload 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts' && sleep 1
	#bldownload 'http://someonewhocares.org/hosts/hosts' && sleep 1 # replaced by StevenBlack Host
	#bldownload 'https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt' && sleep 1 # replaced by StevenBlack Host
	#bldownload 'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/PULL_REQUESTS/domains.txt' && sleep 1 # replaced by StevenBlack Host
	#bldownload 'http://www.passwall.com/blacklist.txt' && sleep 1 # out of date (included in blackurls.txt)

function blzip() {
    wget -q -c --retry-connrefused -t 0 "$1" && unzip -p domains.zip >> bl/bltmp.txt
}
	blzip 'http://www.malware-domains.com/files/domains.zip' && sleep 1

function superh() {
    wget -q -c --retry-connrefused -t 0 "$1" && unzip -p superhosts.deny.zip >> bl/bltmp.txt
}
	superh 'https://raw.githubusercontent.com/mitchellkrogza/Ultimate.Hosts.Blacklist/master/superhosts.deny.zip' && sleep 1

# DIR
function bltar() {
    wget -q -c --retry-connrefused -t 0 "$1" && for F in *.tar.gz; do R=$RANDOM ; mkdir bl/$R ; tar -C bl/$R -zxvf $F -i; done >/dev/null 2>&1
}
	bltar 'http://www.shallalist.de/Downloads/shallalist.tar.gz' && sleep 2
	bltar 'http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz' && sleep 2

function blgz() {
    wget -q -c --retry-connrefused -t 0 "$1" && for F in *.tgz; do R=$RANDOM ; mkdir bl/$R ; tar -C bl/$R -zxvf $F -i; done >/dev/null 2>&1
}
	blgz 'http://squidguard.mesd.k12.or.us/blacklists.tgz' && sleep 2

#function blbig() {
    #wget -q -c --retry-connrefused -t 0 "$1" -O bigblacklist.tar.gz && for F in bigblacklist.tar.gz; do R=$RANDOM ; mkdir bl/$R ; tar -C bl/$R -zxvf $F -i; done >/dev/null 2>&1
#}
	#blbig 'http://urlblacklist.com/cgi-bin/commercialdownload.pl?type=download&file=bigblacklist' && sleep 2

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

function univ() {
    wget -q -c --retry-connrefused -t 0 "$1" -O - | egrep -oi "$regexd" | awk '{print "."$1}' | grep -Pvi '(.htm(l)?|.the|.php(il)?)$' | sort -u | sed 's:\(www[[:alnum:]]*\.\|WWW[[:alnum:]]*\.\|ftp\.\|\.\.\.\|/.*\)::g' >> whiteurls.txt
}
    univ 'https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json'

echo "OK"

# DEBUGGING WHITELIST
echo
echo "Debugging Whitelist..."
sed -e '/^#/d' whitetlds.txt | sort -u > tlds.txt
sed -e '/^#/d' {invalid,whiteurls}.txt | sort -u > urls.txt
echo "OK"

# CAPTURE DOMAINS
echo
echo "Capture Domains..."
find bl -type f -execdir egrep -oi "$regexd" {} \; | awk '{print "."$1}' | sort -u | sed 's:\(www[[:alnum:]]*\.\|WWW[[:alnum:]]*\.\|ftp\.\|\.\.\.\|/.*\)::g' > bl.txt
echo "OK"

# DELETE OVERLAPPING DOMAINS
echo
echo "Delete Overlapping Domains..."
chmod +x parse_domain.py
python parse_domain.py | sort -u > blackweb.txt
echo "OK"

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
