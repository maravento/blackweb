## [Blackweb](http://www.maravento.com/p/blacklistweb.html)

**Blackweb** es un proyecto que pretende recopilar la mayor cantidad de listas negras públicas de dominios (para bloquear porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, venta de armas, etc), con el objeto de unificarlas y hacerlas compatibles con [Squid-Cache](http://www.squid-cache.org/) (Tested in v3.5.x). Para lograrlo, realizamos una depuración de urls, para evitar duplicados, dominios inválidos (validación de ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), y un filtrado con listas blancas de dominios (falsos positivos, como google, hotmail, yahoo, etc), para obtener una mega ACL, optimizada para [Squid-Cache](http://www.squid-cache.org/), libre de "overlapping domains" (e.g: "ERROR: '.sub.example.com' is a subdomain of '.example.com'").

**Blackweb** is a project that aims to collect as many public domain blacklists (to block porn, downloads, drugs, malware, spyware, trackers, Bots, social networks, warez, arms sales, etc.), in order to unify them and make them compatible with [Squid-Cache](http://www.squid-cache.org/) (Tested in v3.5.x ). To do this, we perform a debugging of urls, to avoid duplicates, invalid domains (validation, ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), and filter with white lists of domains (false positives such as google , hotmail, yahoo, etc.), to get a mega ACL, optimized for [Squid-Cache](http://www.squid-cache.org/), free of overlapping domains (eg: "ERROR: '.sub.example.com' is a subdomain of '.example.com'").

### FICHA TECNICA / DATA SHEET
---

|ACL|Black Domains|txt size|tar.gz size|
|---|-------------|--------|-----------|
|blackweb.txt|2.441.780|57,4 MB|12,2 MB|

### DEPENDENCIAS / DEPENDENCIES
---
```
git squid bash tar zip wget subversion python
```

### GIT CLONE
---
```
git clone --depth=1 https://github.com/maravento/blackweb.git
```

### MODO DE USO / HOW TO USE
---

La ACL **blackweb.txt** ya viene optimizada para [Squid-Cache](http://www.squid-cache.org/). Descárguela y descomprimala en la ruta de su preferencia / The ACL **blackweb.txt** is already optimized for [Squid-Cache](http://www.squid-cache.org/). Download it and unzip it in the path of your preference

#####  Download and Checksum

```
wget -q -N https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz && cat blackweb.tar.gz* | tar xzf -
wget -q -N https://raw.githubusercontent.com/maravento/blackweb/master/checksum.md5
md5sum blackweb.txt | awk '{print $1}' && cat checksum.md5 | awk '{print $1}'
```
### ACTUALIZACIÓN / UPDATE
---

El script **bwupdate.sh** descarga las [FUENTES](https://github.com/maravento/blackweb#fuentes--sources), las depura, unifica y elimina los dominios superpuestos. Una vez terminado verifique los logs de Squid y si aún existe algún error deberá depurarlo manualmente de **blackweb** / The **bwupdate.sh** script downloads the [SOURCES](https://github.com/maravento/blackweb#fuentes--sources), purifies, unifies and removes overlapping domains. Once finished check the Squid logs and if there is still an error you must manually debug it from **blackweb**

```
wget -q -N https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/bwupdate.sh && sudo chmod +x bwupdate.sh && sudo ./bwupdate.sh
```

##### Advertencia / Warning

- Antes de utilizar **bwupdate.sh** debe activar la regla en [Squid-Cache](http://www.squid-cache.org/) / You must activate the rule in [Squid-Cache](http://www.squid-cache.org/) before using **bwupdate.sh**
- Para reducir el tamaño de **blackweb** (eliminando dominios inactivos/muertos o inválidos) puede utilizar [PyFunceble](https://github.com/funilrys/PyFunceble) (Rápida pero inestable) o [httpstatus](https://github.com/maravento/blackweb/raw/master/bwupdate/tools/httpstatus.sh) (Lenta pero Estable. Incluida) / To reduce the size of **blackweb** (eliminating inactive/dead or invalid domains) can use [PyFunceble](https://github.com/funilrys/PyFunceble) (Fast but unstable) or [httpstatus](https://github.com/maravento/blackweb/raw/master/bwupdate/tools/httpstatus.sh) (Slow but Stable. Included)
- El proceso de actualización y depuración de **blackweb** puede tardar mucho tiempo y consumir muchos recursos de hardware y ancho de banda / The process of updating and debugging of **blackweb** can take a long time and consume many hardware resources and bandwidth
- El path por default de **blackweb** es **/etc/acl**. Puede cambiarlo por el directorio de su preferencia / The default path of **blackweb** is **/etc/acl**. You can change it by the directory of your preference
- **bwupdate.sh** no incluye clouds (Mega, Dropbox, Pcloud, iCloud, etc) o de soporte remoto (Teamviewer, Anydesk, logmein, etc), excepto si ya vienen bloqueados desde las [FUENTES](https://github.com/maravento/blackweb#fuentes--sources). Para bloquearlos o excluirlos debe activar la línea según su elección: / **bwupdate.sh** does not include clouds (Mega, Dropbox, Pcloud, iCloud, etc) or remote support (Teamviewer, Anydesk, logmein, etc), except if they are already blocked from the [SOURCES](https://github.com/maravento/blackweb#fuentes--sources). To block or exclude them you must activate the line according to your choice:

```
# JOIN LIST
# unblock
#sed '/^$/d; /#/d' lst/{cloudsync,remoteurls}.txt | sort -u >> urls.txt
# block
#sed '/^$/d; /#/d' lst/{cloudsync,remoteurls}.txt | sort -u >> bwtmp/bw.txt
```

### REGLA [Squid-Cache](http://www.squid-cache.org/) / [Squid-Cache](http://www.squid-cache.org/) RULE
---

Edite / Edit:
```
/etc/squid/squid.conf
```
Y agregue las siguientes líneas: / And add the following lines:

```
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
acl blackweb dstdomain -i "/path_to_acl/blackweb.txt"
http_access deny blackweb
```
##### MUY IMPORTANTE (Edición Blackweb) / VERY IMPORTANT (Blackweb Edition)

**Blackweb** contiene millones de dominios bloqueados, por tanto: / **Blackweb** contains millions of blocked domains, so:

- Utilice la ACL **whitedomains** para excluir dominios falsos positivos (y repórtelo) u otros dominios que quiera excluir (ejemplo: accounts.youtube.com [desde Feb 2014, Google utiliza el subdominio accounts.youtube.com para autenticar sus servicios](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube)) / Use the ACL **whitedomains** to exclude false-positive (and report it) domains or other domains that you want to exclude (e.g.: accounts.youtube.com [since Feb 2014, Google uses the subdomain accounts.youtube.com to authenticate its services](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube))
- Utilice la ACL **blackdomains** para agregar dominios no incluidos en **Blackweb** (ejemplo: .youtube.com .googlevideo.com, .ytimg.com, etc.) / Use the ACL **blackdomains** to add domains not included in **Blackweb** (e.g.: .youtube.com .googlevideo.com, .ytimg.com, etc)

```
acl whitedomains dstdomain -i "/path_to_acl/whitedomains.txt"
acl blackdomains dstdomain -i "/path_to_acl/blackdomains.txt"
acl blackweb dstdomain -i "/path_to_acl/blackweb.txt"
http_access allow whitedomains
http_access deny blackdomains
http_access deny blackweb
```

### FUENTES / SOURCES
---

##### Blacklists

[Adaway](http://adaway.org/hosts.txt)

[adblockplus malwaredomains_full](https://easylist-downloads.adblockplus.org/malwaredomains_full.txt)

[ABPindo indonesianadblockrules](https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt)

[Anti-WebMiner](https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt)

[anudeepND](https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt)

[BambenekConsulting](http://osint.bambenekconsulting.com/feeds/dga-feed.txt)

[betterwebleon dga-feed](https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt)

[Capitole - Direction du Système d'Information (DSI)](http://dsi.ut-capitole.fr/blacklists/download/)

[Carl Spam](http://www.carl.net/spam/access.txt)

[cedia.org.ec](https://mirror.cedia.org.ec) (included: [domains](https://mirror.cedia.org.ec/malwaredomains/domains.txt), [immortal_domains](https://mirror.cedia.org.ec/malwaredomains/immortal_domains.txt))

[chadmayfield](https://github.com/chadmayfield) (included: [porn_all](https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list), [porn top](https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list))

[CHEF-KOCH BarbBlock-filter-list](https://github.com/CHEF-KOCH/BarbBlock-filter-list)

[Cibercrime-Tracker](http://cybercrime-tracker.net/all.php)

[crazy-max WindowsSpyBlocker](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt)

[Dawsey21 List](https://github.com/Dawsey21/Lists)

[Disconnect.me](https://disconnect.me/) (included: [simple_ad](https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt), [simple_malvertising](https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt), [simple_tracking](https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt))

[dshield.org](http://www.dshield.org) (included: [Low](http://www.dshield.org/feeds/suspiciousdomains_Low.txt), [Medium](https://www.dshield.org/feeds/suspiciousdomains_Medium.txt), [High](https://www.dshield.org/feeds/suspiciousdomains_High.txt))

[ethanr dns-blacklists](https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt)

[firebog.net](firebog.net) (included: [AdguardDNS](https://v.firebog.net/hosts/AdguardDNS.txt), [Airelle-hrsk](https://v.firebog.net/hosts/Airelle-hrsk.txt), [Airelle-trc](https://v.firebog.net/hosts/Airelle-trc.txt), [BillStearns](https://v.firebog.net/hosts/BillStearns.txt), [Easylist](https://v.firebog.net/hosts/Easylist.txt), [Easyprivacy](https://v.firebog.net/hosts/Easyprivacy.txt), [Kowabit](https://v.firebog.net/hosts/Kowabit.txt), [Prigent-Ads](https://v.firebog.net/hosts/Prigent-Ads.txt), [Prigent-Malware](https://v.firebog.net/hosts/Prigent-Malware.txt), [Prigent-Phishing](https://v.firebog.net/hosts/Prigent-Phishing.txt), [Shalla-mal](https://v.firebog.net/hosts/Shalla-mal.txt), [WaLLy3K](https://v.firebog.net/hosts/static/w3kbl.txt))

[gfmaster adblock-korea](https://raw.githubusercontent.com/gfmaster/adblock-korea-contrib/master/filter.txt)

[Halt-and-Block-Mining](https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat)

[hexxium](https://hexxiumcreations.github.io/threat-list/hexxiumthreatlist.txt)

[hostsfile.mine.nu](https://hostsfile.mine.nu/hosts0.txt)

[hosts-file.net](https://hosts-file.net) (included: [ad_servers](https://hosts-file.net/ad_servers.txt), [emd](https://hosts-file.net/emd.txt), [grm](https://hosts-file.net/grm.txt), [hosts](http://hosts-file.net/download/hosts.txt), [psh](https://hosts-file.net/psh.txt))

[Joelotz URL Blacklist](https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv)

[Joewein Blacklist](http://www.joewein.de/sw/bl-text.htm)

[KADhosts](https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt)

[malc0de](http://malc0de.com/bl/)

[Malwaredomains](http://www.malware-domains.com/files/domains.zip)

[Malwaredomainlist Hosts](http://www.malwaredomainlist.com/hostslist/hosts.txt)

[Malware-domains](http://mirror1.malwaredomains.com/files/justdomains) (or [Lehigh Malwaredomains](http://malwaredomains.lehigh.edu/files/justdomains))

[margevicius easylistlithuania](http://margevicius.lt/easylistlithuania.txt)

[Matomo-org referrer-spam-blacklist](https://github.com/matomo-org/referrer-spam-blacklist/blob/master/spammers.txt)

[MESD blacklists](http://squidguard.mesd.k12.or.us/blacklists.tgz)

[mitchellkrogza](https://github.com/mitchellkrogza) (included: [Badd-Boyz-Hosts](https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/PULL_REQUESTS/domains.txt), [Hacked Malware Web Sites](https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/.dev-tools/_strip_domains/domains.txt), [Nginx Ultimate Bad Bot Blocker](https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list), [The Big List of Hacked Malware Web Sites](https://github.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/blob/master/hacked-domains.list), [Ultimate Hosts Blacklist](https://github.com/mitchellkrogza/Ultimate.Hosts.Blacklist))

[notabug latvian-list](https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt)

[Oleksiig Blacklist](https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf)

[openphish](https://openphish.com/feed.txt)

[Perflyst](https://github.com/Perflyst) (included: [android-tracking](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt), [SmartTV](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt))

[Quedlin blacklist](https://github.com/quedlin/blacklist/blob/master/domains)

[quidsup](https://gitlab.com/quidsup) (included: [notrack-blocklists](https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt), [notrack-malware](https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt), [trackers](https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt), [qmalware](https://raw.githubusercontent.com/quidsup/notrack/master/malicious-sites.txt))

[Ransomware Abuse](https://ransomwaretracker.abuse.ch/blocklist/) (included: [CryptoWall](https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt), [Locky](https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt), [Domain Blocklist](https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt), [Ransomware Abuse](https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt) ,[URL Blocklist ](https://ransomwaretracker.abuse.ch/downloads/TC_C2_DOMBL.txt),[TorrentLocker](https://ransomwaretracker.abuse.ch/downloads/TL_C2_DOMBL.txt))

[reddestdream](https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts)

[securemecca.net and hostsfile.org](https://hostsfile.org/Downloads/hosts.txt)

[Shallalist.de](http://www.shallalist.de/Downloads/shallalist.tar.gz)

[Someonewhocares](http://someonewhocares.org/hosts/hosts)

[squidblacklist.org](https://www.squidblacklist.org/) (included: [dg-ads](https://www.squidblacklist.org/downloads/dg-ads.acl), [dg-malicious.acl](https://www.squidblacklist.org/downloads/dg-malicious.acl))

[StevenBlack](https://github.com/StevenBlack) (included: [add.2o7Net](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts), [add.Risk](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts), [fakenews-gambling-porn-social](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts), [hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts), [spam](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts), [uncheckyAds](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts))

[Stopforumspam Toxic Domains](https://www.stopforumspam.com/downloads/toxic_domains_whole.txt)

[tankmohit UnifiedHosts](https://raw.githubusercontent.com/tankmohit/UnifiedHosts/master/hosts.all)

[Taz SpamDomains](http://www.taz.net.au/Mail/SpamDomains)

[vokins yhosts](https://raw.githubusercontent.com/vokins/yhosts/master/hosts)

[Winhelp2002](http://winhelp2002.mvps.org/hosts.txt)

[YousList](https://raw.githubusercontent.com/yous/YousList/master/youslist.txt)

[Yoyo](http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)

[zerodot1 CoinBlockerLists](https://gitlab.com/ZeroDot1/CoinBlockerLists) (included: [Host](https://zerodot1.gitlab.io/CoinBlockerLists/hosts), [host_browser](https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser), [host_optional](https://zerodot1.gitlab.io/CoinBlockerLists/hosts_optional), [list](https://zerodot1.gitlab.io/CoinBlockerLists/list.txt), [list_browser](https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt), [list_browser_UBO](https://zerodot1.gitlab.io/CoinBlockerLists/list_browser_UBO.txt))

[Zeustracker](https://zeustracker.abuse.ch/blocklist.php?download=squiddomain)

##### Discontinued Lists

[UrlBlacklist](https://web.archive.org/web/*/http://urlblacklist.com) ([Server Down since July 24, 2017](https://groups.google.com/forum/#!topic/e2guardian/7WeHpD-54LE))

[Passwall SpamAssassin](http://www.passwall.com/blacklist.txt) ([Server Down since Dec 2016](https://web.archive.org/web/20161203014003/http://www.passwall.com/blacklist.txt))

[Central Repo Dead Domains](https://github.com/mitchellkrogza/CENTRAL-REPO.Dead.Inactive.Whitelisted.Domains.For.Hosts.Projects/blob/master/DOMAINS-dead.txt) (Last Update included in [Inactive Domains](https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/inactive.txt))

##### Debug Lists

###### Internals

[BlackTLDs](https://github.com/maravento/blackweb/raw/master/bwupdate/lst/blacktlds.txt)

[BlackURLs](https://github.com/maravento/blackweb/raw/master/bwupdate/lst/blackurls.txt)

[WhiteURLs](https://github.com/maravento/blackweb/raw/master/bwupdate/lst/whiteurls.txt)

[CloudSync](https://github.com/maravento/blackweb/raw/master/bwupdate/lst/cloudsync.txt)

[RemoteURLs](https://github.com/maravento/blackweb/raw/master/bwupdate/lst/remoteurls.txt)

[Errors](https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/error.txt)

[Invalid Domains](https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/invalid.txt)

[Inactive Domains](https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/inactive.txt)

###### Externals

[ipv6-hosts](https://raw.githubusercontent.com/lennylxx/ipv6-hosts/master/hosts) (Partial)

[O365IPAddresses](https://support.content.office.net/en-us/static/O365IPAddresses.xml) (Partial)

[Ransomware Database](https://docs.google.com/spreadsheets/u/1/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml#)

[University Domains and Names Data List](https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json)

[TLDs](https://raw.githubusercontent.com/maravento/tlds/master/tlds.txt)

[BadTLDs](https://raw.githubusercontent.com/maravento/tlds/master/badtlds.txt)

##### Tools

###### Internals

[Debugging list](https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/tools/debug.py)

[Parse Domains](https://raw.githubusercontent.com/lsemel/python-parse-domain/master/tools/parse_domain.py) ([modified by Maravento](https://github.com/maravento/blackweb/raw/master/bwupdate/tools/parse_domain.py))

[httpstatus](https://github.com/maravento/blackweb/raw/master/bwupdate/tools/httpstatus.sh)

###### Externals

[CTFR](https://github.com/UnaPibaGeek/ctfr)

[PyFunceble](https://github.com/funilrys/PyFunceble)

### CONTRIBUCIONES / CONTRIBUTIONS
---

Agradecemos a todos aquellos que han contribuido a este proyecto. Los interesados pueden contribuir, enviándonos enlaces de nuevas listas, para ser incluidas en este proyecto / We thank all those who have contributed to this project. Those interested can contribute, sending us links of new lists, to be included in this project
Special thanks to: [Jhonatan Sneider](https://github.com/sney2002)

### DONACION / DONATE
---

BTC: 3M84UKpz8AwwPADiYGQjT9spPKCvbqm4Bc

### LICENCIAS / LICENCES
---

[![GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl.txt)

[![CreativeCommons](https://licensebuttons.net/l/by-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-sa/4.0/)
[maravento.com](http://www.maravento.com) is licensed under a [Creative Commons Reconocimiento-CompartirIgual 4.0 Internacional License](http://creativecommons.org/licenses/by-sa/4.0/).

© 2019 [Maravento Studio](http://www.maravento.com)

### EXENCION DE RESPONSABILIDAD / DISCLAIMER
---

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
