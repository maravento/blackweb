## [Blackweb](http://www.maravento.com/p/blacklistweb.html)

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl.txt)
[![Version](https://img.shields.io/badge/Development-ALPHA-blue.svg)](https://img.shields.io/badge/Development-ALPHA-blue.svg)

[Blackweb](http://www.maravento.com/p/blacklistweb.html) es un proyecto que pretende recopilar la mayor cantidad de listas negras públicas de dominios (para bloquear porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, venta de armas, etc), con el objeto de unificarlas y hacerlas compatibles con [Squid-Cache](http://www.squid-cache.org/) (Tested in v3.5.x). Para lograrlo, realizamos una depuración de urls, para evitar duplicados, dominios inválidos (validación de ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), y un filtrado con listas blancas de dominios (falsos positivos, como google, hotmail, yahoo, etc), para obtener una mega ACL, optimizada para [Squid-Cache](http://www.squid-cache.org/), libre de "overlapping domains" (e.g: "ERROR: '.sub.example.com' is a subdomain of '.example.com'").

[Blackweb](http://www.maravento.com/p/blacklistweb.html) is a project that aims to collect as many public domain blacklists (to block porn, downloads, drugs, malware, spyware, trackers, Bots, social networks, warez, arms sales, etc.), in order to unify them and make them compatible with [Squid-Cache](http://www.squid-cache.org/) (Tested in v3.5.x ). To do this, we perform a debugging of urls, to avoid duplicates, invalid domains (validation, ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), and filter with white lists of domains (false positives such as google , hotmail, yahoo, etc.), to get a mega ACL, optimized for [Squid-Cache](http://www.squid-cache.org/), free of overlapping domains (eg: "ERROR: '.sub.example.com' is a subdomain of '.example.com'").

### Descripción / Description

|File|BL Domains|File size|
|----|----------|---------|
|blackweb.txt|8.341.485|193,4 MB|

### Dependencias / Dependencies

```
git squid bash tar zip wget subversion python
```
### Modo de uso / How to use

La ACL **blackweb.txt** ya viene optimizada para [Squid-Cache](http://www.squid-cache.org/). Descárguela con **blackweb.sh**. Por defecto, la ruta de **blackweb.txt** es **/etc/acl** y del script **blackweb.sh** es **/etc/init.d** / The ACL **blackweb.txt** is already optimized for [Squid-Cache](http://www.squid-cache.org/). Download it with **blackweb.sh**. By default, **blackweb.txt** path is **/etc/acl** and the script **blackweb.sh** is **/etc/init.d**

```
wget https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.sh -O /etc/init.d/blackweb.sh
sudo chown root:root /etc/init.d/blackweb.sh && sudo chmod +x /etc/init.d/blackweb.sh
sudo /etc/init.d/blackweb.sh
```
### Actualización BLs / Update BLs

Puede descargar el proyecto Blackweb y actualizar la ACL **blackweb.txt** en dependencia de sus necesidades. Tenga en cuenta que la captura y depuración de dominios es un proceso lento y puede tardar horas / You can download the Blackweb project and update the ACL **blackweb.txt** depending on your needs. Note that capturing and debugging domains is a slow process and can take hours

```
git clone --depth=1 https://github.com/maravento/blackweb.git
sudo cp -f blackweb/bwupdate.sh /etc/init.d
sudo chown root:root /etc/init.d/bwupdate.sh
sudo chmod +x /etc/init.d/bwupdate.sh
sudo /etc/init.d/bwupdate.sh
```
#####  Verifique su ejecución / Check execution (/var/log/syslog):

Ejecución exitosa / Successful execution
```
Blackweb for Squid: Done 06/05/2017 15:47:14
```
Ejecución fallida / Execution failed

```
Blackweb for Squid: Abort 06/05/2017 15:47:14 Check Internet Connection
```

### Regla de [Squid-Cache](http://www.squid-cache.org/) / [Squid-Cache](http://www.squid-cache.org/) Rule

Edit /etc/squid/squid.conf:
```
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access deny blackweb
```
### Edición / Edition

**Blackweb** contiene millones de dominios bloqueados, por tanto, editarla manualmente puede ser frustrante. Entonces, si detecta un falso positivo, utilice la ACL **whitedomains.txt** y reporte el incidente, para corregirlo en la próxima actualización. Lo mismo aplica para dominios no incluidos en **Blackweb**, que quiera bloquear, puede incluirlos en **blackdomains** / **Blackweb** contains million domains blocked therefore manually editing can be frustrating. Then, if it detects a false positive, use the ACL **whitedomains.txt** and report the incident to correct it in the next update. The same applies for domains not included in **Blackweb**, you want to block, you can include them in **blackdomains**

```
acl whitedomains dstdomain -i "/etc/acl/whitedomains.txt"
acl blackdomains dstdomain -i "/etc/acl/blackdomains.txt"
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access allow whitedomains
http_access deny blackdomains 
http_access deny blackweb
```

**blackdomains.txt** contiene dominios no incluidos en **Blackweb** (e.g. .youtube.com .googlevideo.com, .ytimg.com) y **whitedomains.txt** contiene el subdominio **accounts.youtube.com** [desde Feb 2014, Google utiliza el subdominio **accounts.youtube.com** para autenticar sus servicios](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube) / **blackdomains.txt** contains domains not included in **Blackweb** (e.g. .youtube.com .googlevideo.com, .ytimg.com) and **whitedomains.txt** contains subdomain **accounts.youtube.com** [since February 2014, Google uses the accounts subdomain .youtube.com to authenticate their services](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube).

### Data Sheet (Sources)

##### Blacklists

[Shallalist](http://www.shallalist.de/Downloads/shallalist.tar.gz)

[UrlBlacklist](http://urlblacklist.com/?sec=download) ([Server Down since July 2017](https://groups.google.com/forum/#!topic/e2guardian/7WeHpD-54LE))

[Capitole - Direction du Système d'Information (DSI)](http://dsi.ut-capitole.fr/blacklists/download/)

[MESD blacklists](http://squidguard.mesd.k12.or.us/blacklists.tgz)

[Yoyo Serverlist](http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)

[Passwall SpamAssassin](http://www.passwall.com/blacklist.txt) ([Server Down since Dec 2016](https://web.archive.org/web/20161203014003/http://www.passwall.com/blacklist.txt). Last Update included in [BlackURLs](https://github.com/maravento/blackweb/raw/master/blackurls.txt). [Mirror](https://gutl.jovenclub.cu/wp-content/uploads/2017/05/blacklist.txt))

[Oleksiig Blacklist](https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf)

[HP Hosts-file](http://hosts-file.net/download/hosts.txt)

[Winhelp2002](http://winhelp2002.mvps.org/hosts.txt)

[Cibercrime-Tracker](http://cybercrime-tracker.net/all.php)

[Joewein Blacklist](http://www.joewein.de/sw/bl-text.htm)

[Tracking-Addresses](https://github.com/10se1ucgo/DisableWinTracking/wiki/Tracking-Addresses)

[Adaway](http://adaway.org/hosts.txt)

[Lehigh Malwaredomains](http://malwaredomains.lehigh.edu/files/)

[Easylist for adblockplus](https://easylist-downloads.adblockplus.org/malwaredomains_full.txt)

[Zeus tracker](https://zeustracker.abuse.ch/blocklist.php?download=squiddomain)

[Malwaredomain Hosts List](http://www.malwaredomainlist.com/hostslist/hosts.txt)

[Malware-domains](http://www.malware-domains.com/)

[malc0de](http://malc0de.com/bl/)

[BambenekConsulting](http://osint.bambenekconsulting.com/feeds/dga-feed.txt)

[openphish](https://openphish.com/feed.txt)

[Artists Against 419](https://db.aa419.org/fakebankslist.php)

[Tracking Disconnect.me](https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt)

[Carl Spam](http://www.carl.net/spam/access.txt)

[Taz SpamDomains](http://www.taz.net.au/Mail/SpamDomains)

[StevenBlack Hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts) (Replaces [Badd-Boyz-Hosts](https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/PULL_REQUESTS/domains.txt), [Someonewhocares](http://someonewhocares.org/hosts/hosts) and [KADhosts](https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt))

[Ultimate Super.Hosts Blacklist](https://github.com/mitchellkrogza/Ultimate.Hosts.Blacklist)

[Hacked-Malware-Web-Sites](https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/.dev-tools/_strip_domains/domains.txt)

[NginxBadBotBlocker](https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list)

[BlackURLs](https://github.com/maravento/blackweb/raw/master/blackurls.txt)

##### Ransomware

[Ransomware Abuse](https://ransomwaretracker.abuse.ch/blocklist/)

##### Domains Debugging

[TLDs IANA](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)

[TLDs Mozilla Public Suffix](https://publicsuffix.org/list/public_suffix_list.dat)

[Wikipedia Top Level Domains](https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains)

[WhiteURLs](https://github.com/maravento/blackweb/raw/master/whiteurls.txt)

[Invalid Domains/TLDs](https://github.com/maravento/blackweb/raw/master/invalid.txt)

[RemoteURLs](https://github.com/maravento/remoteip/raw/master/remoteurls.txt)

[ipv6-hosts](https://raw.githubusercontent.com/lennylxx/ipv6-hosts/master/hosts) (Partial)

[O365IPAddresses](https://support.content.office.net/en-us/static/O365IPAddresses.xml) (Partial)

[Parse Domains](https://github.com/lsemel/python-parse-domain/raw/master/parse_domain.py) (modified)

[University Domains and Names Data List](https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json)

[httpstatus](https://httpstatus.io/)

### Contributions

Agradecemos a todos aquellos que han contribuido a este proyecto. Los interesados pueden contribuir, enviándonos enlaces de nuevas "Blacklist", para ser incluidas en este proyecto / We thank all those who contributed to this project. Those interested may contribute sending us new "Blacklist" links to be included in this project

### Licence

[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)

© 2017 [Maravento Studio](http://www.maravento.com)

#### Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
