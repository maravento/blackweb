## [Blackweb](http://www.maravento.com/p/blacklistweb.html)

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl.txt)
[![GitHub version](https://img.shields.io/badge/Version-1.0-yellowgreen.svg)](http://www.maravento.com/p/blacklistweb.html)

**Blackweb** es un proyecto que pretende recopilar la mayor cantidad de listas negras públicas de dominios (para bloquear porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, venta de armas, etc), con el objeto de unificarlas y hacerlas compatibles con [Squid-Cache](http://www.squid-cache.org/) (Tested in v3.5.x). Para lograrlo, realizamos una depuración de urls, para evitar duplicados, dominios inválidos (validación de ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), y un filtrado con listas blancas de dominios (falsos positivos, como google, hotmail, yahoo, etc), para obtener una mega ACL, optimizada para [Squid-Cache](http://www.squid-cache.org/), libre de "overlapping domains" (e.g: "ERROR: '.sub.example.com' is a subdomain of '.example.com'").

**Blackweb** is a project that aims to collect as many public domain blacklists (to block porn, downloads, drugs, malware, spyware, trackers, Bots, social networks, warez, arms sales, etc.), in order to unify them and make them compatible with [Squid-Cache](http://www.squid-cache.org/) (Tested in v3.5.x ). To do this, we perform a debugging of urls, to avoid duplicates, invalid domains (validation, ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), and filter with white lists of domains (false positives such as google , hotmail, yahoo, etc.), to get a mega ACL, optimized for [Squid-Cache](http://www.squid-cache.org/), free of overlapping domains (eg: "ERROR: '.sub.example.com' is a subdomain of '.example.com'").

### FICHA TECNICA / DATA SHEET
---

|File|BL Domains|File size|
|----|----------|---------|
|blackweb.txt|2.080.749|50,5 MB|

### DEPENDENCIAS / DEPENDENCIES
---
```
git squid bash tar zip wget subversion python
```

### DESCARGA / DOWNLOAD
---
```
git clone --depth=1 https://github.com/maravento/blackweb.git
```

### MODO DE USO / HOW TO USE
---

La ACL **blackweb.txt** ya viene optimizada para [Squid-Cache](http://www.squid-cache.org/). Descárguela con **blackweb.sh**. Por defecto, la ruta de **blackweb.txt** es **/etc/acl**. Ejemplo:

The ACL **blackweb.txt** is already optimized for [Squid-Cache](http://www.squid-cache.org/). Download it with **blackweb.sh**. By default, **blackweb.txt** path is **/etc/acl**. Example:

```
wget -q -N https://github.com/maravento/blackweb/raw/master/blackweb.sh && sudo chmod +x blackweb.sh && sudo ./blackweb.sh
```
### ACTUALIZACIÓN / UPDATE
---

El script **bwupdate.sh** actualiza la ACL **blackweb.txt**, realizando la captura, depuración y limpieza de dominios, sin embargo puede generar conflíctos por errores en las [fuentes](https://github.com/maravento/blackweb#fuentes--sources), por tanto deberá depurarlos manualmente. Tenga en cuenta que este script consume gran cantidad de recursos de hardware durante el procesamiento y puede tardar horas o días.

The **bwupdate.sh** script updates **blackweb.txt** ACL, doing the capture, debugging and cleaning of domains, however it can generate conflicts for errors in the [sources](https://github.com/maravento/blackweb#fuentes--sources), therefore you must manually debug conflicts. Keep in mind that this script consumes a lot of hardware resources during processing and can take hours or days
 
```
wget -q -N https://github.com/maravento/blackweb/raw/master/bwupdate/bwupdate.sh && sudo chmod +x bwupdate.sh && sudo ./bwupdate.sh
```
#####  Verifique la ejecución / Check execution

path: /var/log/syslog

```
Blackweb for Squid: Done 06/05/2017 15:47:14
```
Y verifique el contenido del archivo **SquidError.txt** en su escritorio para corregirlos / And check the contents of the **SquidError.txt** file on your desktop to fix them

##### Importante Antes de Usar / Important Before Use

- Puede incluir su propia Blacklist, que quiera bloquear y que no se encuentre en **blackweb.txt**, editando el script **bwupdate.sh** y descomentando en **ADD OWN LIST** la línea **/path/blackweb_own.txt** y reemplazandola por la ruta hacia su propia lista / You can include your own Blacklist, which you want to block and which is not in **blackweb.txt**, by editing the **bwupdate.sh** script and decomposing the line **/path/blackweb_own.txt** in **ADD OWN LIST** and replacing it with the path to your own list
- La ACL **cloudsync.txt** contiene servicios appcloud (diferentes a onedrive y gdrive), como dropbox, pcloud, mega, etc., y la ACL **remoteurls.txt** contiene servicios remotos, como Teamviewer, Anydesk, Logmein, etc. Por defecto se excluyen de **blackweb.txt**. Para modificarlo, edite **bwupdate.sh**, busque y elimine "**,cloudsync,remoteurl**" / The ACL **cloudsync.txt** contains appcloud services (other than onedrive and gdrive), such as dropbox, pcloud, mega, etc., and the ACL **remoteurls.txt** contains remote services, such as Teamviewer, Anydesk, Logmein , etc. By default they are excluded from **blackweb.txt**. To modify it, edit **bwupdate.sh**, search and delete "**,cloudsync,remoteurl**"
- Antes de utilizar **bwupdate.sh** debe activar la regla en [Squid-Cache](http://www.squid-cache.org/) / You must activate the rule in [Squid-Cache](http://www.squid-cache.org/) before using **bwupdate.sh**
- La actualización debe ejecutarse en equipos de pruebas destinados para este propósito. Nunca en servidores en producción. / The update must run on test equipment designed for this purpose. Never on servers in production.

### REGLA [Squid-Cache](http://www.squid-cache.org/) / [Squid-Cache](http://www.squid-cache.org/) RULE
---

Edit /etc/squid/squid.conf:
```
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access deny blackweb
```
### EDICIÓN / EDITION
---

**Blackweb** contiene millones de dominios bloqueados, por tanto, editarla manualmente puede ser frustrante. Entonces, si detecta un falso positivo, utilice la ACL **whitedomains.txt** y reporte el incidente, para corregirlo en la próxima actualización. Lo mismo aplica para dominios no incluidos en **Blackweb**, que quiera bloquear, puede agregarlos en **blackdomains**.

**Blackweb** contains million domains blocked therefore manually editing can be frustrating. Then, if it detects a false positive, use the ACL **whitedomains.txt** and report the incident to correct it in the next update. The same applies for domains not included in **Blackweb**, you want to block, you can add them in **blackdomains**.

```
acl whitedomains dstdomain -i "/etc/acl/whitedomains.txt"
acl blackdomains dstdomain -i "/etc/acl/blackdomains.txt"
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access allow whitedomains
http_access deny blackdomains 
http_access deny blackweb
```

**blackdomains.txt** contiene dominios no incluidos en **Blackweb** (e.g. .youtube.com .googlevideo.com, .ytimg.com) y **whitedomains.txt** contiene el subdominio **accounts.youtube.com** [desde Feb 2014, Google utiliza el subdominio **accounts.youtube.com** para autenticar sus servicios](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube).

**blackdomains.txt** contains domains not included in **Blackweb** (e.g. .youtube.com .googlevideo.com, .ytimg.com) and **whitedomains.txt** contains subdomain **accounts.youtube.com** [since February 2014, Google uses the accounts subdomain .youtube.com to authenticate their services](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube).

### FUENTES / SOURCES
---

##### URLs Blacklists

[Shallalist](http://www.shallalist.de/Downloads/shallalist.tar.gz)

[Capitole - Direction du Système d'Information (DSI)](http://dsi.ut-capitole.fr/blacklists/download/)

[MESD blacklists](http://squidguard.mesd.k12.or.us/blacklists.tgz)

[Yoyo Serverlist](http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)

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

[Tracking Disconnect.me](https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt)

[Carl Spam](http://www.carl.net/spam/access.txt)

[Ultimate Hosts Blacklist](https://github.com/mitchellkrogza/Ultimate.Hosts.Blacklist)

[Hacked Malware Web Sites](https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/.dev-tools/_strip_domains/domains.txt)

[Nginx Ultimate Bad Bot Blocker](https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list)

[Taz SpamDomains](http://www.taz.net.au/Mail/SpamDomains)

[The Big List of Hacked Malware Web Sites](https://github.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/blob/master/hacked-domains.list)

[StevenBlack Hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts)

[Matomo-org referrer-spam-blacklist](https://github.com/matomo-org/referrer-spam-blacklist/blob/master/spammers.txt)

[Quedlin blacklist](https://github.com/quedlin/blacklist/blob/master/domains)

[Joelotz URL Blacklist](https://github.com/joelotz/URL_Blacklist/blob/master/blacklist.csv)

[dshield.org](http://www.dshield.org/feeds/suspiciousdomains_Low.txt)

[Stopforumspam Toxic Domains](https://www.stopforumspam.com/downloads/toxic_domains_whole.txt)

##### URLs Blacklists (Discontinued or Replaced)

[Passwall SpamAssassin](http://www.passwall.com/blacklist.txt) ([Server Down since Dec 2016](https://web.archive.org/web/20161203014003/http://www.passwall.com/blacklist.txt)). [Last Update](https://gutl.jovenclub.cu/wp-content/uploads/2017/05/blacklist.txt)

[UrlBlacklist](https://web.archive.org/web/*/http://urlblacklist.com) ([Server Down since July 24, 2017](https://groups.google.com/forum/#!topic/e2guardian/7WeHpD-54LE))

[Badd-Boyz-Hosts](https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/PULL_REQUESTS/domains.txt), [Someonewhocares](http://someonewhocares.org/hosts/hosts) and [KADhosts](https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt). Replaced by [StevenBlack Hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts)

##### Web Miner

[Anti-WebMiner](https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt)

##### Ransomware

[Ransomware Abuse](https://ransomwaretracker.abuse.ch/blocklist/)

##### External Debugging (URLs/TLDs Whitelists, Invalid Domains, etc)

[TLDs IANA](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)

[TLDs Mozilla Public Suffix](https://publicsuffix.org/list/public_suffix_list.dat)

[Wikipedia Top Level Domains](https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains)

[Whoisxmlapi GTLDs](https://www.whoisxmlapi.com/support/supported_gtlds.php)

[ipv6-hosts](https://raw.githubusercontent.com/lennylxx/ipv6-hosts/master/hosts) (Partial)

[O365IPAddresses](https://support.content.office.net/en-us/static/O365IPAddresses.xml) (Partial)

[University Domains and Names Data List](https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json)

[Central Repo Dead Domains](https://github.com/mitchellkrogza/CENTRAL-REPO.Dead.Inactive.Whitelisted.Domains.For.Hosts.Projects/blob/master/DOMAINS-dead.txt)

##### Internal Debugging (URLs/TLDs Whitelists, Invalid Domains, etc)

[WhiteTLDs](https://github.com/maravento/blackweb/raw/master/bwupdate/whitetlds.txt)

[WhiteURLs](https://github.com/maravento/blackweb/raw/master/bwupdate/whiteurls.txt)

[RemoteURLs](https://github.com/maravento/blackweb/raw/master/bwupdate/remoteurls.txt)

[CloudSync](https://github.com/maravento/blackweb/raw/master/bwupdate/cloudsync.txt)

[BlackURLs](https://github.com/maravento/blackweb/raw/master/bwupdate/blackurls.txt)

[Common Errors](https://github.com/maravento/blackweb/raw/master/bwupdate/debug.txt)

[Invalid Domains/TLDs](https://github.com/maravento/blackweb/raw/master/bwupdate/invalid.txt)

##### External Tools

[Parse Domains](https://raw.githubusercontent.com/lsemel/python-parse-domain/master/parse_domain.py) ([modified](https://github.com/maravento/blackweb/raw/master/bwupdate/parse_domain.py))

[httpstatus](https://httpstatus.io/)

[CTFR](https://github.com/UnaPibaGeek/ctfr)

##### Internal Tools

[httpstatus bash](https://github.com/maravento/blackweb/raw/master/bwupdate/extools/httpstatus.sh)

[Debugging list](https://github.com/maravento/blackweb/raw/master/bwupdate/extools/debug.py)

### CONTRIBUCIONES / CONTRIBUTIONS
---

Agradecemos a todos aquellos que han contribuido a este proyecto. Los interesados pueden contribuir, enviándonos enlaces de nuevas listas, para ser incluidas en este proyecto / We thank all those who have contributed to this project. Those interested can contribute, sending us links of new lists, to be included in this project

### DONACION / DONATE
---

BTC: 3M84UKpz8AwwPADiYGQjT9spPKCvbqm4Bc

### LICENCIA / LICENCE
---

[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)

[![License](https://licensebuttons.net/l/by-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-sa/4.0/)
[maravento.com](http://www.maravento.com), [gateproxy.com](http://www.gateproxy.com) and [dextroyer.com](http://www.dextroyer.com) is licensed under a [Creative Commons Reconocimiento-CompartirIgual 4.0 Internacional License](http://creativecommons.org/licenses/by-sa/4.0/).

© 2018 [Maravento Studio](http://www.maravento.com)

### EXENCION DE RESPONSABILIDAD / DISCLAIMER
---

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
