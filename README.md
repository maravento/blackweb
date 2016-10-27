## [Blackweb] (http://www.maravento.com/p/blacklistweb.html)

<a target="_blank" href=""><img src="https://img.shields.io/badge/Development-ALPHA-blue.svg"></a>

En ocasiones hemos necesitado bloquear un sitio web, ya sea de porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, venta de armas, etc; y como son muchos, para ahorrar tiempo utilizamos las llamadas "listas negras" (blacklist). En Internet existen muchas, tales como [Shallalist] (http://www.shallalist.de/), [Urlblacklist] (http://urlblacklist.com/), [Capitole (Univ Toulouse)] (https://dsi.ut-capitole.fr/blacklists/), etc, sin embargo están plagadas de subdominios y falsos positivos.

Sumado a esto, no son compatibles con [Squid-Cache] (http://www.squid-cache.org/) y al internar correrlas, el proxy se detiene, generando: "ERROR: '.sub.example.com' is a subdomain of '.example.com'". Este problema, conocido como "overlapping domains", [ha generado diversos debates] (https://stackoverflow.com/questions/33557298/remove-subdomains-from-blacklist-overlapping-domains), y a la fecha no hay solución. Lo anterior se debe a que estas listas negras fueron concebidas para Squid2x y Squidguard, y cuando ocurrió la migración de [Squid2x a 3x] (http://comments.gmane.org/gmane.comp.web.squid.general/98170), Squid dejó de aceptar subdominios. Muchos han optado por editar sus listas negras manualmente, y aplicado [parches] (http://www.squid-cache.org/mail-archive/squid-users/201208/0360.html), pero no ha funcionado. 

[Blackweb] (http://www.maravento.com/p/blacklistweb.html) pretende recopilar la mayor cantidad de listas negras públicas de dominios, con el objeto de unificarlas y hacerlas compatibles con [Squid-Cache] (http://www.squid-cache.org/) (v3.5.x). Para lograrlo, realizamos una rigurosa depuración, evitando duplicados, y las comparamos con lista de extensiones de dominios (ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), para detectar dominios inválidos, y con "listas blancas" de dominios, para filtrar la mayor cantidad de falsos positivos posibles (google, hotmail, yahoo, etc), y obtener una mega lista de control (ACL), optimizada para [Squid-Cache] (http://www.squid-cache.org/), libre de "overlapping domains".

Sometimes we needed to block a website, like a porn, downloads, drugs, malware, spyware, trackers, bots, social networks, warez, arms sales, etc; and how they are many, to save time we use so-called "blacklists" (blacklist). On the Internet there are many, such as [Shallalist] (http://www.shallalist.de/), [Urlblacklist] (http://urlblacklist.com/), [Capitole (Univ Toulouse)] (https://dsi.ut-capitole.fr/blacklists/), etc., however are plagued subdomains and false positives.

Added to this, are not compatible with Squid-Cache and when try run them, proxy stops, generating: "ERROR: '.sub.example.com' is a subdomain of '.example.com'." This problem, known as "overlapping domains" has [generated many debates] (https://stackoverflow.com/questions/33557298/remove-subdomains-from-blacklist-overlapping-domains), and to date no solution. This is because these blacklists were designed to Squid2x and Squidguard, and when migration occurred [Squid2x to 3x] (http://comments.gmane.org/gmane.comp.web.squid.general/98170), Squid stopped accepting subdomains, generating the error. Many have chosen to manually edit their blacklists, and applied [patches] (http://www.squid-cache.org/mail-archive/squid-users/201208/0360.html), but has not worked.

[Blackweb] (http://www.maravento.com/p/blacklistweb.html) aims to collect as many public blacklists of domains, in order to unify and compatible with Squid-Cache (v3.5.x). To achieve this, we conduct a thorough cleansing, avoiding duplicate, and compared with list of domain extensions (ccTLDs ccSLD, sTLD, uTLD, gSLD, gTLD, etc.) and "whitelist" domains to filter as many potential false positives (google, hotmail, yahoo, etc), and get a mega control list (ACL), optimized for [Squid-Cache] (http://www.squid-cache.org/) and free of "overlapping domains".

### Descripción/Description

|File|BLDomains|
|----|---------|
|blackweb.txt|4.181.679|

### Dependencias/Dependencies

```
sudo apt-get -y install git apt dpkg squid
```

### Modo de uso/How to use

Descargue/Download:
```
git clone https://github.com/maravento/blackweb.git
```
Copie el script y ejecútelo/Copy the script and run:
```
sudo cp -f blackweb/blackweb.sh /etc/init.d
sudo chown root:root /etc/init.d/blackweb.sh
sudo chmod +x /etc/init.d/blackweb.sh
sudo /etc/init.d/blackweb.sh
```
Cron task:
```
sudo crontab -e
@weekly /etc/init.d/blackweb.sh
```
Verifique su ejecución/Check execution: /var/log/syslog.log:
```
Blackweb for Squid: 14/06/2016 15:47:14
```
Descarga incompleta/Incomplete download:
```
Blackweb for Squid: Abort 14/06/2016 16:35:38 Check Internet Connection
```
Edit /etc/squid3/squid.conf or /etc/squid/squid.conf:
```
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access deny blackweb
```
### Edición/Edit

Blackweb contiene millones de dominios bloqueados, por tanto, editarla manualmente puede ser frustrante. Eentonces, si detecta un falso positivo, utilice la ACL "whitedomains" y reporte el incidente, para corregirlo en la próxima actualización. Lo mismo aplica para dominios no incluidos en Blackweb, que quiera bloquear, puede incluirlos en "blackdomains"

Blackweb contains million domains blocked therefore manually editing can be frustrating. Then, if it detects a false positive, use the ACL "whitedomains" and report the incident to correct it in the next update. The same applies for domains not included in Blackweb, you want to block, you can include them in "blackdomains"

```
acl whitedomains dstdomain -i "/etc/acl/whitedomains.txt"
acl blackdomains dstdomain -i "/etc/acl/blackdomains.txt"
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access allow whitedomains
http_access deny blackdomains 
http_access deny blackweb
```
"Blackdomains" incluye por default algunos dominios no incluidos en Blackweb (e.g. .youtube.com .googlevideo.com, .ytimg.com) y "whitedomains" incluye el subdominio accounts.youtube.com [desde Feb 2014, Google utiliza el subdominio accounts.youtube.com para autenticar sus servicios] (http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube).

"Blackdomains" by default includes some domains not included in Blackweb (eg .youtube.com .googlevideo.com, .ytimg.com) and "whitedomains" includes the subdomain accounts.youtube.com [since February 2014, Google uses the accounts subdomain .youtube.com to authenticate their services] (http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube).

### Important

- Por defecto la ruta de la acl blackweb es **/etc/acl** y del script de actualización **/etc/init.d**.
- La acl blackweb está diseñada exclusivamente para bloquear dominios. Para los interesados en bloquear banners y otras modalidades publicitarias, visite el foro [Alterserv] (http://www.alterserv.com/foros/index.php?topic=1428.0).
- Para convertir **Blackweb** a MS-DOS/Windows utilice las herramientas [Dos2Unix] (http://dos2unix.sourceforge.net/) o [FF Multiconverter] (https://sites.google.com/site/ffmulticonverter/download), etc.

- The default path is blackweb acl **/etc/acl** and update script **/etc/init.d**.
- The acl blackweb is designed exclusively to block domains. For those interested in blocking banners and other advertising forms, visit the [Alterserv] (http://www.alterserv.com/foros/index.php?topic=1428.0) forum.
- To convert **Blackweb** to MS-DOS/Windows use the tools [dos2unix] (http://dos2unix.sourceforge.net/) or [FF Multiconverter] (https://sites.google.com/site/ffmulticonverter/download ), etc.

### Blackweb Update

Puede actualizar **Blackweb** y/o agregarle sus listas propias, sin necesidad de esperar que publiquemos la nueva actualización, descargando el script [blupdate.sh] (https://github.com/maravento/blackweb/raw/master/blupdate.sh), que es el encargado de crear **blackweb**. Se recomienda ejecutarlo con privilegios y verificar los enlaces antes de correr el script. Tenga presente que la captura y depuración de dominios consume gran cantidad de recursos de hardware durante el procesamiento.

You can update **Blackweb** and/or add your own lists, without waiting to publish the new update, downloading the script [blupdate.sh] (https://github.com/maravento/blackweb/raw/master/blupdate.sh), which is responsible for creating **blackweb**. It is recommended to run with privileges and check links before running the script. Note that the capture and debug domains consumes large amount of hardware resources during processing.

### Contributions

Los interesados pueden contribuir, enviándonos enlaces de nuevas BLs, para ser incluidas en este proyecto. Estas deberán alojarse de forma permanente con acceso público (Ej: [Github] (https://github.com)), de fácil descarga, vía http/s, git, wget, etc, y de ser posible con control de versiones.

Those interested may contribute sending us new BLs links to be included in this project. These must stay permanently with public access (eg [Github] (https://github.com)), easy to download via http/s, git, wget, etc, and if possible with version control.

### Data sheet (BLs including)

##### General Public and Malware BLs
[Shallalist] (http://www.shallalist.de/Downloads/shallalist.tar.gz)

[UrlBlacklist] (http://urlblacklist.com/?sec=download)

[Capitole - Direction du Système d'Information (DSI)] (http://dsi.ut-capitole.fr/blacklists/download/)

[MESD blacklists] (http://squidguard.mesd.k12.or.us/blacklists.tgz)

[Yoyo Serverlist] (http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)

[Passwall] (http://www.passwall.com/blacklist.txt)

[Oleksiig Blacklist] (https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf)

[Someonewhocares] (http://someonewhocares.org/hosts/hosts)

[HP Hosts-file] (http://hosts-file.net/download/hosts.txt)

[Winhelp2002] (http://winhelp2002.mvps.org/hosts.txt)

[Cibercrime-Tracker] (http://cybercrime-tracker.net/all.php)

[Joewein Blacklist] (http://www.joewein.de/sw/bl-text.htm)

[Tracking-Addresses] (https://github.com/10se1ucgo/DisableWinTracking/wiki/Tracking-Addresses)

[Adaway] (http://adaway.org/hosts.txt)

[Lehigh Malwaredomains] (http://malwaredomains.lehigh.edu/files/)

[Easylist for adblockplus] (https://easylist-downloads.adblockplus.org/malwaredomains_full.txt)

[Zeus tracker] (https://zeustracker.abuse.ch/blocklist.php?download=squiddomain)

[Malwaredomain Hosts List] (http://www.malwaredomainlist.com/hostslist/hosts.txt)

[Malware-domains] (http://www.malware-domains.com/)

[malc0de] (http://malc0de.com/bl/)

[BambenekConsulting] (http://osint.bambenekconsulting.com/feeds/dga-feed.txt)

[openphish] (https://openphish.com/feed.txt)

#####Ransomware BL
[Ransomware Abuse] (https://ransomwaretracker.abuse.ch/blocklist/)

#####TLDs
[IANA] (https://www.iana.org/domains/root/db)

[Mozilla Public Suffix] (https://publicsuffix.org/list/public_suffix_list.dat)

#####Own lists (inside project)
blackurls

whiteurls

### Licence

[GPL-3.0] (https://www.gnu.org/licenses/gpl-3.0.en.html)

This Project is educational purposes. Este proyecto es con fines educativos. Agradecemos a todos aquellos que han contribuido a este proyecto. We thank all those who contributed to this project. Special thanks to [novatoz.com] (http://www.novatoz.com)

© 2016 [Gateproxy] (http://www.gateproxy.com) by [maravento] (http://www.maravento.com)

#### Disclaimer

Este script puede dañar su sistema si se usa incorrectamente. Úselo bajo su propio riesgo. This script can damage your system if used incorrectly. Use it at your own risk. [HowTO Gateproxy] (https://goo.gl/ZT4LTi)
