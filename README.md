## [Blackweb] (http://www.maravento.com/p/blacklistweb.html)

<a target="_blank" href=""><img src="https://img.shields.io/badge/Development-ALPHA-blue.svg"></a>

En ocasiones hemos necesitado bloquear un sitio web, ya sea de porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, venta de armas, etc; y como son muchos, para ahorrar tiempo utilizamos las llamadas "listas negras" (blacklist). En Internet existen muchas, tales como [Shallalist] (http://www.shallalist.de/), [Urlblacklist] (http://urlblacklist.com/), [Capitole (Univ Toulouse)] (https://dsi.ut-capitole.fr/blacklists/), etc, sin embargo están plagadas de subdominios y falsos positivos.

Sumado a esto, no son compatibles con [Squid-Cache] (http://www.squid-cache.org/) y al internar correrlas, el proxy se detiene, generando el error: "ERROR: '.sub.example.com' is a subdomain of '.example.com'". Este problema, conocido como "overlapping domains", [ha generado diversos debates] (https://stackoverflow.com/questions/33557298/remove-subdomains-from-blacklist-overlapping-domains), sin que a la fecha haya una solución. Lo anterior se debe a que estas listas negras fueron concebidas para Squid2x y Squidguard, y cuando ocurrió la migración de [Squid2x a 3x] (http://comments.gmane.org/gmane.comp.web.squid.general/98170), este proxy dejó de aceptar listas con subdominios, generando el error.

En un intento por evitarlo, muchos han optado por editar sus listas negras manualmente. Incluso algunos han propuesto [parchear squid3] (http://www.squid-cache.org/mail-archive/squid-users/201208/0360.html) para que tolere los subdominios, pero no ha funcionado bien con las versiones actuales y tampoco elimina completamente el error. 

[Blackweb] (http://www.maravento.com/p/blacklistweb.html) pretende recopilar la mayor cantidad de listas negras públicas de dominios, con el objeto de unificarlas y hacerlas compatibles con [Squid-Cache] (http://www.squid-cache.org/) (v3.5.x). Para lograrlo, realizamos una rigurosa depuración, evitando duplicados, y las comparamos con lista de extensiones de dominios (ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, etc), para detectar dominios inválidos, y finalmente las cotejamos con "listas blancas" para filtrar la mayor cantidad de falsos positivos posibles (google, hotmail, yahoo, etc), para obtener una sola mega lista de control (ACL), apta para correr en [Squid-Cache] (http://www.squid-cache.org/) y libre de "overlapping domains".

### Descripción

|File|BLDomains|
|----|---------|
|blackweb.txt|4.169.885|

### Dependencias

```
sudo apt-get -y install git apt dpkg squid
```

### Modo de uso

Descargue el repositorio blackweb:
```
git clone https://github.com/maravento/blackweb.git
```
Copie el script de actualización y ejecutelo:
```
sudo cp -f blackweb/blackweb.sh /etc/init.d
sudo chown root:root /etc/init.d/blackweb.sh
sudo chmod +x /etc/init.d/blackweb.sh
sudo /etc/init.d/blackweb.sh
```
Programe su ejecución semanal en el cron:
```
sudo crontab -e
@weekly /etc/init.d/blackweb.sh
```
Verifique el archivo /var/log/syslog.log. Si la ejecución fue exitosa, saldrá el mensaje:
```
Blackweb for Squid: ejecucion 14/06/2016 15:47:14
```
Caso contrario (descarga incompleta del repositorio):
```
Blackweb for Squid: abortada 14/06/2016 16:35:38 Verifique su conexion de internet
```
Edite el archivo de configuración de Squid (/etc/squid3/squid.conf o /etc/squid/squid.conf) y agregue la siguiente regla:
```
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access deny blackweb
```
### Edición

La ACL blackweb, al ser una "lista negra" con más de 4 millones de dominios bloqueados, editarla manualmente puede ser algo muy frustrante. Por esta razón, si detecta un falso positivo, recomendamos crear una "lista blanca" y poner ahí los dominios que quiera excluir de blackweb y reportarnos el incidente para corregirlo en la próxima actualización. (en el órden propuesto)
```
acl whitedomains dstdomain -i "/etc/acl/whitedomains.txt"
acl blackdomains dstdomain -i "/etc/acl/blackdomains.txt"
acl blackweb dstdomain -i "/etc/acl/blackweb.txt"
http_access allow whitedomains
http_access deny blackdomains 
http_access deny blackweb
```
En la regla anterior hemos creado dos acls. blackdomains; que servirá para bloquear dominios no incluidos en blackweb (ej: .youtube.com .googlevideo.com, .ytimg.com, etc) y whitedomains para incluir los falsos positivos de blackweb y también para autorizar el subdominio accounts.youtube.com [desde Feb 2014, Google utiliza el subdominio accounts.youtube.com para autenticar sus servicios] (http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube). Ambas listas entan disponibles en el repositorio.

### Importante

- Por defecto la ruta de la acl blackweb es **/etc/acl** y del script de actualización **/etc/init.d**.
- La acl blackweb está diseñada exclusivamente para bloquear dominios. Para los interesados en bloquear banners y otras modalidades publicitarias, visite el foro [Alterserv] (http://www.alterserv.com/foros/index.php?topic=1428.0)
- Para convertir la acl a MS-DOS/Windows utilice las herramientas [Dos2Unix] (http://dos2unix.sourceforge.net/) o [FF Multiconverter] (https://sites.google.com/site/ffmulticonverter/download), etc.

### Blackweb Update

Puede actualizar **blackweb** y/o agregarle sus listas propias, sin necesidad de esperar que publiquemos la nueva actualización, descargando el script [blupdate.sh] (https://github.com/maravento/blackweb/raw/master/blupdate.sh) (disponible en el repositorio), que es el encargado de crear **blackweb**. Se recomienda ejecutarlo con privilegios y verificar los enlaces antes de correr el script. Tenga presente que la captura y depuración de dominios consume gran cantidad de recursos de hardware durante el procesamiento.

### Contribuciones

Los interesados pueden contribuir, enviándonos enlaces de nuevas BLs, para ser incluidas en este proyecto. Estas deberán alojarse de forma permanente con acceso público (Ej: [Github] (https://github.com)), de fácil descarga, vía http/s, git, wget, etc, y de ser posible con control de versiones.

### Ficha Técnica (BLs incluidas)

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

### Legal

This Project is educational purposes. Este proyecto es con fines educativos. Agradecemos a todos los que han contribuido a este proyecto, en especial [novatoz.com] (http://www.novatoz.com)

© 2016 [Blackweb] (http://www.maravento.com/p/blacklistweb.html) por [maravento] (http://www.maravento.com), es un componente del proyecto [Gateproxy] (http://www.gateproxy.com)
