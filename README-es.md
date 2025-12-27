# [BlackWeb](https://www.maravento.com/p/blackweb.html)

<!-- markdownlint-disable MD033 -->

[![status-stable](https://img.shields.io/badge/status-stable-green.svg)](https://github.com/maravento/blackweb)
[![last commit](https://img.shields.io/github/last-commit/maravento/blackweb)](https://github.com/maravento/blackweb)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/maravento/blackweb)
[![Twitter Follow](https://img.shields.io/twitter/follow/maraventostudio.svg?style=social)](https://twitter.com/maraventostudio)

<table align="center">
  <tr>
    <td align="center">
      <a href="README.md">English</a> | <span>Español</span>
    </td>
  </tr>
</table>

BlackWeb es un proyecto que recopila y unifica listas públicas de bloqueo de dominios (porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, armas, etc.) para hacerlas compatibles con [Squid-Cache](http://www.squid-cache.org/).

## DATA SHEET

---

| ACL | Blocked Domains | File Size |
| :---: | :---: | :---: |
| blackweb.txt | 4909773 | 121,3 MB |

## GIT CLONE

---

```bash
git clone --depth=1 https://github.com/maravento/blackweb.git
```

## HOW TO USE

---

`blackweb.txt` ya viene actualizada y optimizada para [Squid-Cache](http://www.squid-cache.org/). Descárguela y descomprimala en la ruta de su preferencia y active la [REGLA de Squid-Cache](https://github.com/maravento/blackweb#regla-squid-cache--squid-cache-rule).

### Download

```bash
wget -q -c -N https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz && cat blackweb.tar.gz* | tar xzf -
```

#### If Multiparts Exist

```bash
#!/bin/bash

# Variables
url="https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz"
wgetd="wget -q -c --timestamping --no-check-certificate --retry-connrefused --timeout=10 --tries=4 --show-progress"

# TMP folder
output_dir="bwtmp"
mkdir -p "$output_dir"

# Download
if $wgetd "$url"; then
  echo "File downloaded: $(basename $url)"
else
  echo "Main file not found. Searching for multiparts..."

  # Multiparts from a to z
  all_parts_downloaded=true
  for part in {a..z}{a..z}; do
    part_url="${url%.*}.$part"
    if $wgetd "$part_url"; then
      echo "Part downloaded: $(basename $part_url)"
    else
      echo "Part not found: $part"
      all_parts_downloaded=false
      break
    fi
  done

  if $all_parts_downloaded; then
    # Rebuild the original file in the current directory
    cat blackweb.tar.gz.* > blackweb.tar.gz
    echo "Multipart file rebuilt"
  else
    echo "Multipart process cannot be completed"
    exit 1
  fi
fi

# Unzip the file to the output folder
tar -xzf blackweb.tar.gz -C "$output_dir"

echo "Done"
```

### Checksum

```bash
wget -q -c -N https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz && cat blackweb.tar.gz* | tar xzf -
wget -q -c -N https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.txt.sha256
LOCAL=$(sha256sum blackweb.txt | awk '{print $1}'); REMOTE=$(awk '{print $1}' blackweb.txt.sha256); echo "$LOCAL" && echo "$REMOTE" && [ "$LOCAL" = "$REMOTE" ] && echo OK || echo FAIL
```

### BlackWeb Rule for [Squid-Cache](http://www.squid-cache.org/)

---

Edit:

```bash
/etc/squid/squid.conf
```

Y agregue las siguientes líneas:

```bash
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS

# Block Rule for Blackweb
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

#### Advanced Rules

BlackWeb contiene millones de dominios, por tanto se recomienda:

##### Allow Rule for Domains

>Usar `allowdomains.txt` para excluir dominios o subdominios esenciales, como `.accounts.google.com`, `.yahoo.com`, `.github.com`, etc. Según la [documentación de Squid](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube), los subdominios `accounts.google.com` y `accounts.youtube.com` pueden ser utilizados por Google para la autenticación dentro de su ecosistema. Bloquearlos podría interrumpir el acceso a servicios como Gmail, Drive, Docs, entre otros.

```bash
acl allowdomains dstdomain "/path_to/allowdomains.txt"
http_access allow allowdomains
```

##### Block Rule for Domains

>Utilice `blockdomains.txt` para bloquear cualquier otro dominio, no incluido en `blackweb.txt`

```bash
acl blockdomains dstdomain "/path_to/blockdomains.txt"
http_access deny blockdomains
```

##### Block Rule for gTLD, sTLD, ccTLD, etc

>Use `blocktlds.txt` para bloquear gTLD, sTLD, ccTLD, etc.

```bash
acl blocktlds dstdomain "/path_to/blocktlds.txt"
http_access deny blocktlds
```

Input:

```bash
.bardomain.xxx
.subdomain.bardomain.xxx
.bardomain.ru
.bardomain.adult
.foodomain.com
.foodomain.porn
```

Output:

```bash
.foodomain.com
```

##### Block Rule for Punycode

>Usar esta regla para bloquear [Punycode - RFC3492](https://datatracker.ietf.org/doc/html/rfc3492), IDN | Non-ASCII (TLDs o Dominios), para prevenir un [Ataque homógrafo IDN](https://en.wikipedia.org/wiki/IDN_homograph_attack). Para mayor información visite [welivesecurity: Ataques homográficos](https://www.welivesecurity.com/la-es/2017/07/13/ataques-homograficos/).

```bash
acl punycode dstdom_regex -i \.xn--.*
http_access deny punycode
```

Input:

```bash
.bücher.com
.mañana.com
.google.com
.auth.wikimedia.org
.xn--fiqz9s
.xn--p1ai
```

ASCII Output:

```bash
.google.com
.auth.wikimedia.org
```

##### Block Rule for Words

>Usar esta regla para bloquear palabras (Opcional. Puede generar falsos positivos).

```bash
# Download ACL:
sudo wget -P /etc/acl/ https://raw.githubusercontent.com/maravento/vault/refs/heads/master/blackshield/acl/squid/blockwords.txt
# Squid Rule to Block Words:
acl blockwords url_regex -i "/etc/acl/blockwords.txt"
http_access deny blockwords
```

Input:

```bash
.bittorrent.com
https://www.google.com/search?q=torrent
https://www.google.com/search?q=mydomain
https://www.google.com/search?q=porn
.mydomain.com
```

Output:

```bash
https://www.google.com/search?q=mydomain
.mydomain.com
```

##### Streaming (Optional)

>Utilice `streaming.txt` para bloquear dominios de streaming, no incluidos en `blackweb.txt` (.youtube.com .googlevideo.com, .ytimg.com, etc.).

```bash
acl streaming dstdomain "/path_to/streaming.txt"
http_access deny streaming
```

>Nota: Esta lista puede contener dominios superpuestos. Es importante depurarla manualmente según el objetivo propuesto. Ejemplo:
>- Si el objetivo es bloquear Facebook, conserva los dominios principales y elimina los subdominios específicos.
>- Si el objetivo es bloquear funcionalidades, como el streaming de Facebook, mantén los subdominios específicos y elimina los dominios principales para no afectar el acceso general al sitio. Ejemplo:

```bash
# Block Facebook
.fbcdn.net
.facebook.com

# Block some Facebook streaming content
.z-p3-video.flpb1-1.fna.fbcdn.net
```

#### Advanced Rules Summary

```bash
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS

# Allow Rule for Domains
acl allowdomains dstdomain "/path_to/allowdomains.txt"
http_access allow allowdomains

# Block Rule for Punycode
acl punycode dstdom_regex -i \.xn--.*
http_access deny punycode

# Block Rule for gTLD, sTLD, ccTLD
acl blocktlds dstdomain "/path_to/blocktlds.txt"
http_access deny blocktlds

# Block Rule for Domains
acl blockdomains dstdomain "/path_to/blockdomains.txt"
http_access deny blockdomains

# Block Rule for Patterns (Optional)
# https://raw.githubusercontent.com/maravento/vault/refs/heads/master/blackshield/acl/squid/blockpatterns.txt
acl blockwords url_regex -i "/path_to/blockpatterns.txt"
http_access deny blockwords

# Block Rule for web3 (Optional)
# https://raw.githubusercontent.com/maravento/vault/refs/heads/master/blackshield/acl/web3/web3domains.txt
acl web3 dstdomain "/path_to/web3domains.txt"
http_access deny web3

# Block Rule for Blackweb
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

## BLACKWEB UPDATE

---

### ⚠️ WARNING: BEFORE YOU CONTINUE

Esta sección es únicamente para explicar cómo funciona el proceso de actualización y optimización. No es necesario que el usuario la ejecute. Este proceso puede tardar y consumir muchos recursos de hardware y ancho de banda, por tanto se recomienda usar equipos de pruebas.

#### Bash Update

>El proceso de actualización de `blackweb.txt` consta de varios pasos y es ejecutado en secuencia por el script `bwupdate.sh`. El script solicitará privilegios cuando lo requiera.

```bash
wget -q -N https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/bwupdate.sh && chmod +x bwupdate.sh && ./bwupdate.sh
```

#### Dependencies

>La actualización requiere python 3x y bash 5x. También requiere las siguientes dependencias:

```bash
wget git curl libnotify-bin perl tar rar unrar unzip zip gzip python-is-python3 idn2 iconv
```

>Asegúrese de que Squid esté instalado correctamente. Si tiene algún problema, ejecute el siguiente script: (`sudo ./squid_install.sh`):

```bash
#!/bin/bash

# kill old version
while pgrep squid > /dev/null; do
    echo "Waiting for Squid to stop..."
    killall -s SIGTERM squid &>/dev/null
    sleep 5
done

# squid remove (if exist)
apt purge -y squid* &>/dev/null
rm -rf /var/spool/squid* /var/log/squid* /etc/squid* /dev/shm/* &>/dev/null

# squid install (you can use 'squid-openssl' or 'squid')
apt install -y squid-openssl squid-langpack squid-common squidclient squid-purge

# create log
if [ ! -d /var/log/squid ]; then
    mkdir -p /var/log/squid
fi &>/dev/null
if [[ ! -f /var/log/squid/{access,cache,store,deny}.log ]]; then
    touch /var/log/squid/{access,cache,store,deny}.log
fi &>/dev/null

# permissions
chown -R proxy:proxy /var/log/squid

# enable service
systemctl enable squid.service
systemctl start squid.service
echo "Done"
```

#### Capture Public Blocklists

>Captura los dominios de las listas de bloqueo públicas descargadas (ver [FUENTES](https://github.com/maravento/blackweb#fuentes--sources)) y las unifica en un solo archivo.

#### Domains Debugging

>Elimina dominios superpuestos (`'.sub.example.com' es un dominio de '.example.com'`), hace la homologación al formato de Squid-Cache y excluye falsos positivos (google, hotmail, yahoo, etc.) con una lista de permitidos (`debugwl.txt`).

Input:

```bash
com
.com
.domain.com
domain.com
0.0.0.0 domain.com
127.0.0.1 domain.com
::1 domain.com
domain.com.co
foo.bar.subdomain.domain.com
.subdomain.domain.com.co
www.domain.com
www.foo.bar.subdomain.domain.com
domain.co.uk
xxx.foo.bar.subdomain.domain.co.uk
```

Output:

```bash
.domain.com
.domain.com.co
.domain.co.uk
```

#### Debugging Punycode-IDN

>Elimina dominios con TLD inválidos (con una lista de TLDs Public and Private Suffix: ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, eTLD, etc., hasta 4to nivel 4LDs).

Input:

```bash
.domain.exe
.domain.com
.domain.edu.co
```

Output:

```bash
.domain.com
.domain.edu.co
```

#### Debugging non-ASCII characters

>Elimina hostnames mayores a 63 caracteres ([RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)) y otros caracteres inadmisibles por [IDN](http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html) y convierte dominios con caracteres internacionales (no ASCII) y usados para [ataques homográficos](https://es.qwerty.wiki/wiki/IDN_homograph_attack) al formato [Punycode/IDNA](https://www.charset.org/punycode).

Input:

```bash
bücher.com
café.fr
españa.com
köln-düsseldorfer-rhein-main.de
mañana.com
mūsųlaikas.lt
sendesık.com
президент.рф
```

Output:

```bash
xn--bcher-kva.com
xn--caf-dma.fr
xn--d1abbgf6aiiy.xn--p1ai
xn--espaa-rta.com
xn--kln-dsseldorfer-rhein-main-cvc6o.de
xn--maana-pta.com
xn--mslaikas-qzb5f.lt
xn--sendesk-wfb.com
```

#### Depuración de caracteres no ASCII

>Elimina entradas con codificación incorrecta, caracteres no imprimibles, espacios en blanco, símbolos no permitidos y cualquier contenido que no se ajuste al formato ASCII estricto para nombres de dominio válidos (CP1252, ISO-8859-1, UTF-8 corrupto, etc.) y convierte la salida a texto sin formato `charset=us-ascii`, lo que garantiza una lista limpia y estandarizada, lista para validación, comparación o resolución DNS.

Input:

```bash
M-C$
-$
.$
0$
1$
23andmÃª.com
.Ã²utlook.com
.ÄƒlibÄƒbÄƒ.com
.ÄƒmÄƒzon.com
.ÄƒvÄƒst.com
.amÃ¹azon.com
.amÉ™zon.com
.avalÃ³n.com
.bÄºnance.com
.bitdáº¹fender.com
.blÃ³ckchain.site
.blockchaiÇ¹.com
.cashpluÈ™.com
.dáº¹ll.com
.diÃ³cesisdebarinas.org
.disnáº¹ylandparis.com
.ebÄƒy.com
.É™mÉ™zon.com
.evo-bancÃ³.com
.goglÄ™.com
.gooÄŸle.com
.googÄ¼Ä™.com
.googlÉ™.com
.google.com
.ibáº¹ria.com
.imgÃºr.com
.lloydÅŸbank.com
.mÃ½etherwallet.com
.mrgreÄ™n.com
.myáº¹tháº¹rwallet.com
.myáº¹thernwallet.com
.myetháº¹rnwallet.com
.myetheá¹™wallet.com
.myethernwalláº¹t.com
.nÄ™tflix.com
.paxfÃ¹ll.com
.tÃ¼rkiyeisbankasi.com
.tÅ™ezor.com
.westernÃºnion.com
.yÃ²utube.com
.yÄƒhoo.com
.yoÃ¼tÃ¼be.co
.yoÃ¼tÃ¼be.com
.yoÃ¼tu.be
```

Output:
```bash
.google.com
```

#### DNS Loockup

>La mayoría de las [FUENTES](https://github.com/maravento/blackweb#fuentes--sources) contienen millones de dominios inválidos o inexistentes, por lo que cada dominio se verifica mediante DNS (en dos pasos) para excluir esas entradas de Blackweb. Este proceso se realiza en paralelo y puede consumir muchos recursos, dependiendo del hardware y las condiciones de la red. Puede controlar la concurrencia con la variable `PROCS`:

```bash
PROCS=$(($(nproc)))        # Conservative (network-friendly)
PROCS=$(($(nproc) * 2))    # Balanced
PROCS=$(($(nproc) * 4))    # Aggressive (default)
PROCS=$(($(nproc) * 8))    # Extreme (8 or higher, use with caution)
```

>Por ejemplo, en un sistema con una CPU Core i5 (4 núcleos físicos/8 subprocesos con Hyper-Threading):

```bash
nproc             → 8
PROCS=$((8 * 4))  → 32 parallel queries
```

>⚠️ Los valores altos de `PROCS` aumentan la velocidad de resolución del DNS, pero pueden saturar la CPU o el ancho de banda, especialmente en redes limitadas como enlaces satelitales. Ajuste el sistema según corresponda. Ejemplo de procesamiento en tiempo real:

```bash
Processed: 2463489 / 7244989 (34.00%)
```

Output:

```bash
HIT google.com
google.com has address 142.251.35.238
google.com has IPv6 address 2607:f8b0:4008:80b::200e
google.com mail is handled by 10 smtp.google.com.

FAULT testfaultdomain.com
Host testfaultdomain.com not found: 3(NXDOMAIN)
```

#### Excludes government-related TLDs

>Elimina de BlackWeb los dominios de gobierno (.gov) y otros TLD relacionados.

Input:

```bash
.argentina.gob.ar
.mydomain.com
.gob.mx
.gov.uk
.navy.mil
```

Output:

```bash
.mydomain.com
```

#### Run Squid-Cache with BlackWeb

>Corre Squid-Cache con BlackWeb y cualquier error lo envía a `SquidError.txt`.

#### Check execution (/var/log/syslog)

```bash
BlackWeb: Done 06/05/2023 15:47:14
```

#### Important about BlackWeb Update

- El path por default de BlackWeb es `/etc/acl`. Puede cambiarlo por el de su preferencia.
- Si necesita interrumpir la ejecución de `bwupdate.sh` (ctrl + c) y se detuvo en la parte de [DNS Loockup](https://github.com/maravento/blackweb#dns-loockup), reiniciará en ese punto. Si lo detiene antes deberá comenzar desde el principio o modificar el script manualmente para que inicie desde el punto deseado.
- Si usa `aufs`, cámbielo temporalmente a `ufs` durante la actualización, para evitar: `ERROR: Can't change type of existing cache_dir aufs /var/spool/squid to ufs. Restart required`.

## SOURCES

---

### BLOCKLISTS

#### Active

- [ABPindo - indonesianadblockrules](https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt)
- [abuse.ch - hostfile](https://urlhaus.abuse.ch/downloads/hostfile/)
- [Adaway - host](https://adaway.org/hosts.txt)
- [adblockplus - advblock Russian](https://easylist-downloads.adblockplus.org/advblock.txt)
- [adblockplus - antiadblockfilters](https://easylist-downloads.adblockplus.org/antiadblockfilters.txt)
- [adblockplus - easylistchina](https://easylist-downloads.adblockplus.org/easylistchina.txt)
- [adblockplus - easylistlithuania](https://easylist-downloads.adblockplus.org/easylistlithuania+easylist.txt)
- [anudeepND - adservers](https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt)
- [anudeepND - coinminer](https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt)
- [AssoEchap - stalkerware-indicators](https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts)
- [azet12 - KADhosts](https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt)
- [BarbBlock - blacklists](https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt)
- [BBcan177 - minerchk](https://github.com/BBcan177/minerchk)
- [BBcan177 - MS-2](https://gist.github.com/BBcan177/4a8bf37c131be4803cb2)
- [BBcan177 - referrer-spam-blacklist](https://github.com/BBcan177/referrer-spam-blacklist)
- [betterwebleon - slovenian-list](https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt)
- [bigdargon - hostsVN](https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts)
- [BlackJack8 - iOSAdblockList](https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt)
- [BlackJack8 - webannoyances](https://github.com/BlackJack8/webannoyances/raw/master/ultralist.txt)
- [blocklistproject - everything](https://raw.githubusercontent.com/blocklistproject/Lists/master/everything.txt)
- [cert.pl - List of malicious domains](https://hole.cert.pl/domains/domains.txt)
- [chadmayfield - porn top](https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list)
- [chadmayfield - porn_all](https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list)
- [chainapsis - phishing-block-list](https://raw.githubusercontent.com/chainapsis/phishing-block-list/main/block-list.txt)
- [cjx82630 - Chinese CJX's Annoyance List](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)
- [cobaltdisco - Google-Chinese-Results-Blocklist](https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/GHHbD_perma_ban_list.txt)
- [CriticalPathSecurity - Public-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/)
- [DandelionSprout - adfilt](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt)
- [Dawsey21 - adblock-list](https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt)
- [Dawsey21 - main-blacklist](https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt)
- [developerdan - ads-and-tracking-extended](https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt)
- [Disconnect.me - simple_ad](https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt)
- [Disconnect.me - simple_malvertising](https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt)
- [Disconnect.me - simple_tracking](https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt)
- [dorxmi - nothingblock](https://github.com/dorxmi/nothingblock)
- [Eallion - uBlacklist](https://raw.githubusercontent.com/eallion/uBlacklist-subscription-compilation/refs/heads/main/uBlacklist.txt)
- [EasyList - EasyListHebrew](https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt)
- [ethanr - dns-blacklists](https://bitbucket.org/ethanr/dns-blacklists/raw/master/bad_lists/Mandiant_APT1_Report_Appendix_D.txt)
- [fabriziosalmi - blacklists](https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt)
- [firebog - AdguardDNS](https://v.firebog.net/hosts/AdguardDNS.txt)
- [firebog - Admiral](https://v.firebog.net/hosts/Admiral.txt)
- [firebog - Easylist](https://v.firebog.net/hosts/Easylist.txt)
- [firebog - Easyprivacy](https://v.firebog.net/hosts/Easyprivacy.txt)
- [firebog - Kowabit](https://v.firebog.net/hosts/Kowabit.txt)
- [firebog - neohostsbasic](https://v.firebog.net/hosts/neohostsbasic.txt)
- [firebog - Prigent-Ads](https://v.firebog.net/hosts/Prigent-Ads.txt)
- [firebog - Prigent-Crypto](https://v.firebog.net/hosts/Prigent-Crypto.txt)
- [firebog - Prigent-Malware](https://v.firebog.net/hosts/Prigent-Malware.txt)
- [firebog - RPiList-Malware](https://v.firebog.net/hosts/RPiList-Malware.txt)
- [firebog - RPiList-Phishing](https://v.firebog.net/hosts/RPiList-Phishing.txt)
- [firebog - WaLLy3K](https://v.firebog.net/hosts/static/w3kbl.txt)
- [frogeye - firstparty-trackers-hosts](https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt)
- [gardar - Icelandic ABP List](https://adblock.gardar.net/is.abp.txt)
- [greatis - Anti-WebMiner](https://raw.githubusercontent.com/greatis/Anti-WebMiner/master/blacklist.txt)
- [hagezi - dns-blocklists](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt)
- [hexxium - threat-list/](https://hexxiumcreations.github.io/threat-list/hexxiumthreatlist.txt)
- [hoshsadiq - adblock-nocoin-list](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt)
- [jawz101 - potentialTrackers](https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv)
- [jdlingyu - ad-wars](https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts)
- [joelotz - URL_Blacklist](https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv)
- [kaabir - AdBlock_Hosts](https://raw.githubusercontent.com/kaabir/AdBlock_Hosts/master/hosts)
- [kevle1 - Windows-Telemetry-Blocklist - xiaomiblock](https://raw.githubusercontent.com/kevle1/Xiaomi-Telemetry-Blocklist/master/xiaomiblock.txt)
- [liamja - Prebake Filter Obtrusive Cookie Notices](https://raw.githubusercontent.com/liamja/Prebake/master/obtrusive.txt)
- [malware-filter - URLhaus Malicious URL Blocklist](https://gitlab.com/malware-filter/urlhaus-filter/-/raw/master/urlhaus-filter.txt)
- [malware-filter.- phishing-filter-hosts](https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt)
- [Matomo-org - spammers](https://github.com/matomo-org/referrer-spam-blacklist/blob/master/spammers.txt)
- [MBThreatIntel - malspam](https://github.com/MBThreatIntel/malspam)
- [mine.nu - hosts0](https://hostsfile.mine.nu/hosts0.txt)
- [mitchellkrogza - Badd-Boyz-Hosts](https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/domains)
- [mitchellkrogza - hacked-domains](https://github.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/blob/master/hacked-domains.list)
- [mitchellkrogza - nginx-ultimate-bad-bot-blocker](https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrers.list)
- [mitchellkrogza - strip_domains](https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/.dev-tools/_strip_domains/domains.txt)
- [molinero - hBlock](https://hblock.molinero.dev/hosts_domains.txt)
- [NanoAdblocker - NanoFilters](https://github.com/NanoAdblocker/NanoFilters)
- [neodevpro - neodevhost](https://raw.githubusercontent.com/neodevpro/neodevhost/master/domain)
- [notracking - hosts-blocklists](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt)
- [Oleksiig - Squid-BlackList](https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf)
- [openphish - feed](https://openphish.com/feed.txt)
- [pengelana - domains blocklist](https://github.com/pengelana/blocklist/tree/master/src/blacklist)
- [phishing.army - phishing_army_blocklist_extended](https://phishing.army/download/phishing_army_blocklist_extended.txt)
- [piperun - iploggerfilter](https://github.com/piperun/iploggerfilter)
- [quidsup - notrack-blocklists](https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt)
- [quidsup - notrack-malware](https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt)
- [reddestdream - MinimalHostsBlocker](https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts)
- [RooneyMcNibNug - pihole-stuff](https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt)
- [Rpsl - adblock-leadgenerator-list](https://github.com/Rpsl/adblock-leadgenerator-list)
- [ruvelro - Halt-and-Block-Mining](https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat)
- [ryanbr - fanboy-adblock](https://github.com/ryanbr/fanboy-adblock)
- [scamaNet - blocklist](https://raw.githubusercontent.com/scamaNet/blocklist/main/blocklist.txt)
- [simeononsecurity/System-Wide-Windows-Ad-Blocker](https://raw.githubusercontent.com/simeononsecurity/System-Wide-Windows-Ad-Blocker/main/Files/hosts.txt)
- [Someonewhocares - hosts](https://someonewhocares.org/hosts/hosts)
- [stanev.org - Bulgarian adblock list](http://stanev.org/abp/adblock_bg.txt)
- [StevenBlack - add.2o7Net](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts)
- [StevenBlack - add.Risk](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts)
- [StevenBlack - fakenews-gambling-porn-social](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts)
- [StevenBlack - hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
- [StevenBlack - spam](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts)
- [StevenBlack - uncheckyAds](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts)
- [Stopforumspam - Toxic Domains](https://www.stopforumspam.com/downloads/toxic_domains_whole.txt)
- [sumatipru - squid-blacklist](https://raw.githubusercontent.com/sumatipru/squid-blacklist/refs/heads/master/blacklist.txt)
- [Taz - SpamDomains](http://www.taz.net.au/Mail/SpamDomains)
- [tomasko126 - Easylist Czech and Slovak filter list](https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt)
- [txthinking - blackwhite](https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list)
- [txthinking - bypass china domains](https://raw.githubusercontent.com/txthinking/bypass/master/china_domain.txt)
- [Ultimate Hosts Blacklist - hosts](https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/tree/master/hosts)
- [Université Toulouse 1 Capitole - Blacklists UT1 - Olbat](https://github.com/olbat/ut1-blacklists/tree/master/blacklists)
- [Université Toulouse 1 Capitole - Blacklists UT1](https://dsi.ut-capitole.fr/blacklists/index_en.php)
- [vokins - yhosts](https://raw.githubusercontent.com/vokins/yhosts/master/hosts)
- [Winhelp2002 - hosts](http://winhelp2002.mvps.org/hosts.txt)
- [yourduskquibbles - Web Annoyances Ultralist](https://github.com/yourduskquibbles/webannoyances)
- [yous - YousList](https://raw.githubusercontent.com/yous/YousList/master/youslist.txt)
- [yoyo - Peter Lowe’s Ad and tracking server list](http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)
- [zoso - Romanian Adblock List](https://zoso.ro/pages/rolist.txt)

### DEBUG LISTS

- [google supported domains](https://www.google.com/supported_domains)
- [iana](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
- [ipv6-hosts](https://raw.githubusercontent.com/lennylxx/ipv6-hosts/master/hosts) (Partial)
- [publicsuffix](https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat)
- [Ransomware Database](https://docs.google.com/spreadsheets/u/1/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml#)
- [University Domains and Names Data List](https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json)
- [whoisxmlapi](https://www.whoisxmlapi.com/support/supported_gtlds.php)

### WORKTOOLS

- [Domain Filtering](https://github.com/maravento/vault/tree/master/dofi)

## BACKLINKS

---

- [Awesome Open Source: Blackweb](https://awesomeopensource.com/project/maravento/blackweb)
- [Community IPfire: url filter and self updating blacklists](https://community.ipfire.org/t/url-filter-and-self-updating-blacklists/6601)
- [covert.io: Getting Started with DGA Domain Detection Research](http://www.covert.io/getting-started-with-dga-research/)
- [Crazymax: WindowsSpyBlocker](https://crazymax.dev/WindowsSpyBlocker/)
- [egirna: Allowing/Blocking Websites Using Squid](https://www.egirna.com/blog/news-2/allowing-blocking-websites-using-squid-5)
- [Jason Trost: Getting Started with DGA Domain Detection Research](https://jason-trost.medium.com/getting-started-with-dga-domain-detection-research-89af69213257)
- [Kandi Openweaver: Domains Blocklist for Squid-Cache](https://kandi.openweaver.com/shell/maravento/blackweb)
- [Kerry Cordero: Blocklists of Suspected Malicious IPs and URLs](https://cordero.me/blocklists-of-suspected-malicious-ips-and-urls/)
- [Keystone Solutions: blocklists](https://keystonesolutions.io/solutions/blocklists/)
- [Lifars: Sites with blocklist of malicious IPs and URLs](https://lifars.com/wp-content/uploads/2017/06/LIFARS_Guide_Sites-with-blocklist-of-malicious-IPs-and-URLs.pdf)
- [Opensourcelibs: Blackweb](https://opensourcelibs.com/lib/blackweb)
- [OSINT Framework: Domain Name/Domain Blacklists/Blackweb](https://osintframework.com/)
- [Osintbay: Blackweb](https://osintbay.com/tool/blackweb)
- [Reddit: Blackweb](https://www.reddit.com/r/AskNetsec/comments/w1yqd9/does_anyone_know_any_free_database_for_url/)
- [Secrepo: Samples of Security Related Data](http://www.secrepo.com/)
- [Segu-Info: Análisis de malware y sitios web en tiempo real](https://blog.segu-info.com.ar/2019/07/analisis-de-malware-y-sitios-web-en.html)
- [Segu-Info: Dominios/TLD dañinos que pueden ser bloqueados para evitar spam y #phishing](https://blog.segu-info.com.ar/2024/05/dominiostld-daninos-que-pueden-ser.html)
- [Soficas: CiberSeguridad - Protección Activa](https://soficas.com/noticias/proteccion-ciberseguridad.html)
- [Stackoverflow: Blacklist IP database](https://stackoverflow.com/a/39516166/8747573)
- [Wikipedia: Blacklist_(computing)](https://en.wikipedia.org/wiki/Blacklist_(computing)#:~:text=There%20are%20also%20free%20blacklists%20for%20Squid%20(software)%20proxy%2C%20such%20as%20Blackweb)
- [Xploitlab: Projects using WindowsSpyBlocker](https://xploitlab.com/windowsspyblocker-block-spying-and-tracking-on-windows/)
- [Zeltser: Free Blocklists of Suspected Malicious IPs and URLs](https://zeltser.com/malicious-ip-blocklists/)
- [Zenarmor: How-to-enable-web-filtering-on-OPNsense-proxy?](https://www.zenarmor.com/docs/network-security-tutorials/how-to-set-up-caching-proxy-in-opnsense#how-to-enable-web-filtering-on-opnsense-proxy)

## NOTICE

---

- Este proyecto incluye componentes de terceros.
- Los cambios deben proponerse mediante Issues. No se aceptan Pull Requests.
- BlackWeb está diseñado exclusivamente para [Squid-Cache](http://www.squid-cache.org/) y debido a la gran cantidad de dominios bloqueados no se recomienda usarlo en otros entornos (DNSMasq, Pi-Hole, etc.), o agregarlas al archivo Hosts File de Windows, ya que podría ralentizarlo o bloquearlo. **Úselo bajo su propio riesgo**. For more information check [Issue 10](https://github.com/maravento/blackweb/issues/10#issuecomment-650834301)
- **Blackweb NO es un servicio de listas negras como tal**. No verifica de forma independiente los dominios. Su función es consolidar y formatear listas negras públicas para hacerlas compatibles con Squid.
- Si su dominio aparece en Blackweb, y considera que esto es un error, debe revisar las fuentes públicas [SOURCES](https://github.com/maravento/blackweb/blob/master/README-es.md#sources), identificar en cuál(es) aparece, y contactar al responsable de dicha lista para solicitar su eliminación. Una vez que el dominio sea eliminado en la fuente original, desaparecerá automáticamente de Blackweb en la siguiente actualización.
  También puede usar el siguiente script y obtener el mismo resultado de verificación:

```bash
wget https://raw.githubusercontent.com/maravento/blackweb/refs/heads/master/bwupdate/tools/checksources.sh
chmod +x checksources.sh
./checksources.sh
```
ej:

```bash
[?] Enter domain to search: kickass.to

[*] Searching for 'kickass.to'...
[+] Domain found in: https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt
[+] Domain found in: https://hostsfile.org/Downloads/hosts.txt
[+] Domain found in: https://raw.githubusercontent.com/blocklistproject/Lists/master/everything.txt
[+] Domain found in: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt
[+] Domain found in: https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0
[+] Domain found in: https://sysctl.org/cameleon/hosts
[+] Domain found in: https://v.firebog.net/hosts/Kowabit.txt
Done
```

## STARGAZERS

---

[![Stargazers](https://bytecrank.com/nastyox/reporoster/php/stargazersSVG.php?user=maravento&repo=blackweb)](https://github.com/maravento/blackweb/stargazers)

## CONTRIBUTIONS

---

Agradecemos a todos aquellos que han contribuido a este proyecto. Los interesados pueden contribuir, enviándonos enlaces de nuevas listas, para ser incluidas en este proyecto.

Special thanks to: [Jhonatan Sneider](https://github.com/sney2002)

## SPONSOR THIS PROJECT

---

[![Image](https://raw.githubusercontent.com/maravento/winexternal/master/img/maravento-paypal.png)](https://paypal.me/maravento)

## PROJECT LICENSES

---

[![GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl.txt)
[![CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC_BY--NC--ND_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-nd/4.0/deed.en)

## DISCLAIMER

---

EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA, INCLUYENDO, ENTRE OTRAS, LAS GARANTÍAS DE COMERCIABILIDAD, IDONEIDAD PARA UN PROPÓSITO PARTICULAR Y NO INFRACCIÓN. EN NINGÚN CASO LOS AUTORES O TITULARES DE LOS DERECHOS DE AUTOR SERÁN RESPONSABLES DE NINGUNA RECLAMACIÓN, DAÑO U OTRA RESPONSABILIDAD, YA SEA EN UNA ACCIÓN CONTRACTUAL, EXTRACONTRACTUAL O DE OTRO MODO, QUE SURJA DE, A PARTIR DE O EN CONEXIÓN CON EL SOFTWARE O EL USO U OTRAS OPERACIONES EN EL SOFTWARE.

## OBJECTION

---

Debido a los recientes cambios arbitrarios en la terminología informática, es necesario aclarar el significado y connotación del término **blacklist**, asociado a este proyecto:

*En informática, una lista negra, lista de denegación o lista de bloqueo es un mecanismo básico de control de acceso que permite a través de todos los elementos (direcciones de correo electrónico, usuarios, contraseñas, URL, direcciones IP, nombres de dominio, hashes de archivos, etc.), excepto los mencionados explícitamente. Esos elementos en la lista tienen acceso denegado. Lo opuesto es una lista blanca, lo que significa que solo los elementos de la lista pueden pasar por cualquier puerta que se esté utilizando.* Fuente [Wikipedia](https://en.wikipedia.org/wiki/Blacklist_(computing))

Por tanto, **blacklist**, **blocklist**, **blackweb**, **blackip**, **whitelist** y similares, son términos que no tienen ninguna relación con la discriminación racial.
