# [BlackWeb](https://www.maravento.com/p/blackweb.html)

[![status-stable](https://img.shields.io/badge/status-stable-green.svg)](https://github.com/maravento/blackweb)
[![last commit](https://img.shields.io/github/last-commit/maravento/blackweb)](https://github.com/maravento/blackweb)
[![Twitter Follow](https://img.shields.io/twitter/follow/maraventostudio.svg?style=social)](https://twitter.com/maraventostudio)

BlackWeb is a project that collects and unifies public blocklists of domains (porn, downloads, drugs, malware, spyware, trackers, bots, social networks, warez, weapons, etc.) to make them compatible with [Squid-Cache](http://www.squid-cache.org/).

BlackWeb es un proyecto que recopila y unifica listas públicas de bloqueo de dominios (porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, armas, etc.) para hacerlas compatibles con [Squid-Cache](http://www.squid-cache.org/).

## DATA SHEET

---

|ACL|Blocked Domains|File Size|
| :---: | :---: | :---: |
|blackweb.txt|5313000|138,1 MB|

## GIT CLONE

---

```bash
git clone --depth=1 https://github.com/maravento/blackweb.git
```

## HOW TO USE

---

`blackweb.txt` is already updated and optimized for [Squid-Cache](http://www.squid-cache.org/). Download it and unzip it in the path of your preference and activate [Squid-Cache RULE](https://github.com/maravento/blackweb#regla-squid-cache--squid-cache-rule). / `blackweb.txt` ya viene actualizada y optimizada para [Squid-Cache](http://www.squid-cache.org/). Descárguela y descomprimala en la ruta de su preferencia y active la [REGLA de Squid-Cache](https://github.com/maravento/blackweb#regla-squid-cache--squid-cache-rule).

### Download

```bash
wget -q -c -N https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz && cat blackweb.tar.gz* | tar xzf -
```

### If Multiparts Exist

```bash
#!/usr/bin/env bash
base_url="https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz."

for num in {000..999}; do
    file="${base_url}${num}"
    echo "Check: $file"
    if wget --spider "$file" 2>/dev/null; then
        wget -q -c --timestamping --no-check-certificate --retry-connrefused --timeout=10 --tries=4 --show-progress "$file"
    else
        break
    fi
done
cat blackweb.tar.gz* | tar xzf -
```

### Checksum

```bash
wget -q -c -N https://raw.githubusercontent.com/maravento/blackweb/master/checksum.md5
md5sum blackweb.txt | awk '{print $1}' && cat checksum.md5 | awk '{print $1}'
```

### BlackWeb Rule for [Squid-Cache](http://www.squid-cache.org/)

---

Edit:

```bash
/etc/squid/squid.conf
```

And add the following lines: / Y agregue las siguientes líneas:

```bash
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS

# Block Rule for Blackweb
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

#### Advanced Rules

BlackWeb contains millions of domains, therefore it is recommended: / BlackWeb contiene millones de dominios, por tanto se recomienda:

| Allow Rule for Domains |
| ---------------------- |

>Use `allowdomains.txt` to exclude domains (e.g.: accounts.youtube.com [since Feb 2014, Google uses the subdomain accounts.youtube.com to authenticate its services](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube)) or false positives. / Usar `allowdomains.txt` para excluir dominios (ejemplo: accounts.youtube.com [desde Feb 2014, Google utiliza el subdominio accounts.youtube.com para autenticar sus servicios](http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube)) o falsos positivos.

```bash
acl allowdomains dstdomain "/path_to/allowdomains.txt"
http_access allow allowdomains
```

| Block Rule for Domains |
| ---------------------- |

>Use `blockdomains.txt` to add domains not included in `blackweb.txt` (e.g.: .youtube.com .googlevideo.com, .ytimg.com, etc). / Usar `blockdomains.txt` para agregar dominios no incluidos en `blackweb.txt` (ejemplo: .youtube.com .googlevideo.com, .ytimg.com, etc.).

```bash
acl blockdomains dstdomain "/path_to/blockdomains.txt"
http_access deny blockdomains
```

| Block Rule for gTLD, sTLD, ccTLD, etc. |
| -------------------------------------- |

>Use `blocktlds.txt` to block gTLD, sTLD, ccTLD, etc. / Use `blocktlds.txt` para bloquear gTLD, sTLD, ccTLD, etc.

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

| Block Rule for Punycode |
| ----------------------- |

>Use this rule to block [Punycode - RFC3492](https://datatracker.ietf.org/doc/html/rfc3492), IDN | Non-ASCII (TLDs or Domains), to prevent an [IDN homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack). For more information visit [welivesecurity: Homograph attacks](https://www.welivesecurity.com/2017/07/27/homograph-attacks-see-to-believe/) / Usar esta regla para bloquear [Punycode - RFC3492](https://datatracker.ietf.org/doc/html/rfc3492), IDN | Non-ASCII (TLDs o Dominios), para prevenir un [Ataque homógrafo IDN](https://en.wikipedia.org/wiki/IDN_homograph_attack). Para mayor información visite [welivesecurity: Ataques homográficos](https://www.welivesecurity.com/la-es/2017/07/13/ataques-homograficos/)

```bash
acl punycode dstdom_regex -i \.xn--.*
http_access deny punycode
```

Input:

```bash
.bücher.com
.mañana.com
.mydomain.org
.net
.xn--fiqz9s
.xn--p1ai
```

Output:

```bash
.mydomain.org
.net
```

| Block Rule for Words |
| -------------------- |

>Use this rule to block words (Optional. Can generate false positives) / Usar esta regla para bloquear palabras (Opcional. Puede generar falsos positivos)

```bash
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

# Block Rule for Words (Optional)
acl blockwords url_regex -i "/etc/acl/blockwords.txt"
http_access deny blockwords

# Block Rule for Domains
acl blockdomains dstdomain "/path_to/blockdomains.txt"
http_access deny blockdomains

# Block Rule for Blackweb
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

## IMPORTANT

BlackWeb is designed exclusively for [Squid-Cache](http://www.squid-cache.org/) and due to the large number of blocked domains it is not recommended to use it in other environments (DNSMasq, Pi-Hole, etc.), or add it to the Windows Hosts File, as it could slow down or crash it. **Use it at your own risk**. / BlackWeb está diseñado exclusivamente para [Squid-Cache](http://www.squid-cache.org/) y debido a la gran cantidad de dominios bloqueados no se recomienda usarlo en otros entornos (DNSMasq, Pi-Hole, etc.), o agregarlas al archivo Hosts File de Windows, ya que podría ralentizarlo o bloquearlo. **Úselo bajo su propio riesgo**.

For more information check [Issue 10](https://github.com/maravento/blackweb/issues/10#issuecomment-650834301)

## BLACKWEB UPDATE

---

### ⚠️ WARNING: BEFORE YOU CONTINUE

This section is only to explain how update and optimization process works. It is not necessary for user to run it. This process can take time and consume a lot of hardware and bandwidth resources, therefore it is recommended to use test equipment. / Esta sección es únicamente para explicar cómo funciona el proceso de actualización y optimización. No es necesario que el usuario la ejecute. Este proceso puede tardar y consumir muchos recursos de hardware y ancho de banda, por tanto se recomienda usar equipos de pruebas.

| Bash Update |
| ----------- |

>The update process of `blackweb.txt` consists of several steps and is executed in sequence by the script `bwupdate.sh`. / El proceso de actualización de `blackweb.txt` consta de varios pasos y es ejecutado en secuencia por el script `bwupdate.sh`.

>The script will request privileges when required. / El script solicitará privilegios cuando lo requiera.

```bash
wget -q -N https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/bwupdate.sh && chmod +x bwupdate.sh && ./bwupdate.sh
```

| Dependencies |
| ------------ |

>Update requires python 3x and bash 5x. / La actualización requiere python 3x y bash 5x.

```bash
pkgs='wget git curl libnotify-bin idn2 perl tar rar unrar unzip zip python-is-python3 squid'
if ! dpkg -s $pkgs >/dev/null 2>&1; then
  apt-get install $pkgs
fi
```

| Capture Public Blocklists |
| ------------------------- |

>Capture domains from downloaded public blocklists (see [SOURCES](https://github.com/maravento/blackweb#fuentes--sources)) and unifies them in a single file. / Captura los dominios de las listas de bloqueo públicas descargadas (ver [FUENTES](https://github.com/maravento/blackweb#fuentes--sources)) y las unifica en un solo archivo.

| Domain Debugging |
| ---------------- |

>Remove overlapping domains (`'.sub.example.com' is a subdomain of '.example.com'`), does homologation to Squid-Cache format and excludes false positives (google, hotmail, yahoo, etc.) with a allowlist (`allowurls.txt`). / Elimina dominios superpuestos (`'.sub.example.com' es un dominio de '.example.com'`), hace la homologación al formato de Squid-Cache y excluye falsos positivos (google, hotmail, yahoo, etc.) con una lista de permitidos (`allowurls.txt`).

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

| TLD Validation |
| ---------------|

>Remove domains with invalid TLDs (with a list of Public and Private Suffix TLDs: ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, eTLD, etc., up to 4th level 4LDs). / Elimina dominios con TLD inválidos (con una lista de TLDs Public and Private Suffix: ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, eTLD, etc., hasta 4to nivel 4LDs).

Input:

```bash
.domain.exe
.domain.com
.domain.edu.ca
```

Output:

```bash
.domain.com
.domain.edu.ca
```

| Debugging Punycode-IDN |
| -----------------------|

>Remove hostnames larger than 63 characters ([RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)) and other characters inadmissible by [IDN](http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html) and convert domains with international characters (non ASCII) and used for [homologous attacks](https://es.qwerty.wiki/wiki/IDN_homograph_attack) to [Punycode/IDNA](https://www.charset.org/punycode) format. / Elimina hostnames mayores a 63 caracteres ([RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)) y otros caracteres inadmisibles por [IDN](http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html) y convierte dominios con caracteres internacionales (no ASCII) y usados para [ataques homográficos](https://es.qwerty.wiki/wiki/IDN_homograph_attack) al formato [Punycode/IDNA](https://www.charset.org/punycode).

Input:

```bash
.президент.рф
.mañana.com
.bücher.com
.café.fr
.köln-düsseldorfer-rhein-main.de
.mūsųlaikas.lt
.sendesık.com
```

Output:

```bash
.xn--d1abbgf6aiiy.xn--p1ai
.xn--maana-pta.com
.xn--bcher-kva.com
.xn--caf-dma.fr
.xn--kln-dsseldorfer-rhein-main-cvc6o.de
.xn--mslaikas-qzb5f.lt
.xn--sendesk-wfb.com
```

| DNS Loockup |
| ------------|

>Most of the [SOURCES](https://github.com/maravento/blackweb#fuentes--sources) contain millions of invalid and nonexistent domains. Then, a double check of each domain is done (in 2 steps) via DNS and invalid and nonexistent are excluded from Blackweb. This process may take. By default it processes domains in parallel ≈ 6k to 12k x min, depending on the hardware and bandwidth. / La mayoría de las [FUENTES](https://github.com/maravento/blackweb#fuentes--sources) contienen millones de dominios inválidos e inexistentes. Entonces se hace una verificación doble de cada dominio (en 2 pasos) vía DNS y los inválidos e inexistentes se excluyen de Blackweb. Este proceso puede tardar. Por defecto procesa en paralelo dominios ≈ 6k a 12k x min, en dependencia del hardware y ancho de banda.

```bash
HIT google.com
google.com has address 142.251.35.238
google.com has IPv6 address 2607:f8b0:4008:80b::200e
google.com mail is handled by 10 smtp.google.com.

FAULT testfaultdomain.com
Host testfaultdomain.com not found: 3(NXDOMAIN)
```

For more information, check [internet live stats](https://www.internetlivestats.com/total-number-of-websites/)

| Excludes government-related TLDs |
| ---------------------------------|

>Remove government domains (.gov) and other related TLDs from BlackWeb. / Elimina de BlackWeb los dominios de gobierno (.gov) y otros TLD relacionados.

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

| Run Squid-Cache with BlackWeb |
| ----------------------------- |

>Run Squid-Cache with BlackWeb and any error sends it to `SquidError.txt` on your desktop. / Corre Squid-Cache con BlackWeb y cualquier error lo envía a `SquidError.txt` en su escritorio.

| Check execution (/var/log/syslog) |
| --------------------------------- |

```bash
BlackWeb: Done 06/05/2023 15:47:14
```

#### Important about BlackWeb Update

- The default path of BlackWeb is `/etc/acl`. You can change it for your preference. / El path por default de BlackWeb es `/etc/acl`. Puede cambiarlo por el de su preferencia.
- `bwupdate.sh` includes lists of remote support related domains (Teamviewer, Anydesk, logmein, etc) and web3 domains. They are commented by default (unless their domains are in [SOURCES](https://github.com/maravento/blackweb#sources--sources)). To block or exclude them you must activate the corresponding lines in the script (# JOIN LIST), although it is not recommended to avoid conflicts or false positives. / `bwupdate.sh` incluye listas de dominios relacionados con soporte remoto (Teamviewer, Anydesk, logmein, etc) y dominios web3. Están comentadas por defecto (excepto que sus dominios estén en las [FUENTES](https://github.com/maravento/blackweb#fuentes--sources)). Para bloquearlas o excluirlas debe activar las líneas correspondientes en el script (# JOIN LIST), aunque no se recomienda para evitar conflictos o falsos positivos.
- If you need to interrupt the execution of `bwupdate.sh` (ctrl + c) and it stopped at the [DNS Loockup](https://github.com/maravento/blackweb#dns-loockup) part, it will restart at that point. If you stop it earlier, you will have to start from the beginning or modify the script manually so that it starts from the desired point. / Si necesita interrumpir la ejecución de `bwupdate.sh` (ctrl + c) y se detuvo en la parte de [DNS Loockup](https://github.com/maravento/blackweb#dns-loockup), reiniciará en ese punto. Si lo detiene antes deberá comenzar desde el principio o modificar el script manualmente para que inicie desde el punto deseado.
- If someone believes that any URL, included in `allowurls.txt` and `blockurls.txt`, should not be in these lists, can create an [Issue](https://github.com/maravento/blackweb/issues) and notify to remove it. / Si alguien considera que alguna URL, incluida en `allowurls.txt` y `blockurls.txt`, no debería estar en estas listas, puede crear un [Issue](https://github.com/maravento/blackweb/issues) y notificar para removerla.

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
- [adblockplus. - easylistlithuania](https://easylist-downloads.adblockplus.org/easylistlithuania+easylist.txt)
- [anudeepND - adservers](https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt)
- [anudeepND - coinminer](https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt)
- [AssoEchap - stalkerware-indicators](https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts)
- [azet12 - KADhosts](https://raw.githubusercontent.com/azet12/KADhosts/master/KADhosts.txt)
- [badmojr - 1Hosts](https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt)
- [BarbBlock - blacklists](https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt)
- [BBcan177  - minerchk](https://github.com/BBcan177/minerchk)
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
- [crazy-max - WindowsSpyBlocker](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt)
- [CriticalPathSecurity - Public-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/)
- [DandelionSprout - adfilt](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt)
- [Dawsey21 - adblock-list](https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt)
- [Dawsey21 - main-blacklist](https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt)
- [developerdan - ads-and-tracking-extended](https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt)
- [digitalside - Threat-Intel](https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt)
- [Disconnect.me - simple_ad](https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt)
- [Disconnect.me - simple_malvertising](https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt)
- [Disconnect.me - simple_tracking](https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt)
- [dorxmi - nothingblock](https://github.com/dorxmi/nothingblock)
- [EasyList - EasyListHebrew](https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt)
- [ethanr - dns-blacklists](https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt)
- [fabriziosalmi - blacklists](https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt)
- [FadeMind - 2o7Net](https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts)
- [FadeMind - Risk](https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts)
- [FadeMind - Spam](https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts)
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
- [heradhis - Indonesian ABPindo](https://raw.githubusercontent.com/heradhis/indonesianadblockrules/master/subscriptions/abpindo.txt)
- [hexxium - threat-list/](https://hexxiumcreations.github.io/threat-list/hexxiumthreatlist.txt)
- [hoshsadiq - adblock-nocoin-list](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt)
- [hostsfile - hosts](https://hostsfile.org/Downloads/hosts.txt)
- [jawz101 - potentialTrackers](https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv)
- [jdlingyu - ad-wars](https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts)
- [joelotz - URL_Blacklist](https://raw.githubusercontent.com/joelotz/URL_Blacklist/master/blacklist.csv)
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
- [notabug - Latvian List](https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt)
- [notracking - hosts-blocklists](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt)
- [Oleksiig - Squid-BlackList](https://raw.githubusercontent.com/oleksiig/Squid-BlackList/master/denied_ext.conf)
- [openphish - feed](https://openphish.com/feed.txt)
- [pengelana - domains blocklist](https://raw.githubusercontent.com/pengelana/blocklist/master/domain.txt)
- [Perflyst - PiHoleBlocklist Android](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt)
- [Perflyst - PiHoleBlocklist SmartTV](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt)
- [phishing.army - phishing_army_blocklist_extended](https://phishing.army/download/phishing_army_blocklist_extended.txt)
- [piperun - iploggerfilter](https://github.com/piperun/iploggerfilter)
- [Quedlin - domains](https://github.com/quedlin/blacklist/blob/master/domains)
- [quidsup - notrack-blocklists](https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt)
- [quidsup - notrack-malware](https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt)
- [reddestdream - MinimalHostsBlocker](https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts)
- [RooneyMcNibNug - pihole-stuff](https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt)
- [Rpsl - adblock-leadgenerator-list](https://github.com/Rpsl/adblock-leadgenerator-list)
- [ruvelro - Halt-and-Block-Mining](https://raw.githubusercontent.com/ruvelro/Halt-and-Block-Mining/master/HBmining.bat)
- [ryanbr - fanboy-adblock](https://github.com/ryanbr/fanboy-adblock)
- [scamaNet - blocklist](https://raw.githubusercontent.com/scamaNet/blocklist/main/blocklist.txt)
- [Someonewhocares - hosts](https://someonewhocares.org/hosts/hosts)
- [stanev.org - Bulgarian adblock list](http://stanev.org/abp/adblock_bg.txt)
- [StevenBlack - add.2o7Net](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts)
- [StevenBlack - add.Risk](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts)
- [StevenBlack - fakenews-gambling-porn-social](https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts)
- [StevenBlack - hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
- [StevenBlack - spam](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts)
- [StevenBlack - uncheckyAds](https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts)
- [Stopforumspam - Toxic Domains](https://www.stopforumspam.com/downloads/toxic_domains_whole.txt)
- [Taz - SpamDomains](http://www.taz.net.au/Mail/SpamDomains)
- [tomasko126 - Easylist Czech and Slovak filter list](https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt)
- [txthinking - blackwhite](https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list)
- [txthinking - bypass china domains](https://raw.githubusercontent.com/txthinking/bypass/master/china_domain.txt)
- [Ultimate Hosts Blacklist - hosts](https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/tree/master/hosts)
- [Université Toulouse 1 Capitole - Blacklists UT1](https://dsi.ut-capitole.fr/blacklists/index_en.php)
- [vokins - yhosts](https://raw.githubusercontent.com/vokins/yhosts/master/hosts)
- [Winhelp2002 - hosts](http://winhelp2002.mvps.org/hosts.txt)
- [yourduskquibbles - Web Annoyances Ultralist](https://github.com/yourduskquibbles/webannoyances)
- [yous - YousList](https://raw.githubusercontent.com/yous/YousList/master/youslist.txt)
- [yoyo - Peter Lowe’s Ad and tracking server list](http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)
- [zerodot1 - CoinBlockerLists list_browser](https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt)
- [zerodot1 - CoinBlockerLists list](https://zerodot1.gitlab.io/CoinBlockerLists/list.txt)
- [zerodot1 - CoinBlockerLists list_optional](https://zerodot1.gitlab.io/CoinBlockerLists/list_optional.txt)
- [zoso - Romanian Adblock List](https://zoso.ro/pages/rolist.txt)

#### Inactive, Offline, Discontinued or Private

- [280blocker - 280blocker_domain](https://280blocker.net/files/280blocker_domain.txt)
- [abuse.ch - Ransomware Abuse CryptoWall](https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt)
- [abuse.ch - Ransomware Abuse Domain Blocklist](https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt)
- [abuse.ch - Ransomware Abuse Locky](https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt)
- [abuse.ch - Ransomware Abuse RW_URLB](https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt)
- [abuse.ch - Ransomware Abuse TorrentLocker](https://ransomwaretracker.abuse.ch/downloads/TL_C2_DOMBL.txt)
- [abuse.ch - Ransomware Abuse URL Blocklist](https://ransomwaretracker.abuse.ch/downloads/TC_C2_DOMBL.txt)
- [abuse.ch - Zeustracker](https://zeustracker.abuse.ch/blocklist.php?download=squiddomain)
- [adblockplus - malwaredomains_full](https://easylist-downloads.adblockplus.org/malwaredomains_full.txt)
- [BambenekConsulting - dga-feed](http://osint.bambenekconsulting.com/feeds/dga-feed.txt)
- [Carl - Spam](http://www.carl.net/spam/access.txt)
- [cedia - domains](https://mirror.cedia.org.ec/malwaredomains/domains.txt)
- [cedia - immortal_domains](https://mirror.cedia.org.ec/malwaredomains/immortal_domains.txt)
- [CHEF-KOCH - BarbBlock-filter-list](https://github.com/CHEF-KOCH/BarbBlock-filter-list)
- [Cibercrime-Tracker](http://cybercrime-tracker.net/all.php)
- [dshield - High](https://www.dshield.org/feeds/suspiciousdomains_High.txt)
- [dshield - Low](http://www.dshield.org/feeds/suspiciousdomains_Low.txt)
- [dshield - Medium](https://www.dshield.org/feeds/suspiciousdomains_Medium.txt)
- [firebog - Airelle-hrsk](https://v.firebog.net/hosts/Airelle-hrsk.txt)
- [firebog - Airelle-trc](https://v.firebog.net/hosts/Airelle-trc.txt)
- [firebog - BillStearns](https://v.firebog.net/hosts/BillStearns.txt)
- [firebog - Prigent-Phishing](https://v.firebog.net/hosts/Prigent-Phishing.txt)
- [firebog - Shalla-mal](https://v.firebog.net/hosts/Shalla-mal.txt)
- [gfmaster - adblock-korea](https://raw.githubusercontent.com/gfmaster/adblock-korea-contrib/master/filter.txt)
- [hosts-file - ad_servers](https://hosts-file.net/ad_servers.txt)
- [hosts-file - emd](https://hosts-file.net/emd.txt)
- [hosts-file - grm](https://hosts-file.net/grm.txt)
- [hosts-file - hosts](http://hosts-file.net/download/hosts.txt)
- [hosts-file - psh](https://hosts-file.net/psh.txt)
- [Joewein - dom-bl-base](http://www.joewein.net/dl/bl/dom-bl-base.txt)
- [Joewein - dom-bl](http://www.joewein.net/dl/bl/dom-bl.txt)
- [malc0de - bl](http://malc0de.com/bl/)
- [Malware Domains - justdomains](http://mirror1.malwaredomains.com/files/justdomains)
- [Malwaredomainlist - Hosts](http://www.malwaredomainlist.com/hostslist/hosts.txt)
- [MESD squidguard - blacklists](http://squidguard.mesd.k12.or.us/blacklists.tgz)
- [Netlab360 - DGA Domains](https://data.netlab.360.com/feeds/dga/dga.txt)
- [nfz.moe - hosts](https://hosts.nfz.moe/full/hosts)
- [Passwall - SpamAssassin](http://www.passwall.com/blacklist.txt)
- [ShadowWhisperer - BlockLists](https://github.com/ShadowWhisperer/BlockLists)
- [Shallalist.de - shallalist](http://www.shallalist.de/Downloads/shallalist.tar.gz)
- [squidblacklist.org - dg-ads](https://www.squidblacklist.org/downloads/dg-ads.acl)
- [squidblacklist.org - dg-malicious.acl](https://www.squidblacklist.org/downloads/dg-malicious.acl)
- [tankmohit - UnifiedHosts](https://raw.githubusercontent.com/tankmohit/UnifiedHosts/master/hosts.all)
- [UrlBlacklist - UrlBlacklist](https://web.archive.org/web/*/http://urlblacklist.com)
- [zerodot1 - list_browser_UBO](https://zerodot1.gitlab.io/CoinBlockerLists/list_browser_UBO.txt)

### DEBUG LISTS

- [Allow DNS](https://github.com/maravento/blackweb/tree/master/bwupdate/lst)
- [Allow URLs](https://github.com/maravento/blackweb/tree/master/bwupdate/lst)
- [Block TLDs](https://github.com/maravento/blackweb/tree/master/bwupdate/lst)
- [Block URLs](https://github.com/maravento/blackweb/tree/master/bwupdate/lst)
- [firebog sources](https://firebog.net/)
- [google supported domains](https://www.google.com/supported_domains)
- [iana](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
- [Invalid TLDs](https://github.com/maravento/blackweb/tree/master/bwupdate/lst)
- [ipv6-hosts](https://raw.githubusercontent.com/lennylxx/ipv6-hosts/master/hosts) (Partial)
- [publicsuffix](https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat)
- [Ransomware Database](https://docs.google.com/spreadsheets/u/1/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml#)
- [Remote](https://github.com/maravento/blackweb/tree/master/bwupdate/lst)
- [University Domains and Names Data List](https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json)
- [whoisxmlapi](https://www.whoisxmlapi.com/support/supported_gtlds.php)

### WORKTOOLS

- [CTFR](https://github.com/UnaPibaGeek/ctfr)
- [Debug internal lst](https://github.com/maravento/blackweb/tree/master/bwupdate/tools)
- [Debug Squid-Cache Errors](https://github.com/maravento/blackweb/tree/master/bwupdate/tools)
- [idn2](http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html)
- [Parse Domains](https://raw.githubusercontent.com/lsemel/python-parse-domain/master/tools/parse_domain.py) ([modified](https://github.com/maravento/blackweb/tree/master/bwupdate/tools))

## REFERENCES TO BLACKWEB

---

- [Awesome Open Source: Blackweb](https://awesomeopensource.com/project/maravento/blackweb)
- [community ipfire: url filter and self updating blacklists](https://community.ipfire.org/t/url-filter-and-self-updating-blacklists/6601)
- [covert.io: Getting Started with DGA Domain Detection Research](http://www.covert.io/getting-started-with-dga-research/)
- [crazymax: WindowsSpyBlocker](https://crazymax.dev/WindowsSpyBlocker/)
- [Jason Trost: Getting Started with DGA Domain Detection Research](https://jason-trost.medium.com/getting-started-with-dga-domain-detection-research-89af69213257)
- [kandi.openweaver: Domains Blocklist for Squid-Cache](https://kandi.openweaver.com/shell/maravento/blackweb)
- [Kerry Cordero: Blocklists of Suspected Malicious IPs and URLs](https://cordero.me/blocklists-of-suspected-malicious-ips-and-urls/)
- [Keystone Solutions: blocklists](https://keystonesolutions.io/solutions/blocklists/)
- [Lifars: Sites with blocklist of malicious IPs and URLs](https://lifars.com/wp-content/uploads/2017/06/LIFARS_Guide_Sites-with-blocklist-of-malicious-IPs-and-URLs.pdf)
- [opensourcelibs: Blackweb](https://opensourcelibs.com/lib/blackweb)
- [OSINT Framework: Domain Name/Domain Blacklists/Blackweb](https://osintframework.com/)
- [Secrepo: Samples of Security Related Data](http://www.secrepo.com/)
- [Segu-Info: Análisis de malware y sitios web en tiempo real](https://blog.segu-info.com.ar/2019/07/analisis-de-malware-y-sitios-web-en.html)
- [Segu-Info: Dominios/TLD dañinos que pueden ser bloqueados para evitar spam y #phishing](https://blog.segu-info.com.ar/2024/05/dominiostld-daninos-que-pueden-ser.html)
- [Soficas: CiberSeguridad - Protección Activa](https://soficas.com/noticias/proteccion-ciberseguridad.html)
- [stackoverflow: Blacklist IP database](https://stackoverflow.com/a/39516166/8747573)
- [Wikipedia: Blacklist_(computing)](https://en.wikipedia.org/wiki/Blacklist_(computing)#:~:text=There%20are%20also%20free%20blacklists%20for%20Squid%20(software)%20proxy%2C%20such%20as%20Blackweb)
- [Xploitlab: Projects using WindowsSpyBlocker](https://xploitlab.com/windowsspyblocker-block-spying-and-tracking-on-windows/)
- [Zeltser: Free Blocklists of Suspected Malicious IPs and URLs](https://zeltser.com/malicious-ip-blocklists/)
- [zenarmor: How-to-enable-web-filtering-on-OPNsense-proxy?](https://www.zenarmor.com/docs/network-security-tutorials/how-to-set-up-caching-proxy-in-opnsense#how-to-enable-web-filtering-on-opnsense-proxy)

## STARGAZERS

---

[![Stargazers](https://bytecrank.com/nastyox/reporoster/php/stargazersSVG.php?user=maravento&repo=blackweb)](https://github.com/maravento/blackweb/stargazers)

## CONTRIBUTIONS

---

We thank all those who have contributed to this project. Those interested can contribute, sending us links of new lists, to be included in this project. / Agradecemos a todos aquellos que han contribuido a este proyecto. Los interesados pueden contribuir, enviándonos enlaces de nuevas listas, para ser incluidas en este proyecto.

Special thanks to: [Jhonatan Sneider](https://github.com/sney2002)

## SPONSOR THIS PROJECT

---

[![Image](https://raw.githubusercontent.com/maravento/winexternal/master/img/maravento-paypal.png)](https://paypal.me/maravento)

## LICENSES

---

[![GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl.txt)
[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC_BY--SA_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)

## DISCLAIMER

---

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## OBJECTION

---

Due to recent arbitrary changes in computer terminology, it is necessary to clarify the meaning and connotation of the term **blacklist**, associated with this project: *In computing, a blacklist, denylist or blocklist is a basic access control mechanism that allows through all elements (email addresses, users, passwords, URLs, IP addresses, domain names, file hashes, etc.), except those explicitly mentioned. Those items on the list are denied access. The opposite is a whitelist, which means only items on the list are let through whatever gate is being used.*

Debido a los recientes cambios arbitrarios en la terminología informática, es necesario aclarar el significado y connotación del término **blacklist**, asociado a este proyecto: *En informática, una lista negra, lista de denegación o lista de bloqueo es un mecanismo básico de control de acceso que permite a través de todos los elementos (direcciones de correo electrónico, usuarios, contraseñas, URL, direcciones IP, nombres de dominio, hashes de archivos, etc.), excepto los mencionados explícitamente. Esos elementos en la lista tienen acceso denegado. Lo opuesto es una lista blanca, lo que significa que solo los elementos de la lista pueden pasar por cualquier puerta que se esté utilizando.*

Source [Wikipedia](https://en.wikipedia.org/wiki/Blacklist_(computing))

Therefore / Por tanto

**blacklist**, **blocklist**, **blackweb**, **blackip**, **whitelist**, **etc.**

are terms that have nothing to do with racial discrimination / son términos que no tienen ninguna relación con la discriminación racial.
