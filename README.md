# [BlackWeb](https://www.maravento.com/p/blackweb.html)

[![status-maintained](https://img.shields.io/badge/status-maintained-purple.svg)](https://github.com/maravento/blackweb)
[![last commit](https://img.shields.io/github/last-commit/maravento/blackweb)](https://github.com/maravento/blackweb)
[![Twitter Follow](https://img.shields.io/twitter/follow/maraventostudio.svg?style=social)](https://twitter.com/maraventostudio)

<!-- markdownlint-disable MD033 -->

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <b>BlackWeb</b> is a project that collects and unifies public blocklists of domains (porn, downloads, drugs, malware, spyware, trackers, bots, social networks, warez, weapons, etc.) to make them compatible with <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <b>BlackWeb</b> es un proyecto que recopila y unifica listas públicas de bloqueo de dominios (porno, descargas, drogas, malware, spyware, trackers, bots, redes sociales, warez, armas, etc.) para hacerlas compatibles con <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>.
    </td>
  </tr>
</table>

## DATA SHEET

---

| ACL | Blocked Domains | File Size |
| :---: | :---: | :---: |
| blackweb.txt | 5417944 | 131,3 MB |

## GIT CLONE

---

```bash
git clone --depth=1 https://github.com/maravento/blackweb.git
```

## HOW TO USE

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <code>blackweb.txt</code> is already updated and optimized for <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>. Download it and unzip it in the path of your preference and activate the <a href="#blackweb-rule-for-squid-cache">Squid-Cache Rule</a>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>blackweb.txt</code> ya viene actualizada y optimizada para <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>. Descárguela y descomprímala en la ruta de su preferencia y active la <a href="#blackweb-rule-for-squid-cache">Regla de Squid-Cache</a>.
    </td>
  </tr>
</table>

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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Edit:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Edite:
    </td>
  </tr>
</table>

```bash
/etc/squid/squid.conf
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      And add the following lines:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Y agregue las siguientes líneas:
    </td>
  </tr>
</table>

```bash
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS

# Block Rule for Blackweb
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

#### Advanced Rules

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      BlackWeb contains millions of domains, therefore it is recommended:
    </td>
    <td style="width: 50%; vertical-align: top;">
      BlackWeb contiene millones de dominios, por tanto se recomienda:
    </td>
  </tr>
</table>

##### Allow Rule for Domains

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use <code>allowdomains.txt</code> to exclude essential domains or subdomains, such as <code>.accounts.google.com</code>, <code>.yahoo.com</code>, <code>.github.com</code>, etc. According to <a href="http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube" target="_blank">Squid's documentation</a>, the subdomains <code>accounts.google.com</code> and <code>accounts.youtube.com</code> may be used by Google for authentication within its ecosystem. Blocking them could disrupt access to services like Gmail, Drive, Docs, and others.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Use <code>allowdomains.txt</code> para excluir dominios o subdominios esenciales, como <code>.accounts.google.com</code>, <code>.yahoo.com</code>, <code>.github.com</code>, etc. Según la <a href="http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube" target="_blank">documentación de Squid</a>, los subdominios <code>accounts.google.com</code> y <code>accounts.youtube.com</code> pueden ser utilizados por Google para la autenticación dentro de su ecosistema. Bloquearlos podría interrumpir el acceso a servicios como Gmail, Drive, Docs, entre otros.
    </td>
  </tr>
</table>

```bash
acl allowdomains dstdomain "/path_to/allowdomains.txt"
http_access allow allowdomains
```

##### Block Rule for Domains

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use <code>blockdomains.txt</code> to block any other domain not included in <code>blackweb.txt</code>
    </td>
    <td style="width: 50%; vertical-align: top;">
      Utilice <code>blockdomains.txt</code> para bloquear cualquier otro dominio no incluido en <code>blackweb.txt</code>
    </td>
  </tr>
</table>

```bash
acl blockdomains dstdomain "/path_to/blockdomains.txt"
http_access deny blockdomains
```

##### Block Rule for gTLD, sTLD, ccTLD, etc

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use <code>blocktlds.txt</code> to block gTLD, sTLD, ccTLD, etc.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Use <code>blocktlds.txt</code> para bloquear gTLD, sTLD, ccTLD, etc.
    </td>
  </tr>
</table>

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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use this rule to block <a href="https://datatracker.ietf.org/doc/html/rfc3492" target="_blank">Punycode - RFC3492</a>, IDN | Non-ASCII (TLDs or Domains), to prevent an <a href="https://en.wikipedia.org/wiki/IDN_homograph_attack" target="_blank">IDN homograph attack</a>. For more information visit <a href="https://www.welivesecurity.com/2017/07/27/homograph-attacks-see-to-believe/" target="_blank">welivesecurity: Homograph attacks</a>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Usar esta regla para bloquear <a href="https://datatracker.ietf.org/doc/html/rfc3492" target="_blank">Punycode - RFC3492</a>, IDN | Non-ASCII (TLDs o Dominios), para prevenir un <a href="https://en.wikipedia.org/wiki/IDN_homograph_attack" target="_blank">ataque homógrafo IDN</a>. Para mayor información visite <a href="https://www.welivesecurity.com/la-es/2017/07/13/ataques-homograficos/" target="_blank">welivesecurity: Ataques homográficos</a>.
    </td>
  </tr>
</table>

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

##### Block Rule for Patterns

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use this rule to block patterns (Optional. Can generate false positives).
    </td>
    <td style="width: 50%; vertical-align: top;">
      Use esta regla para bloquear patrones (Opcional. Puede generar falsos positivos).
    </td>
  </tr>
</table>

```bash
# Example: Download ACL:
sudo wget -P /etc/acl/acl_squid https://raw.githubusercontent.com/maravento/vault/refs/heads/master/blackshield/acl/source/squid/blockpatterns.txt
# Squid Rule to Block Patterns (change path):
acl blockwords url_regex -i "/etc/acl/acl_squid/blockpatterns.txt"
http_access deny blockpatterns
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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use <code>streaming.txt</code> to block streaming domains not included in <code>blackweb.txt</code> (for example: <code>.youtube.com</code>, <code>.googlevideo.com</code>, <code>.ytimg.com</code>, etc.).
    </td>
    <td style="width: 50%; vertical-align: top;">
      Utilice <code>streaming.txt</code> para bloquear dominios de streaming no incluidos en <code>blackweb.txt</code> (por ejemplo: <code>.youtube.com</code>, <code>.googlevideo.com</code>, <code>.ytimg.com</code>, etc.).
    </td>
  </tr>
</table>

```bash
acl streaming dstdomain "/path_to/streaming.txt"
http_access deny streaming
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <b>Note:</b> This list may contain overlapping domains. It is important to manually clean it according to the proposed objective. Example:
      <ul>
        <li>If your goal is to block Facebook, keep the primary domains and remove specific subdomains.</li>
        <li>If your goal is to block features, like Facebook streaming, keep the specific subdomains and remove the primary domains to avoid impacting overall site access. Example:</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      <b>Nota:</b> Esta lista puede contener dominios superpuestos. Es importante depurarla manualmente según el objetivo propuesto. Ejemplo:
      <ul>
        <li>Si el objetivo es bloquear Facebook, conserva los dominios principales y elimina los subdominios específicos.</li>
        <li>Si el objetivo es bloquear funcionalidades, como el streaming de Facebook, mantén los subdominios específicos y elimina los dominios principales para no afectar el acceso general al sitio. Ejemplo:</li>
      </ul>
    </td>
  </tr>
</table>

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
# https://raw.githubusercontent.com/maravento/vault/refs/heads/master/blackshield/acl/source/squid/blockpatterns.txt
acl blockwords url_regex -i "/path_to/blockpatterns.txt"
http_access deny blockpatterns

# Block Rule for web3 (Optional)
# https://raw.githubusercontent.com/maravento/vault/refs/heads/master/blackshield/acl/source/web3/web3domains.txt
acl web3 dstdomain "/path_to/web3domains.txt"
http_access deny web3

# Block Rule for Blackweb
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

## BLACKWEB UPDATE

---

### ⚠️ WARNING: BEFORE YOU CONTINUE

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      This section is only to explain how the update and optimization process works. It is not necessary for the user to run it. This process can take time and consume a lot of hardware and bandwidth resources, therefore it is recommended to use test equipment.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Esta sección es únicamente para explicar cómo funciona el proceso de actualización y optimización. No es necesario que el usuario la ejecute. Este proceso puede tardar y consumir muchos recursos de hardware y ancho de banda, por tanto se recomienda usar equipos de pruebas.
    </td>
  </tr>
</table>

#### Bash Update

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      The update process of <code>blackweb.txt</code> consists of several steps and is executed in sequence by the script <code>bwupdate.sh</code>. The script will request privileges when required.
    </td>
    <td style="width: 50%; vertical-align: top;">
      El proceso de actualización de <code>blackweb.txt</code> consta de varios pasos y es ejecutado en secuencia por el script <code>bwupdate.sh</code>. El script solicitará privilegios cuando lo requiera.
    </td>
  </tr>
</table>

```bash
wget -q -N https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/bwupdate.sh && chmod +x bwupdate.sh && ./bwupdate.sh
```

#### Dependencies

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Update requires python 3x and bash 5x. It also requires the following dependencies:
    </td>
    <td style="width: 50%; vertical-align: top;">
      La actualización requiere python 3x y bash 5x. También requiere las siguientes dependencias:
    </td>
  </tr>
</table>

```bash
wget git curl tar unzip zip gzip idn2 squid python3 bind9-host
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Make sure your Squid is installed correctly. If you have any problems, run the following script: (<code>sudo ./squid_install.sh</code>):
    </td>
    <td style="width: 50%; vertical-align: top;">
      Asegúrese de que Squid esté instalado correctamente. Si tiene algún problema, ejecute el siguiente script: (<code>sudo ./squid_install.sh</code>):
    </td>
  </tr>
</table>

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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Capture domains from downloaded public blocklists (see <a href="#sources">SOURCES</a>) and unify them in a single file.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Captura los dominios de las listas de bloqueo públicas descargadas (ver <a href="#sources">FUENTES</a>) y las unifica en un solo archivo.
    </td>
  </tr>
</table>

#### Domains Debugging

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Remove overlapping domains (<code>'.sub.example.com' is a subdomain of '.example.com'</code>), does homologation to Squid-Cache format and excludes false positives (google, hotmail, yahoo, etc.) with an allowlist (<code>debugwl.txt</code>).
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina dominios superpuestos (<code>'.sub.example.com' es un dominio de '.example.com'</code>), hace la homologación al formato de Squid-Cache y excluye falsos positivos (google, hotmail, yahoo, etc.) con una lista de permitidos (<code>debugwl.txt</code>).
    </td>
  </tr>
</table>

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

#### TLD Validation

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Remove domains with invalid TLDs (with a list of Public and Private Suffix TLDs: ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, eTLD, etc., up to 4th level 4LDs).
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina dominios con TLD inválidos (con una lista de TLDs Public and Private Suffix: ccTLD, ccSLD, sTLD, uTLD, gSLD, gTLD, eTLD, etc., hasta 4to nivel 4LDs).
    </td>
  </tr>
</table>

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

#### Debugging Punycode-IDN

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Remove hostnames larger than 63 characters (<a href="https://www.ietf.org/rfc/rfc1035.txt" target="_blank">RFC 1035</a>) and other characters inadmissible by <a href="http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html" target="_blank">IDN</a> and convert domains with international characters (non ASCII) and used for <a href="https://en.wikipedia.org/wiki/IDN_homograph_attack" target="_blank">homograph attacks</a> to <a href="https://www.charset.org/punycode" target="_blank">Punycode/IDNA</a> format.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina hostnames mayores a 63 caracteres (<a href="https://www.ietf.org/rfc/rfc1035.txt" target="_blank">RFC 1035</a>) y otros caracteres inadmisibles por <a href="http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html" target="_blank">IDN</a> y convierte dominios con caracteres internacionales (no ASCII) y usados para <a href="https://es.qwerty.wiki/wiki/IDN_homograph_attack" target="_blank">ataques homográficos</a> al formato <a href="https://www.charset.org/punycode" target="_blank">Punycode/IDNA</a>.
    </td>
  </tr>
</table>

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

#### Debugging non-ASCII characters

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Removes entries with invalid encoding, non-printable characters, whitespace, disallowed symbols, and any content that does not conform to the strict ASCII format for valid domain names (CP1252, ISO-8859-1, corrupted UTF-8, etc.). Converts the output to plain text with <code>charset=us-ascii</code>, ensuring a clean, standardized list ready for validation, comparison, or DNS resolution:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina entradas con codificación incorrecta, caracteres no imprimibles, espacios en blanco, símbolos no permitidos y cualquier contenido que no se ajuste al formato ASCII estricto para nombres de dominio válidos (CP1252, ISO-8859-1, UTF-8 corrupto, etc.) y convierte la salida a texto sin formato <code>charset=us-ascii</code>, lo que garantiza una lista limpia y estandarizada, lista para validación, comparación o resolución DNS:
    </td>
  </tr>
</table>

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

#### DNS Lookup

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Most of the <a href="#sources">SOURCES</a> contain millions of invalid or nonexistent domains, so each domain is double-checked via DNS (in 2 steps) to exclude those entries from Blackweb. This process is performed in parallel and can be resource-intensive, depending on your hardware and network conditions. You can control concurrency with the <code>PROCS</code> variable:
    </td>
    <td style="width: 50%; vertical-align: top;">
      La mayoría de las <a href="#sources">FUENTES</a> contienen millones de dominios inválidos o inexistentes, por lo que cada dominio se verifica mediante DNS (en dos pasos) para excluir esas entradas de Blackweb. Este proceso se realiza en paralelo y puede consumir muchos recursos, dependiendo del hardware y las condiciones de la red. Puede controlar la concurrencia con la variable <code>PROCS</code>:
    </td>
  </tr>
</table>

```bash
PROCS=$(($(nproc)))        # Conservative (network-friendly)
PROCS=$(($(nproc) * 2))    # Balanced
PROCS=$(($(nproc) * 4))    # Aggressive (default)
PROCS=$(($(nproc) * 8))    # Extreme (8 or higher, use with caution)
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      For example, on a system with a Core i5 CPU (4 physical cores / 8 threads with Hyper-Threading):
    </td>
    <td style="width: 50%; vertical-align: top;">
      Por ejemplo, en un sistema con una CPU Core i5 (4 núcleos físicos/8 subprocesos con Hyper-Threading):
    </td>
  </tr>
</table>

```bash
nproc             → 8
PROCS=$((8 * 4))  → 32 parallel queries
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <b>⚠️ Warning:</b> High <code>PROCS</code> values increase DNS resolution speed but may saturate your CPU or bandwidth, especially on limited networks like satellite links. Adjust accordingly. Real-time processing example:
    </td>
    <td style="width: 50%; vertical-align: top;">
      <b>⚠️ Advertencia:</b> Los valores altos de <code>PROCS</code> aumentan la velocidad de resolución del DNS, pero pueden saturar la CPU o el ancho de banda, especialmente en redes limitadas como enlaces satelitales. Ajuste el sistema según corresponda. Ejemplo de procesamiento en tiempo real:
    </td>
  </tr>
</table>

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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Remove government domains (.gov) and other related TLDs from BlackWeb.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina de BlackWeb los dominios de gobierno (.gov) y otros TLD relacionados.
    </td>
  </tr>
</table>

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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Run Squid-Cache with BlackWeb and any error sends it to <code>SquidError.txt</code>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Corre Squid-Cache con BlackWeb y cualquier error lo envía a <code>SquidError.txt</code>.
    </td>
  </tr>
</table>

#### Log

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Both <code>bwupdate.sh</code> and <code>checksources.sh</code> generate a log file (<code>bwupdate.log</code> / <code>checksources.log</code>) in the same directory where they are executed.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>bwupdate.sh</code> y <code>checksources.sh</code> generan un archivo de log (<code>bwupdate.log</code> / <code>checksources.log</code>) en el mismo directorio donde se ejecutan.
    </td>
  </tr>
</table>

#### Important about BlackWeb Update

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>The default path of BlackWeb is <code>/etc/acl</code>. You can change it for your preference.</li>
        <li>If you need to interrupt the execution of <code>bwupdate.sh</code> (ctrl + c) and it stopped at the <a href="#dns-lookup">DNS Lookup</a> part, it will restart at that point. If you stop it earlier, you will have to start from the beginning or modify the script manually so that it starts from the desired point.</li>
        <li>If you use <code>aufs</code>, temporarily change it to <code>ufs</code> during the upgrade, to avoid: <code>ERROR: Can't change type of existing cache_dir aufs /var/spool/squid to ufs. Restart required</code>.</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>El path por default de BlackWeb es <code>/etc/acl</code>. Puede cambiarlo por el de su preferencia.</li>
        <li>Si necesita interrumpir la ejecución de <code>bwupdate.sh</code> (ctrl + c) y se detuvo en la parte de <a href="#dns-lookup">DNS Lookup</a>, reiniciará en ese punto. Si lo detiene antes deberá comenzar desde el principio o modificar el script manualmente para que inicie desde el punto deseado.</li>
        <li>Si usa <code>aufs</code>, cámbielo temporalmente a <code>ufs</code> durante la actualización, para evitar: <code>ERROR: Can't change type of existing cache_dir aufs /var/spool/squid to ufs. Restart required</code>.</li>
      </ul>
    </td>
  </tr>
</table>

## SOURCES

---

### BLOCKLISTS

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
- [yoyo - Peter Lowe's Ad and tracking server list](http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml)
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
- [Wikipedia: Blacklist_(computing)](<https://en.wikipedia.org/wiki/Blacklist_(computing)#:~:text=There%20are%20also%20free%20blacklists%20for%20Squid%20(software)%20proxy%2C%20such%20as%20Blackweb>)
- [Xploitlab: Projects using WindowsSpyBlocker](https://xploitlab.com/windowsspyblocker-block-spying-and-tracking-on-windows/)
- [Zeltser: Free Blocklists of Suspected Malicious IPs and URLs](https://zeltser.com/malicious-ip-blocklists/)
- [Zenarmor: How-to-enable-web-filtering-on-OPNsense-proxy?](https://www.zenarmor.com/docs/network-security-tutorials/how-to-set-up-caching-proxy-in-opnsense#how-to-enable-web-filtering-on-opnsense-proxy)

## NOTICE

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>This project includes third-party components.</li>
        <li>Changes must be proposed via Issues. Pull Requests are not accepted.</li>
        <li>BlackWeb is designed exclusively for <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a> and due to the large number of blocked domains it is not recommended to use it in other environments (DNSMasq, Pi-Hole, etc.), or add it to the Windows Hosts File, as it could slow down or crash it. <b>Use it at your own risk</b>. For more information check <a href="https://github.com/maravento/blackweb/issues/10#issuecomment-650834301" target="_blank">Issue 10</a></li>
        <li><b>Blackweb is NOT a blacklist service itself</b>. It does not independently verify domains. Its purpose is to consolidate and reformat public blacklist sources to make them compatible with Squid.</li>
        <li>If your domain appears in Blackweb and you believe this is an error, you should review the public sources in <a href="#sources">SOURCES</a> to identify where it is listed and contact the maintainer of that list to request its removal. Once the domain is removed from the upstream source, it will automatically disappear from Blackweb in the next update. You can also use the following script to perform the same verification:</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>Este proyecto incluye componentes de terceros.</li>
        <li>Los cambios deben proponerse mediante Issues. No se aceptan Pull Requests.</li>
        <li>BlackWeb está diseñado exclusivamente para <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a> y debido a la gran cantidad de dominios bloqueados no se recomienda usarlo en otros entornos (DNSMasq, Pi-Hole, etc.), o agregarlo al archivo Hosts de Windows, ya que podría ralentizarlo o bloquearlo. <b>Úselo bajo su propio riesgo</b>. Para más información revise el <a href="https://github.com/maravento/blackweb/issues/10#issuecomment-650834301" target="_blank">Issue 10</a></li>
        <li><b>Blackweb NO es un servicio de listas negras como tal</b>. No verifica de forma independiente los dominios. Su función es consolidar y formatear listas negras públicas para hacerlas compatibles con Squid.</li>
        <li>Si su dominio aparece en Blackweb y considera que esto es un error, debe revisar las fuentes públicas en <a href="#sources">SOURCES</a> para identificar en cuál(es) aparece, y contactar al responsable de dicha lista para solicitar su eliminación. Una vez que el dominio sea eliminado en la fuente original, desaparecerá automáticamente de Blackweb en la siguiente actualización. También puede usar el siguiente script para obtener el mismo resultado de verificación:</li>
      </ul>
    </td>
  </tr>
</table>

```bash
wget https://raw.githubusercontent.com/maravento/blackweb/refs/heads/master/bwupdate/tools/checksources.sh
chmod +x checksources.sh
./checksources.sh
```

e.g:

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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      We thank all those who have contributed to this project. Those interested can contribute, sending us links of new lists, to be included in this project.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Agradecemos a todos aquellos que han contribuido a este proyecto. Los interesados pueden contribuir, enviándonos enlaces de nuevas listas, para ser incluidas en este proyecto.
    </td>
  </tr>
</table>

Special thanks to: [Jhonatan Sneider](https://github.com/sney2002)

## SPONSOR THIS PROJECT

---

[![Image](https://raw.githubusercontent.com/maravento/winexternal/master/img/maravento-paypal.png)](https://paypal.me/maravento)

## PROJECT LICENSES

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      This project uses a dual-licensing model to balance software freedom with content protection:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Este proyecto utiliza un modelo de licencia dual para equilibrar la libertad del software con la protección del contenido:
    </td>
  </tr>
</table>

| Content | Licensed Under |
|---|---|
|Scripts, Binaries, Infrastructure|[![GPL-3.0](https://img.shields.io/badge/Open_Core-GPLv3-blue.svg?style=for-the-badge&labelWidth=120&logoWidth=20)](https://www.gnu.org/licenses/gpl.txt)|
|RAG, Workers, Specialized Modules, Docs|[![CC](https://img.shields.io/badge/Core_Engine-CC_BY--NC--ND_4.0-lightgrey.svg?style=for-the-badge&labelWidth=120&logoWidth=20)](https://creativecommons.org/licenses/by-nc-nd/4.0/)|

## DISCLAIMER

---

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## OBJECTION

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Due to recent arbitrary changes in computer terminology, it is necessary to clarify the meaning and connotation of the term <b>blacklist</b>, associated with this project:
      <br><br>
      <i>In computing, a blacklist, denylist or blocklist is a basic access control mechanism that allows through all elements (email addresses, users, passwords, URLs, IP addresses, domain names, file hashes, etc.), except those explicitly mentioned. Those items on the list are denied access. The opposite is a whitelist, which means only items on the list are let through whatever gate is being used.</i> Source <a href="https://en.wikipedia.org/wiki/Blacklist_(computing)" target="_blank">Wikipedia</a>
      <br><br>
      Therefore, <b>blacklist</b>, <b>blocklist</b>, <b>blackweb</b>, <b>blackip</b>, <b>whitelist</b> and similar, are terms that have nothing to do with racial discrimination.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Debido a los recientes cambios arbitrarios en la terminología informática, es necesario aclarar el significado y connotación del término <b>blacklist</b>, asociado a este proyecto:
      <br><br>
      <i>En informática, una lista negra, lista de denegación o lista de bloqueo es un mecanismo básico de control de acceso que permite a través de todos los elementos (direcciones de correo electrónico, usuarios, contraseñas, URL, direcciones IP, nombres de dominio, hashes de archivos, etc.), excepto los mencionados explícitamente. Esos elementos en la lista tienen acceso denegado. Lo opuesto es una lista blanca, lo que significa que solo los elementos de la lista pueden pasar por cualquier puerta que se esté utilizando.</i> Fuente <a href="https://en.wikipedia.org/wiki/Blacklist_(computing)" target="_blank">Wikipedia</a>
      <br><br>
      Por tanto, <b>blacklist</b>, <b>blocklist</b>, <b>blackweb</b>, <b>blackip</b>, <b>whitelist</b> y similares, son términos que no tienen ninguna relación con la discriminación racial.
    </td>
  </tr>
</table>
