<!--
BlackWeb documentation
FILE: README.md
-->
# [BlackWeb](https://www.maravento.com/p/blackweb.html)

[![status-maintained](https://img.shields.io/badge/status-maintained-purple.svg)](https://github.com/maravento/blackweb)
[![last commit](https://img.shields.io/github/last-commit/maravento/blackweb)](https://github.com/maravento/blackweb)
[![Stargazers](https://img.shields.io/github/stars/maravento/blackweb?label=Stargazers)](https://github.com/maravento/blackweb/stargazers)
[![Twitter Follow](https://img.shields.io/twitter/follow/maraventostudio.svg)](https://twitter.com/maraventostudio)

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <b>BlackWeb</b> brings together public domain blocklists and adapts them for use as access control lists (ACLs) in <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>. It includes domains related to adult content, downloads, drugs, malware, spyware, trackers, bots, social networks, warez, weapons, and other categories.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <b>BlackWeb</b> reúne listas públicas de dominios y las adapta para usarlas como listas de control de acceso (ACL) en <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>. Incluye dominios relacionados con contenido para adultos, descargas, drogas, malware, spyware, rastreadores, bots, redes sociales, warez y armas, entre otras categorías.
    </td>
  </tr>
</table>

<!-- markdownlint-disable MD033 -->

## REQUIREMENTS

---

- `squid` (or `squid-openssl`) to apply the BlackWeb rules

```bash
apt install -y squid
```

### Compatibility

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <code>bwupdate.sh</code> Only tested on Ubuntu 24.04/26.04 LTS. Other versions or distributions are not tested and are used at your own risk.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>bwupdate.sh</code> Solo probado en Ubuntu 24.04/26.04 LTS. Otras versiones o distribuciones no están probadas y se usan bajo tu responsabilidad.
    </td>
  </tr>
</table>

## DATA SHEET

---

| ACL | Blocked Domains | File Size |
| :---: | :---: | :---: |
| blackweb.txt | 7972530 | 194,3 MB |

## REPOSITORY STRUCTURE

---

```
bwupdate/
├── bwupdate.sh                  # Main script: downloads lists, builds blackweb.txt and reloads Squid
├── lst/                         # ACLs and helper lists used by bwupdate.sh
│   ├── ai.txt                      # Separate Squid ACL for AI-related domains; not modified by bwupdate.sh
│   ├── allowdomains.txt            # Separate Squid ACL for exempt domains; not modified by bwupdate.sh
│   ├── allowtlds.txt               # Allowed-TLD pattern used during debugging
│   ├── blockdomains.txt            # Separate Squid ACL for additional blocked domains; not modified by bwupdate.sh
│   ├── blocktlds.txt               # Separate Squid ACL for blocking whole TLDs; not modified by bwupdate.sh
│   ├── debugbl.txt                 # Added to the candidate blocklist before debugging
│   ├── debugwl.txt                 # Excludes false positives during debugging (Google, Hotmail, Yahoo, etc.)
│   ├── invalid.txt                 # Added to urls.txt during debugging, along with debugwl.txt
│   ├── pendingtld.txt              # Not read by scripts; maintainer reference
│   ├── streaming.txt               # Separate Squid ACL for streaming domains; not modified by bwupdate.sh
│   ├── tldsappx.txt                # TLD source used by dofi/domfilter.py
│   └── tldsbk.txt                  # Not read by scripts; maintainer reference
└── tools/
    ├── checksources.sh          # Downloads the source lists and searches them for a domain
    └── debugerror.py            # Removes domains flagged in Squid's cache.log when their parent domain is already blocked
```

## HOW TO USE

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      The archive includes <code>blackweb.txt</code>, prepared for use as a domain ACL in Squid. To use it, download the archive and save the file in a path Squid can access; then add the block rule shown below to the configuration.
    </td>
    <td style="width: 50%; vertical-align: top;">
      El archivo comprimido incluye <code>blackweb.txt</code>, preparado para usarse como ACL de dominios en Squid. Para aplicarlo, debe descargarse y guardarse en una ruta accesible para Squid; después, se añade a la configuración la regla de bloqueo que aparece abajo.
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

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Open:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Abra:
    </td>
  </tr>
</table>

```bash
/etc/squid/squid.conf
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Add the following lines at the indicated location:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Añada las siguientes líneas en el punto indicado:
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
      Add domains that should be exempt from blocking to <code>allowdomains.txt</code>, such as <code>.accounts.google.com</code>, <code>.yahoo.com</code> or <code>.github.com</code>. Place <code>http_access allow allowdomains</code> before the rules that deny access; otherwise, the exception may not take effect. <br>
      <br>
      According to <a href="http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube" target="_blank">Squid's documentation</a>, Google may use the subdomains <code>accounts.google.com</code> and <code>accounts.youtube.com</code> for authentication within its ecosystem. Blocking them could disrupt access to services such as Gmail, Drive and Docs.
    </td>
    <td style="width: 50%; vertical-align: top;">
      En <code>allowdomains.txt</code> se incluyen los dominios que deben excluirse del bloqueo, como <code>.accounts.google.com</code>, <code>.yahoo.com</code> o <code>.github.com</code>. La regla <code>http_access allow allowdomains</code> debe colocarse antes de las reglas que deniegan el acceso; de lo contrario, la excepción puede no surtir efecto. <br>
      <br>
      Según la <a href="http://wiki.squid-cache.org/ConfigExamples/Streams/YouTube" target="_blank">documentación de Squid</a>, Google puede utilizar los subdominios <code>accounts.google.com</code> y <code>accounts.youtube.com</code> para la autenticación dentro de su ecosistema. Bloquearlos podría interrumpir el acceso a servicios como Gmail, Drive y Docs.
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
      Use <code>blockdomains.txt</code> to list additional domains to block. This is a separate ACL; it does not automatically block every domain absent from <code>blackweb.txt</code>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>blockdomains.txt</code> contiene los dominios adicionales que se bloquearán mediante esa ACL. Es una lista independiente: no bloquea automáticamente todos los dominios que no aparezcan en <code>blackweb.txt</code>.
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
      Use <code>blocktlds.txt</code> to block entire top-level domains, such as gTLDs, sTLDs or ccTLDs.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>blocktlds.txt</code> contiene los TLD completos que se bloquearán, como gTLD, sTLD o ccTLD.
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
      This optional rule blocks domain names containing a Punycode label (<code>xn--</code>). It may reduce some homograph risks, but it can also block legitimate internationalized domains. Review and test the rule before enabling it. For background, see <a href="https://www.welivesecurity.com/2017/07/27/homograph-attacks-see-to-believe/" target="_blank">Welivesecurity: Homograph attacks</a>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Esta regla opcional bloquea dominios cuyo nombre contiene una etiqueta Punycode (<code>xn--</code>). Puede ayudar a reducir ciertos riesgos de ataques homográficos, pero también puede bloquear dominios internacionalizados legítimos. Conviene revisar y probar la regla antes de activarla. Para más información, puede consultarse <a href="https://www.welivesecurity.com/la-es/2017/07/13/ataques-homograficos/" target="_blank">Welivesecurity: Ataques homográficos</a>.
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
      This optional rule blocks URLs that match patterns in the file. It may produce false positives, so review the list before enabling the rule.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Esta regla opcional bloquea las URL que coincidan con los patrones del archivo. Puede generar falsos positivos; conviene revisar la lista antes de activarla.
    </td>
  </tr>
</table>

```bash
# Example: Download ACL:
sudo wget -P /etc/acl/squid https://raw.githubusercontent.com/maravento/vault/refs/heads/master/gateproxy/acl/squid/blockpatterns.txt
# Squid Rule to Block Patterns (change path):
acl blockpatterns url_regex -i "/etc/acl/squid/blockpatterns.txt"
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
      Use <code>streaming.txt</code> to block streaming domains not included in <code>blackweb.txt</code>, such as <code>.youtube.com</code>, <code>.googlevideo.com</code> or <code>.ytimg.com</code>. To allow them instead, use an <code>allow</code> rule in place of the example <code>deny</code> rule.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>streaming.txt</code> permite bloquear dominios de servicios de streaming que no estén en <code>blackweb.txt</code>, por ejemplo <code>.youtube.com</code>, <code>.googlevideo.com</code> o <code>.ytimg.com</code>. Para permitirlos, se puede configurar una regla <code>allow</code> en lugar de la regla <code>deny</code> del ejemplo.
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
      This list may contain overlapping domains. It is important to manually clean it according to the proposed objective. Example:
      <ul>
        <li>If your goal is to block Facebook, keep the primary domains and remove specific subdomains.</li>
        <li>If your goal is to block features, like Facebook streaming, keep the specific subdomains and remove the primary domains to avoid impacting overall site access. Example:</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      Esta lista puede contener dominios superpuestos. Conviene depurarla manualmente según el objetivo. Por ejemplo:
      <ul>
        <li>Para bloquear Facebook, se conservan los dominios principales y se eliminan los subdominios específicos.</li>
        <li>Para bloquear solo algunas funciones, como el streaming de Facebook, se conservan los subdominios específicos y se eliminan los dominios principales, a fin de no afectar el acceso general al sitio. Por ejemplo:</li>
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

##### AI (Optional)

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Use <code>ai.txt</code> to block domains related to artificial intelligence. To allow them instead, use an <code>allow</code> rule in place of the example <code>deny</code> rule.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>ai.txt</code> permite bloquear dominios relacionados con servicios de inteligencia artificial. Para permitirlos, se puede configurar una regla <code>allow</code> en lugar de la regla <code>deny</code> del ejemplo.
    </td>
  </tr>
</table>

```bash
acl ai dstdomain "/path_to/ai.txt"
http_access deny ai
```

#### Advanced Rules Summary

```bash
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS

# Allow Rule for Domains
# https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/allowdomains.txt
acl allowdomains dstdomain "/path_to/allowdomains.txt"
http_access allow allowdomains

# Block Rule for Punycode
acl punycode dstdom_regex -i \.xn--.*
http_access deny punycode

# Block Rule for gTLD, sTLD, ccTLD
# https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/blocktlds.txt
acl blocktlds dstdomain "/path_to/blocktlds.txt"
http_access deny blocktlds

# Block Rule for Domains
# https://raw.githubusercontent.com/maravento/blackweb/master/bwupdate/lst/blockdomains.txt
acl blockdomains dstdomain "/path_to/blockdomains.txt"
http_access deny blockdomains

# Block Rule for Patterns (Optional)
# https://raw.githubusercontent.com/maravento/vault/refs/heads/master/gateproxy/acl/squid/blockpatterns.txt
acl blockpatterns url_regex -i "/path_to/blockpatterns.txt"
http_access deny blockpatterns

# Block Rule for Blackweb
# https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz
acl blackweb dstdomain "/path_to/blackweb.txt"
http_access deny blackweb
```

## BLACKWEB UPDATE

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      This section describes how <code>bwupdate.sh</code> updates and processes the list. Running the script is not required to use the published <code>blackweb.txt</code>. Updates can take time and use substantial CPU, memory, network and bandwidth resources; run the process on a test system.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Esta sección describe el proceso que sigue <code>bwupdate.sh</code> para actualizar y depurar la lista. No es necesario ejecutar este script para usar el archivo <code>blackweb.txt</code> publicado. La actualización puede tardar y consumir muchos recursos de CPU, memoria, red y ancho de banda; se recomienda ejecutarla en un equipo de pruebas.
    </td>
  </tr>

</table>

### Dependencies (for `bwupdate.sh`)

- Python 3.x, Bash 5.x
- `wget`, `curl`, `tar`, `gzip`, `idn2`, `squid` (or `squid-openssl`), `python3`, `bind9-host`, `findutils`, `grep`, `sed`, `coreutils`, `util-linux`, `file`, `libc-bin`, `sudo`
- Python module: `requests` (required by `domfilter.py`)

```bash
apt install -y wget curl tar gzip idn2 squid python3 bind9-host findutils grep sed coreutils python3-requests util-linux file libc-bin sudo
```

#### Bash Update

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <code>bwupdate.sh</code> runs the steps needed to generate and update <code>blackweb.txt</code> in sequence. The script requests elevated privileges when an operation requires them.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>bwupdate.sh</code> ejecuta en secuencia los pasos necesarios para generar y actualizar <code>blackweb.txt</code>. Cuando una operación requiere privilegios, el script los solicita.
    </td>
  </tr>
</table>

```bash
git clone --depth=1 https://github.com/maravento/blackweb.git && cd blackweb/bwupdate && ./bwupdate.sh
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Before continuing, check that Squid is installed and its service is running.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Antes de continuar, conviene comprobar que Squid esté instalado y que el servicio funcione.
    </td>
  </tr>
</table>

#### Capture Public Blocklists

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Downloads the public blocklists listed under <b>SOURCES</b>, extracts their domains and combines them for further processing.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Descarga las listas públicas indicadas en <b>SOURCES</b>, extrae sus dominios y los reúne para continuar con la depuración.
    </td>
  </tr>
</table>

#### Domains Debugging

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Removes redundant domains when a broader entry already covers them, normalizes entries for Squid ACLs, and applies <code>debugwl.txt</code> to retain domains that should not be blocked.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina dominios redundantes cuando uno ya queda cubierto por otro más general, normaliza las entradas al formato de ACL de Squid y aplica la lista <code>debugwl.txt</code> para conservar dominios que deben excluirse del bloqueo.
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
      Removes domains whose suffix is not in the configured list of valid TLDs. The list covers different levels of public and private suffixes, including domains with up to four labels.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina los dominios cuyo sufijo no figura entre los TLD válidos de las fuentes configuradas. La lista contempla distintos niveles de sufijos públicos y privados, incluidos dominios de hasta cuatro etiquetas.
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
      Removes domain names that exceed length limits or contain unsupported characters, as defined by <a href="https://www.ietf.org/rfc/rfc1035.txt" target="_blank">RFC 1035</a> and the <a href="http://www.gnu.org/s/libidn/manual/html_node/Invoking-idn.html" target="_blank">IDN</a> tools. <br>
      <br>
      It also converts domains containing non-ASCII characters to <a href="https://www.charset.org/punycode" target="_blank">Punycode/IDNA</a> so they can be validated and processed as ASCII names.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina nombres de dominio que exceden los límites de longitud o contienen caracteres no admitidos. <br>
      <br>
      También convierte los dominios con caracteres no ASCII a formato <a href="https://www.charset.org/punycode" target="_blank">Punycode/IDNA</a>, para que puedan validarse y procesarse como nombres ASCII. Esta conversión no significa que todos esos dominios se usen para ataques homográficos.
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
      Removes entries with invalid encoding, non-printable characters, whitespace or unsupported symbols. It then converts the output to ASCII text for further domain validation and processing:
    </td>
    <td style="width: 50%; vertical-align: top;">
      Elimina entradas con codificación inválida, caracteres no imprimibles, espacios o símbolos no admitidos. Después convierte la salida a texto ASCII para continuar con la validación y el procesamiento de los dominios:
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
      Many <b>SOURCES</b> contain invalid or nonexistent domains, so DNS queries run in two stages to discard domains that do not resolve. The queries run in parallel and can use substantial CPU and bandwidth. The <code>parallel_procs</code> variable controls concurrency:
    </td>
    <td style="width: 50%; vertical-align: top;">
      El proceso comprueba los dominios mediante consultas DNS en dos etapas para descartar los que no resuelven. Las consultas se ejecutan en paralelo y pueden consumir bastante CPU y ancho de banda. <code>parallel_procs</code> permite ajustar la cantidad de consultas simultáneas según los recursos del equipo y la red:
    </td>
  </tr>
</table>

```bash
parallel_procs=$(($(nproc)))        # Conservative (network-friendly)
parallel_procs=$(($(nproc) * 2))    # Balanced
parallel_procs=$(($(nproc) * 4))    # Aggressive (default)
parallel_procs=$(($(nproc) * 8))    # Extreme (8 or higher, use with caution)
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      For example, on a system with a Core i5 CPU (4 physical cores and 8 threads with Hyper-Threading):
    </td>
    <td style="width: 50%; vertical-align: top;">
      Por ejemplo, en un equipo con CPU Core i5, cuatro núcleos físicos y ocho subprocesos con Hyper-Threading:
    </td>
  </tr>
</table>

```bash
nproc             → 8
parallel_procs=$((8 * 4))  → 32 parallel queries
```

> **⚠️ WARNING -- DNS query parallelism:** Higher `parallel_procs` values can speed up DNS resolution, but may saturate CPU or bandwidth, especially on constrained networks such as satellite links. The following shows an example of the live progress output:
>
> **⚠️ WARNING -- DNS query parallelism:** Los valores altos de `parallel_procs` pueden acelerar la resolución DNS, pero también saturar la CPU o el ancho de banda, especialmente en redes limitadas como los enlaces satelitales. El siguiente ejemplo muestra el progreso durante la ejecución:

```bash
Processed: 2463489 / 7244989 (34.00%)
```

Output (manual run):

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
      When Squid runs with BlackWeb, errors are written to <code>SquidErrors.txt</code>.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Al ejecutar Squid-Cache con BlackWeb, los errores se escriben en <code>SquidErrors.txt</code>.
    </td>
  </tr>
</table>

#### Log

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Both <code>bwupdate.sh</code> and <code>checksources.sh</code> write a log file (<code>bwupdate.log</code> or <code>checksources.log</code>) in the directory containing the script.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>bwupdate.sh</code> y <code>checksources.sh</code> escriben un archivo de registro (<code>bwupdate.log</code> o <code>checksources.log</code>) en el directorio donde se encuentra cada script.
    </td>
  </tr>
</table>

> Processing messages keep their timestamp and have no level or flag. `STATUS` is a viewer label, not text written in the log. Three trailing dots are reserved for these lines; other messages have no final period.
>
> Los mensajes de procesamiento conservan la fecha y no llevan nivel ni flag. `STATUS` es una etiqueta del visor; no se escribe en el log. Los tres puntos finales se reservan para estas líneas; los demás mensajes no llevan punto final.

```text
2026-10-17 12:00:00 Joining Lists...
2026-10-17 12:00:00 Debugging Domains...
```

#### Download Status

| Tag | Shows | Description | Descripción |
|---|---|---|---|
| `SAVED:` | File name | The transfer completed and the file was written | La descarga terminó y el archivo se guardó |
| `PARTIAL:` | Full URL | The download started and was cut off before finishing | La descarga comenzó y se interrumpió antes de terminar |
| `BUSY:` | Full URL | The server answered 5xx: it is up but not serving the list right now | El servidor respondió con un error 5xx: está disponible, pero no entrega la lista en ese momento |
| `TIMEOUT:` | Full URL | The server did not answer at all | El servidor no respondió |
| `BROKEN:` | Full URL | The server answered 404 or 410: broken or nonexistent URL | El servidor respondió 404 o 410: el recurso no existe o la URL ya no es válida |
| `HTTP_ERROR:` | HTTP code and full URL | The server returned an HTTP response not covered by the other tags | El servidor devolvió una respuesta HTTP no contemplada por las otras etiquetas |

#### Important about BlackWeb Update

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>The default path of BlackWeb is <code>/etc/acl</code>. You can change it for your preference.</li>
        <li>If you need to interrupt the execution of <code>bwupdate.sh</code> (ctrl + c) and it stopped at the <b>DNS Lookup</b> part, it will restart at that point. If you stop it earlier, you will have to start from the beginning or modify the script manually so that it starts from the desired point.</li>
        <li>If you use <code>aufs</code>, temporarily change it to <code>ufs</code> during the upgrade, to avoid: <code>ERROR: Can't change type of existing cache_dir aufs /var/spool/squid to ufs. Restart required</code>.</li>
        <li><code>bwupdate.sh</code> uses <code>--no-check-certificate</code> (wget) and <code>-k</code> (curl) because some public blocklist sources have certificate issues. This allows download attempts but weakens verification of the server's identity; keep this in mind when changing or reviewing sources.</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>La ruta predeterminada para instalar la ACL es <code>/etc/acl</code>; puede cambiarse en <code>bwupdate.sh</code>.</li>
        <li>Si el script se interrumpe durante la etapa <b>DNS Lookup</b>, al volver a ejecutarlo continuará desde esa etapa. Si se interrumpe antes, será necesario iniciarlo de nuevo o modificarlo para reanudar desde otro punto.</li>
        <li>Si se usa <code>aufs</code>, debe cambiarse temporalmente a <code>ufs</code> durante la actualización para evitar: <code>ERROR: Can't change type of existing cache_dir aufs /var/spool/squid to ufs. Restart required</code>.</li>
        <li><code>bwupdate.sh</code> desactiva la verificación estricta de certificados porque algunas fuentes públicas tienen problemas con ellos. Esto permite intentar la descarga, pero reduce la verificación de la identidad del servidor; conviene tenerlo en cuenta al modificar o revisar las fuentes.</li>
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
- [hagezi - dns-blocklists](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt)
- [hexxium - threat-list/](https://hexxiumcreations.github.io/threat-list/hexxiumthreatlist.txt)
- [hoshsadiq - adblock-nocoin-list](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt)
- [jawz101 - potentialTrackers](https://raw.githubusercontent.com/jawz101/potentialTrackers/master/potentialTrackers.csv)
- [jdlingyu - ad-wars](https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts)
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
- [ShadowWhisperer - Adult](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Adult)
- [ShadowWhisperer - Cryptocurrency](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Cryptocurrency)
- [ShadowWhisperer - Dating](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Dating)
- [ShadowWhisperer - Gambling](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Gambling)
- [ShadowWhisperer - Malware](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Malware)
- [ShadowWhisperer - Risk](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Risk)
- [ShadowWhisperer - Scam](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Scam)
- [ShadowWhisperer - Shock](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Shock)
- [ShadowWhisperer - Tracking](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Tracking)
- [ShadowWhisperer - Typo](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Typo)
- [ShadowWhisperer - UrlShortener](https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/UrlShortener)
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
- [tomasko126 - Easylist Czech and Slovak filter list](https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt)
- [txthinking - blackwhite](https://raw.githubusercontent.com/txthinking/blackwhite/master/black.list)
- [txthinking - bypass china domains](https://raw.githubusercontent.com/txthinking/bypass/master/china_domain.txt)
- [Ultimate Hosts Blacklist - hosts](https://github.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/tree/master/hosts)
- [Université Toulouse 1 Capitole - Blacklists UT1 - Olbat](https://github.com/olbat/ut1-blacklists/tree/master/blacklists)
- [Université Toulouse 1 Capitole - Blacklists UT1](https://dsi.ut-capitole.fr/blacklists/index_en.php)
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
- [whoisxmlapi](https://www.whoisxmlapi.com/support/supported_tlds.php?ts=gp)

## SUBPROJECTS

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      BlackWeb's core is the domain and TLD blocklist (<code>blackweb.txt</code> and <code>bwupdate.sh</code>). It also includes related projects, each with its own tools and update process.
    </td>
    <td style="width: 50%; vertical-align: top;">
      El núcleo de BlackWeb es la lista de bloqueo de dominios y TLD (<code>blackweb.txt</code> y <code>bwupdate.sh</code>). También incluye proyectos relacionados, cada uno con sus propias herramientas y proceso de actualización.
    </td>
  </tr>
</table>

### Filter Pack (fpack)

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <code>fpack/</code> contains optional ACLs outside BlackWeb's core flow; <code>bwupdate.sh</code> does not process them. To generate the ACLs, download the lists and run <code>fpack.sh</code>, then apply the Squid rules shown below. They cover ransomware-related file extensions, malicious User-Agents and static web3 lists. <code>fpack.sh</code> generates the first two; the web3 lists are maintained manually and are not modified by the script.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>fpack/</code> contiene ACL opcionales, ajenas al flujo principal de BlackWeb; <code>bwupdate.sh</code> no las procesa. Para generarlas, se descargan las listas y se ejecuta <code>fpack.sh</code>; después, se aplican las reglas de Squid que aparecen abajo. Incluyen extensiones de archivo relacionadas con ransomware, User-Agents maliciosos y listas web3 estáticas. <code>fpack.sh</code> genera las dos primeras; las listas web3 se mantienen manualmente y el script no las modifica.
    </td>
  </tr>
</table>

```
fpack/
├── fpack.sh              # generates rw/rwext.txt and ua/blockua.txt
├── rw/
│   ├── rw.txt               # administrator ransomware blacklist (source)
│   ├── rwext.txt            # Squid url_regex ACL (generated)
│   └── wl.txt               # administrator ransomware whitelist (source)
├── ua/
│   └── blockua.txt          # Squid browser ACL for bad User-Agents (generated)
└── web3/
    ├── web3domains.txt      # Squid dstdomain ACL, web3/wallet domains (static)
    └── web3tld.txt          # Squid dstdomain ACL, web3/wallet TLDs (static)
```

#### Requirements

- `wget`, `curl`, `grep`, `sed`, `coreutils`, `util-linux`, `libc-bin`

```bash
apt install -y wget curl grep sed coreutils util-linux libc-bin
```

#### Download

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Either clone the whole BlackWeb repo, or download just the <code>fpack/</code> folder with <code>gitfolder.py</code> (same tool vault subprojects use):
    </td>
    <td style="width: 50%; vertical-align: top;">
      Clone todo el repo de BlackWeb, o descargue solo la carpeta <code>fpack/</code> con <code>gitfolder.py</code> (la misma herramienta que usan los subproyectos de vault):
    </td>
  </tr>
</table>

```bash
# Option 1: full clone
git clone --depth=1 https://github.com/maravento/blackweb.git
cd blackweb/fpack

# Option 2: folder-only download
wget -qO gitfolder.py https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolder.py
chmod +x gitfolder.py
python3 gitfolder.py https://github.com/maravento/blackweb/fpack
cd fpack
```

#### Run

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <code>fpack.sh</code> only produces Squid ACLs. Run it manually, as a non-root user — it is not scheduled by any installer:
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>fpack.sh</code> solo produce ACLs para Squid. Se ejecuta manualmente, como usuario no root — ningún instalador la programa:
    </td>
  </tr>
</table>

```bash
bash fpack.sh
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Log: <code>fpack.log</code>, generated in <code>fpack/</code>, emptied at the start of every run.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Log: <code>fpack.log</code>, generado en <code>fpack/</code>, vaciado al inicio de cada ejecución.
    </td>
  </tr>
</table>

#### How It Works

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <code>fpack.sh</code> downloads and normalizes the User-Agent list into <code>ua/blockua.txt</code>. It then downloads several ransomware extension/pattern lists, merges them with the administrator list (<code>rw/rw.txt</code>), normalizes extension forms (<code>ext</code>, <code>.ext</code> and <code>*ext</code> become <code>*.ext</code>, while <code>_ext</code> and <code>-ext</code> keep their prefix and become <code>*._ext</code> and <code>*.-ext</code>), and keeps only simple <code>*.ext</code> patterns. It removes entries listed in the administrator whitelist (<code>rw/wl.txt</code>) and discards ransom-note-style or implausibly long extensions. The result is written as a Squid <code>url_regex</code> ACL, <code>rw/rwext.txt</code>, with regex metacharacters escaped so they match literally.
    </td>
    <td style="width: 50%; vertical-align: top;">
      <code>fpack.sh</code> descarga y normaliza la lista de User-Agents en <code>ua/blockua.txt</code>. Luego descarga varias listas de extensiones/patrones de ransomware, las combina con la lista del administrador (<code>rw/rw.txt</code>), normaliza las formas de extensión (<code>ext</code>, <code>.ext</code> y <code>*ext</code> pasan a <code>*.ext</code>, mientras <code>_ext</code> y <code>-ext</code> conservan su prefijo y pasan a <code>*._ext</code> y <code>*.-ext</code>) y conserva solo patrones simples <code>*.ext</code>. Elimina las entradas de la lista blanca del administrador (<code>rw/wl.txt</code>) y descarta extensiones tipo nota-de-rescate o implausiblemente largas. El resultado se escribe como ACL <code>url_regex</code> de Squid, <code>rw/rwext.txt</code>, con los metacaracteres de regex escapados para que coincidan como texto literal.
    </td>
  </tr>
</table>

> `rw/wl.txt` excludes entries by exact match, format `*.ext`, one per line. Do not add `*.zip` or `*.rar`: they are common legitimate ransomware suffixes (e.g. `*.bart.zip`) and would be discarded if whitelisted.
>
> `rw/wl.txt` excluye entradas por coincidencia exacta, formato `*.ext`, una por línea. No agregue `*.zip` ni `*.rar`: son sufijos legítimos comunes de ransomware (ej. `*.bart.zip`) y se descartarían si se agregan a la lista blanca.

#### Squid Rules

```bash
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS

# Block Rule for Ransomware Extensions/Patterns (Optional)
# https://raw.githubusercontent.com/maravento/blackweb/master/fpack/rw/rwext.txt
acl block_ransomware url_regex -i "/path_to/rwext.txt"
http_access deny block_ransomware

# Block Rule for web3 domains (Optional)
# https://raw.githubusercontent.com/maravento/blackweb/master/fpack/web3/web3domains.txt
acl web3domains dstdomain "/path_to/web3domains.txt"
http_access deny web3domains

# Block Rule for web3 TLDs (Optional)
# https://raw.githubusercontent.com/maravento/blackweb/master/fpack/web3/web3tld.txt
acl web3tld dstdomain "/path_to/web3tld.txt"
http_access deny web3tld

# Block Rule for User-Agents (Optional)
# https://raw.githubusercontent.com/maravento/blackweb/master/fpack/ua/blockua.txt
acl bad_useragents browser -i "/path_to/blockua.txt"
http_access deny bad_useragents
```

---

### Domain Filtering (DoFi)

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Domain Filtering (DoFi) removes redundant domains, validates their suffixes, and can check DNS resolution. <code>bwupdate.sh</code> uses <code>domfilter.py</code> during updates and stops if that step fails. DoFi can also be used independently to process other domain lists:
    </td>
    <td style="width: 50%; vertical-align: top;">
      DoFi (Domain Filtering) elimina dominios redundantes, valida sus sufijos y puede comprobar su resolución DNS. <code>bwupdate.sh</code> usa <code>domfilter.py</code> durante la actualización y se detiene si esa etapa falla. DoFi también puede emplearse por separado para procesar otras listas:
    </td>
  </tr>
</table>

```bash
python3 domfilter.py --input mylst.txt
```

```
dofi/
├── domcheck.sh          # Checks domain existence with the host command
└── domfilter.py         # Removes overlapping domains, validates TLDs
```

#### Requirements

- Python 3.12.3, Bash 5.2.21
- `python3-requests` (required by `domfilter.py`), `bind9-host`, `findutils`, `grep`, `sed`, `coreutils`, `util-linux` (required by `domcheck.sh`)

```bash
apt install -y python3 python3-requests bind9-host findutils grep sed coreutils util-linux
```

#### Download

```bash
# Option 1: full clone
git clone --depth=1 https://github.com/maravento/blackweb.git
cd blackweb/dofi

# Option 2: folder-only download
wget -qO gitfolder.py https://raw.githubusercontent.com/maravento/vault/master/scripts/python/gitfolder.py
chmod +x gitfolder.py
python3 gitfolder.py https://github.com/maravento/blackweb/dofi
cd dofi
```

#### Domain Filter

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Before running the filter, remove <code>http://</code>, <code>https://</code> and <code>www.</code> prefixes from the input list. The script:<br>
      - Downloads public suffix lists from multiple sources.<br>
      - Removes invalid or duplicate TLDs.<br>
      - Filters domains against the valid suffix list.<br>
      - Removes overlapping domains.<br>
      - Excludes duplicates from previously processed domains.<br>
      - Writes the results to a file.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Antes de ejecutar el filtro, deben quitarse de la lista los prefijos <code>http://</code>, <code>https://</code> y <code>www.</code>. El script:<br>
      - Descarga listas de sufijos públicos de varias fuentes.<br>
      - Elimina TLD no válidos o duplicados.<br>
      - Filtra dominios según la lista de sufijos válidos.<br>
      - Elimina dominios superpuestos.<br>
      - Excluye dominios duplicados ya procesados.<br>
      - Guarda los resultados en un archivo.
    </td>
  </tr>
</table>

```bash
python3 domfilter.py --input mylst.txt
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      In the command, replace <code>mylst.txt</code> with the input filename. By default, results go to <code>output.txt</code> and removed lines to <code>removed.txt</code>; these paths can be changed with the following options:
    </td>
    <td style="width: 50%; vertical-align: top;">
      En el comando, <code>mylst.txt</code> debe sustituirse por el nombre del archivo de entrada. De forma predeterminada, el resultado se guarda en <code>output.txt</code> y las líneas descartadas en <code>removed.txt</code>; esas rutas pueden cambiarse con las opciones siguientes:
    </td>
  </tr>
</table>

```bash
python3 domfilter.py --input mylst.txt --output outlst.txt --removed removelst.txt
```

> The `tlds.txt` list includes ccTLDs, gTLDs, sTLDs, eTLDs, and domains of up to four labels.
>
> La lista `tlds.txt` incluye ccTLD, gTLD, sTLD, eTLD y dominios de hasta cuatro etiquetas.

#### Domains Check with Host Command

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      The script queries each domain with the <code>host</code> command and separates results into two files:<br>
      - <code>hit.txt</code>: domains that resolved.<br>
      - <code>fault.txt</code>: domains that did not resolve.
    </td>
    <td style="width: 50%; vertical-align: top;">
      El script consulta cada dominio con el comando <code>host</code> y separa los resultados en dos archivos:<br>
      - <code>hit.txt</code>: dominios que resolvieron.<br>
      - <code>fault.txt</code>: dominios que no pudieron resolverse.
    </td>
  </tr>
</table>

> Before running the script, remove `http://`, `https://`, and `www.` prefixes from the input list.
>
> Antes de ejecutar el script, quite de la lista los prefijos `http://`, `https://` y `www.`.

```bash
chmod +x domcheck.sh
bash domcheck.sh my_domain_list.txt
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      In the command, replace <code>my_domain_list.txt</code> with the input filename. The optional second argument sets the number of parallel processes (default: <code>nproc × 4</code>, capped at <code>200</code>):
    </td>
    <td style="width: 50%; vertical-align: top;">
      En el comando, <code>my_domain_list.txt</code> debe sustituirse por el nombre del archivo de entrada. El segundo argumento, opcional, indica la cantidad de procesos paralelos (por defecto: <code>nproc × 4</code>, con tope de <code>200</code>):
    </td>
  </tr>
</table>

```bash
bash domcheck.sh my_domain_list.txt 50
```

```text
2026-07-07 13:29:58 domcheck start...
2026-07-07 13:29:58 Step 1...
2026-07-07 13:30:17 Step 2...
2026-07-07 13:30:28 INFO: hit.txt: domains successfully resolved
2026-07-07 13:30:28 INFO: fault.txt: unresolved domains
2026-07-07 13:30:28 INFO: Summary:
2026-07-07 13:30:28 INFO: Input domains : 7896
2026-07-07 13:30:28 INFO: Resolved      : 7349
2026-07-07 13:30:28 INFO: Unresolved    : 547
2026-07-07 13:30:28 INFO: Elapsed time  : 30s
2026-07-07 13:30:29 domcheck done
```

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      Log: <code>dofi.log</code>, generated in <code>dofi/</code>, emptied at the start of every run.
    </td>
    <td style="width: 50%; vertical-align: top;">
      Log: <code>dofi.log</code>, generado en <code>dofi/</code>, vaciado al inicio de cada ejecución.
    </td>
  </tr>
</table>

#### Sources

- [tlds-alpha-by-domain](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
- [tldsappx](https://github.com/maravento/blackweb/blob/master/bwupdate/lst/tldsappx.txt)
- [public_suffix_list](https://github.com/publicsuffix/list/blob/master/public_suffix_list.dat)
- [supported_gtlds](https://www.whoisxmlapi.com/support/supported_tlds.php?ts=gp)

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
      <strong>This repository</strong>
      <ul>
        <li>May include third-party components.</li>
        <li>Does not accept Pull Requests. Changes must be proposed via Issues.</li>
        <li>This project does not support backward compatibility. New versions may require configuration changes or reinstallation.</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      <strong>Este repositorio</strong>
      <ul>
        <li>Puede incluir componentes de terceros.</li>
        <li>No acepta Pull Requests. Los cambios deben proponerse mediante Issues.</li>
        <li>Este proyecto no soporta retrocompatibilidad. Las nuevas versiones pueden requerir cambios de configuración o una reinstalación.</li>
      </ul>
    </td>
  </tr>
</table>

## LIMITATIONS

---

<table width="100%">
  <tr>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>BlackWeb is designed exclusively for <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>. Because of the large number of blocked domains, it is not recommended in other environments, such as DNSMasq or Pi-Hole, nor in the Windows Hosts file, since it could slow them down or crash them. <b>Use it at your own risk</b>. For more information see <a href="https://github.com/maravento/blackweb/issues/10#issuecomment-650834301" target="_blank">Issue 10</a>.</li>
        <li><b>Blackweb is NOT a blacklist service itself</b>. It does not independently verify domains. Its purpose is to consolidate and reformat public blacklist sources to make them compatible with Squid.</li>
        <li>If your domain appears in Blackweb and you believe this is an error, review the public sources in <b>SOURCES</b> to identify which list includes it, and contact the maintainer of that list to request its removal. Once the domain is removed from the upstream source, it disappears from Blackweb on the next update. You can also use the following script to perform the same check:</li>
      </ul>
    </td>
    <td style="width: 50%; vertical-align: top;">
      <ul>
        <li>BlackWeb está diseñado exclusivamente para <a href="http://www.squid-cache.org/" target="_blank">Squid-Cache</a>. Debido a la gran cantidad de dominios bloqueados, no se recomienda usarlo en otros entornos, como DNSMasq o Pi-Hole, ni en el archivo Hosts de Windows, ya que podría ralentizarlos o bloquearlos. <b>Úselo bajo su propio riesgo</b>. Para más información revise el <a href="https://github.com/maravento/blackweb/issues/10#issuecomment-650834301" target="_blank">Issue 10</a>.</li>
        <li><b>Blackweb NO es un servicio de listas negras como tal</b>. No verifica de forma independiente los dominios. Su función es consolidar y formatear listas negras públicas para hacerlas compatibles con Squid.</li>
        <li>Si su dominio aparece en Blackweb y considera que es un error, revise las fuentes públicas en <b>SOURCES</b> para identificar en cuál lista aparece, y contacte al responsable de esa lista para solicitar su eliminación. Una vez eliminado en la fuente original, el dominio desaparece de Blackweb en la siguiente actualización. También puede usar el siguiente script para hacer la misma comprobación:</li>
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
[+] Domain found in: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
[+] Domain found in: https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts/hosts0
[+] Domain found in: https://sysctl.org/cameleon/hosts
[+] Domain found in: https://v.firebog.net/hosts/Kowabit.txt
Done
```

## ACKNOWLEDGMENTS

---

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
|Scripts, Binaries, Infrastructure|[![GPL-3.0](https://img.shields.io/badge/Open_Core-GPLv3-blue.svg?style=for-the-badge&labelWidth=120&logoWidth=20)](LICENSE)|
|RAG, Workers, Specialized Modules, Docs|[![CC](https://img.shields.io/badge/Core_Engine-CC_BY--NC--ND_4.0-lightgrey.svg?style=for-the-badge&labelWidth=120&logoWidth=20)](docs/LICENSE-CC-BY-NC-ND-4.0.md)|

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
