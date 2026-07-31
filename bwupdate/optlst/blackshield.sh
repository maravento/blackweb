#!/bin/bash
# maravento.com
#
################################################################################
#
# BlackShield (optlst)
# File Extensions/Patterns/User-Agents to Block
#
# OVERVIEW
# This script builds a Squid ACL for ransomware-related file
# extensions/patterns and another for malicious User-Agent strings, by
# downloading and aggregating several public source lists and then
# filtering out entries that are not safe or meaningful as extension
# patterns.
#
# DIRECTORY LAYOUT
# - rw/    : administrator-maintained ransomware source lists (read-only
#            inputs to this script; never written by it).
# - ua/    : final Squid User-Agent ACL this script produces/updates.
# - web3/  : static web3 domain/TLD lists, not touched by this script.
#
# PIPELINE (in order)
# 1. Download bad User-Agent list -> normalize -> append to
#    ua/blockua.txt (deduplicated).
# 2. Download multiple ransomware extension/pattern lists -> concatenate
#    into a temporary source list.
# 3. Normalize: keep ASCII-only lines, trim whitespace, drop empty lines,
#    sort/dedupe.
# 4. Normalize extension forms: "ext", ".ext", "_ext", "-ext", "*ext" all
#    become "*.ext" so equivalent notations are treated the same.
# 5. Filter to simple "*.ext" patterns only (single leading wildcard, no
#    internal wildcards/whitespace). Anything else (bare filenames,
#    multi-pattern lines separated by "/", lines with embedded spaces,
#    [ID]/[KEY] placeholders, or entries containing unsafe regex/glob
#    metacharacters [ ] @ { } ( ) ? ^) is discarded (the on-screen count
#    is the lasting record).
# 6. Apply rw/wl.txt as an exact-match administrator whitelist (entries
#    removed verbatim).
# 7. Discard ransom-note-style entries: anything ending in a whitelisted
#    document extension (*.ext) or an extra segment plus a whitelisted
#    extension (*.algo.ext), e.g. "*.DATA_RECOVERY.html", "*.README.txt".
# 8. Discard entries whose extension segment is implausibly long (>35
#    chars), which are typically ransom note filenames or attacker IDs
#    rather than real encryption extensions, e.g.
#    "*.NEED_TO_MAKE_THE_PAYMENT_IN_MAXIM_24_HOURS...".
# 9. Generate rw/rwext.txt: a Squid url_regex ACL derived from the
#    filtered list. Regex metacharacters that can appear literally inside
#    an entry (e.g. the "." in "*.bart.zip", or a literal "$") are
#    escaped, so they match as literal characters instead of being
#    interpreted as "any character" or an anchor.
#
# NOTE on rw/rw.txt:
# - Administrator-maintained ransomware extensions/patterns.
# - Merged into the downloaded source lists before normalization.
# - Subject to the same validation, whitelist and filtering rules as all
#   downloaded sources.
#
# NOTE on rw/wl.txt:
# - One pattern per line, format "*.ext".
# - Entries are excluded by exact match (administrator override, step 6).
# - Entries are also used in step 7 to detect and discard ransom-note-style
#   entries ending in a whitelisted extension, e.g. "*.DATA_RECOVERY.html",
#   "*.README.txt".
# - Do NOT add "*.zip" or "*.rar": these are common legitimate ransomware
#   suffixes (e.g. "*.bart.zip", "*.locked.zip") and would be discarded
#   in step 7 if whitelisted here.
#
# NOTE on logging:
# - Writes to blackshield.log (append-only, no rotation configured
#   by this script). Set up logrotate for this file if disk usage matters.
# - To clear it manually: truncate -s 0 blackshield.log
#
################################################################################

set -uo pipefail

# logging
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$SCRIPT_DIR/blackshield.log"
log() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" | tee -a "$log_file" 2>/dev/null || true
}

# check no-root
if [ "$(id -u)" == "0" ]; then
    log "[ERROR] This script should not be run as root."
    exit 1
fi

# prevent overlapping runs
SCRIPT_LOCK="/var/lock/$(basename "$0" .sh).lock"
exec 200>"$SCRIPT_LOCK"
if ! flock -n 200; then
    log "[ERROR] Script $(basename "$0") is already running"
    exit 1
fi

# DEPENDENCIES
for dep in wget grep sed gawk coreutils util-linux; do
    if ! dpkg -s "$dep" &>/dev/null; then
        log "[ERROR] Required dependency '$dep' is not installed."
        exit 1
    fi
done

# Start
log "blackshield start..."

### VARIABLES
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SRC_DIR="rw"
UA_DIR="ua"

TMP_DIR=$(mktemp -d)
trap '[ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"' EXIT

# Unique scratch file per run/invocation, so overlapping executions (e.g.
# cron overlap) never write to the same intermediate path.
TMP_FILE=$(mktemp "${TMP_DIR}/output_lst.XXXXXX")

wgetd='wget -q -c --retry-connrefused --timeout=10 --tries=4'

# Bad User-Agents
if $wgetd -O "${TMP_DIR}/bad-user-agents.list" "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"; then
    sed -E 's/\\//g; s#/#-#g' "${TMP_DIR}/bad-user-agents.list" >> "${UA_DIR}/blockua.txt"
    sort -o "${UA_DIR}/blockua.txt" -u "${UA_DIR}/blockua.txt"
    log "Bad User-Agents for Squid: blockua.txt"
else
    log "ERROR: failed to download bad-user-agents.list"
fi

: > "${TMP_DIR}/source_lst.txt"

# Ransomware
function rw() {
    if $wgetd "$1" -O - >> "${TMP_DIR}/source_lst.txt"; then
        return 0
    else
        log "ERROR: $1"
        return 1
    fi
}
rw 'https://raw.githubusercontent.com/dannyroemhild/ransomware-fileext-list/refs/heads/master/fileextlist.txt' && sleep 1 || true
rw 'https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/refs/heads/main/ransomware-extension-list.txt' && sleep 1 || true
rw 'https://raw.githubusercontent.com/giacomoarru/ransomware-extensions-2024/refs/heads/main/ransomware-extensions.txt' && sleep 1 || true
#rw 'https://raw.githubusercontent.com/kinomakino/ransomware_file_extensions/master/extensions.csv' && sleep 1 || true
rw 'https://raw.githubusercontent.com/nspoab/malicious_extensions/refs/heads/main/list1' && sleep 1 || true

if [ -s "${SRC_DIR}/rw.txt" ]; then
    cat "${SRC_DIR}/rw.txt" >> "${TMP_DIR}/source_lst.txt"
fi

# Normalize raw entries: keep only ASCII, trim whitespace, drop empty lines
LC_ALL=C grep -v '[^[:print:][:space:]]' "${TMP_DIR}/source_lst.txt" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//' | sed '/^$/d' | sort -u > "${TMP_DIR}/normalized_lst.txt"

# Treat "ext", ".ext", "_ext", "-ext", "*ext" and "*.ext" as the same idea:
# normalize all to "*.ext"
# - "ext"   (bare alnum start, no dot/asterisk) -> "*.ext"
# - ".ext"  (leading dot, no asterisk)          -> "*.ext"
# - "_ext"/"-ext" (leading underscore/hyphen)   -> "*._ext" / "*.-ext"
# - "*ext"  (leading wildcard, missing the dot) -> "*.ext"
# - "*.ext" (already correct)                   -> unchanged
sed -E 's/^([a-zA-Z0-9][^*[:space:]]*)$/*.\1/; s/^\.([^*[:space:]]*)$/*.\1/; s/^([_-][^*[:space:]]*)$/*.\1/; s/^\*([^.*[:space:]][^*[:space:]]*)$/*.\1/' "${TMP_DIR}/normalized_lst.txt" | sort -u > "${TMP_DIR}/normalized_lst2.txt"
mv "${TMP_DIR}/normalized_lst2.txt" "${TMP_DIR}/normalized_lst.txt"

# Keep only simple "*.ext" patterns (single leading wildcard, no internal
# wildcards or whitespace). Anything else (bare filenames, multi-wildcard
# patterns, patterns with embedded spaces) is not supported by the Squid
# generation below and is set aside instead of silently corrupting the
# generated ACL.
#
# Entries containing bracketed ID/key placeholders such as "[ID-KEY]" or
# "[ID]" are also discarded: external source lists use this as template
# notation (the attacker substitutes a real ID/key at infection time), so
# it never appears literally in real file extensions and would only
# generate a dead rule.
#
# Entries containing other unescaped regex/glob metacharacters
# ([ ] @ { } ( ) ? ^) are discarded as well: square brackets are character
# classes (not literals) in Squid regex, '?' and '^' are active
# wildcards/anchors, and '@'/'{'/'}'/'('/')' combined with brackets
# produce malformed or unintended ACL rules, e.g.
# "*.[attacker@tuta.io].kix" or "*.CROWN!?".
UNSAFE_RE='\[[A-Za-z]*ID[A-Za-z_-]*\]|\[KEY\]|[][@{}()?^]'
grep -E '^\*\.[^*[:space:]]+$' "${TMP_DIR}/normalized_lst.txt" | grep -E -v "${UNSAFE_RE}" > "${TMP_DIR}/output_lst.txt" || true
grep -E -v '^\*\.[^*[:space:]]+$' "${TMP_DIR}/normalized_lst.txt" > "${TMP_DIR}/discarded_lst.txt" || true
grep -E '^\*\.[^*[:space:]]+$' "${TMP_DIR}/normalized_lst.txt" | grep -E "${UNSAFE_RE}" >> "${TMP_DIR}/discarded_lst.txt" || true
sort -u -o "${TMP_DIR}/discarded_lst.txt" "${TMP_DIR}/discarded_lst.txt"

# Discarded lst
if [ -s "${TMP_DIR}/discarded_lst.txt" ]; then
    log "NOTE: $(wc -l < "${TMP_DIR}/discarded_lst.txt") entries discarded (unsupported pattern format)"
fi

# Apply administrator-defined whitelist (exact match exclusions)
if [ -s "${SRC_DIR}/wl.txt" ]; then
    grep -Fivx -f "${SRC_DIR}/wl.txt" "${TMP_DIR}/output_lst.txt" > "$TMP_FILE"
else
    cp "${TMP_DIR}/output_lst.txt" "$TMP_FILE"
fi
mv "$TMP_FILE" "${TMP_DIR}/output_lst.txt"

# Discard entries that look like ransom-note filenames rather than real
# encryption extensions:
# - ends in a whitelisted document extension (*.ext), or
# - ends in an extra segment plus a whitelisted extension (*.algo.ext),
#   e.g. "*.DATA_RECOVERY.html", "*.README.txt"
# - the extension segment itself is implausibly long (ransom note names
#   or attacker IDs, e.g. "*.NEED_TO_MAKE_THE_PAYMENT_IN_MAXIM_24_HOURS...")
if [ -s "${SRC_DIR}/wl.txt" ]; then
    WL_EXTS=$(grep -v '^#' "${SRC_DIR}/wl.txt" | grep -v '^$' | sed 's/^\*\.//; s/[]^$.+*?{}()|[]/\\&/g' | paste -sd '|' -)
    grep -iE -v "^\*\.(${WL_EXTS})\*?\$|^\*\.[^.]+\.(${WL_EXTS})\*?\$" "${TMP_DIR}/output_lst.txt" > "$TMP_FILE"
    mv "$TMP_FILE" "${TMP_DIR}/output_lst.txt"
fi

awk '{seg=$0; sub(/^\*\./,"",seg); sub(/\*$/,"",seg); if (length(seg) <= 35) print}' "${TMP_DIR}/output_lst.txt" > "$TMP_FILE"
mv "$TMP_FILE" "${TMP_DIR}/output_lst.txt"

# For Squid Extensions/Patterns
sed -E 's/^\*\.//; s/([][(){}+.$])/\\\1/g; s/^/\\./; s/(.*)/\1([a-zA-Z][0-9]*)?(\\?.*)?$/' "${TMP_DIR}/output_lst.txt" | sort -u > "${SRC_DIR}/rwext.txt"
log "Ransomware ACL for Squid: rwext.txt"

# End
log "blackshield done at: $(date)"
