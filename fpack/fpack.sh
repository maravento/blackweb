#!/bin/bash
# maravento.com
#
################################################################################
#
# Filter Pack (fpack)
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
# 1. Download bad User-Agent list -> normalize -> regenerate
#    ua/blockua.txt (deduplicated, overwritten every run).
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
#    metacharacters [ ] @ { } ( ) ? ^ | \) is discarded (the on-screen count
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
# - Writes to fpack.log, emptied at the start of every run, so it always
#   holds the last execution only.
#
################################################################################

set -uo pipefail

# ------------------------------------------------------------------------------
# REQUIREMENTS
# ------------------------------------------------------------------------------

# logging
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$script_dir/fpack.log"
{ > "$log_file"; } 2>/dev/null || true
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$log_file" 2>/dev/null || true
}

# no-root check
if [ "$(id -u)" == "0" ]; then
    log "ERROR: This script should not be run as root -- abort"
    exit 1
fi

# prevent overlapping runs
script_lock="/var/lock/$(basename "$0" .sh).lock"
(umask 077; : >> "$script_lock")
exec 200>"$script_lock"
if ! flock -n 200; then
    log "ERROR: script $(basename "$0") is already running -- abort"
    exit 1
fi

# dependencies
for dep_pkg in wget curl grep sed coreutils util-linux; do
    if ! dpkg -s "$dep_pkg" &>/dev/null; then
        log "ERROR: '$dep_pkg' is not installed -- abort"
        exit 1
    fi
done

# check internet
check_internet() {
    local max_attempts="${1:-24}" attempt=1

    while (( attempt <= max_attempts )); do
        if getent hosts www.google.com >/dev/null 2>&1; then
            log "INFO: internet is available"
            return 0
        fi
        log "INFO: waiting for internet ($attempt/$max_attempts)"
        attempt=$((attempt + 1))
        sleep 5
    done

    return 1
}

if ! check_internet; then
    log "ERROR: no internet connection -- abort"
    exit 1
fi

# Start
log "fpack start..."

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

cd "$script_dir" || { log "ERROR: cannot cd to $(basename "$script_dir") -- abort"; exit 1; }

src_dir="rw"
ua_dir="ua"

tmp_dir=$(mktemp -d)
trap '[ -n "$tmp_dir" ] && rm -rf "$tmp_dir"' EXIT

# Unique scratch file per run/invocation, so overlapping executions (e.g.
# cron overlap) never write to the same intermediate path.
tmp_file=$(mktemp "${tmp_dir}/output_lst.XXXXXX")

wget_opts='wget -q -c --retry-connrefused --timeout=10 --tries=4'

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

# source check
check_url() {
    local source_url="$1" http_code
    http_code=$(curl -k -s -o /dev/null -w '%{http_code}' -I -L --connect-timeout 5 --max-time 15 --retry 1 "$source_url")
    case "$http_code" in
        2*|405) return 0 ;;
        000) log "TIMEOUT: $source_url" ;;
        5*)  log "BUSY: $source_url" ;;
        *)   log "BROKEN: $source_url" ;;
    esac
    return 1
}

# bad User-Agents
ua_url="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"
if check_url "$ua_url"; then
    if $wget_opts -O "${tmp_dir}/bad-user-agents.list" "$ua_url"; then
        sed -E 's/\\//g' "${tmp_dir}/bad-user-agents.list" | sort -u > "${ua_dir}/blockua.txt"
        log "SAVED: $(basename "$ua_url")"
    else
        log "PARTIAL: $ua_url"
    fi
fi

: > "${tmp_dir}/source_lst.txt"

# ransomware
rw() {
    check_url "$1" || return 1
    if $wget_opts "$1" -O - >> "${tmp_dir}/source_lst.txt"; then
        log "SAVED: $(basename "$1")"
        return 0
    else
        log "PARTIAL: $1"
        return 1
    fi
}
rw 'https://raw.githubusercontent.com/dannyroemhild/ransomware-fileext-list/refs/heads/master/fileextlist.txt' && sleep 1 || true
rw 'https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/refs/heads/main/ransomware-extension-list.txt' && sleep 1 || true
rw 'https://raw.githubusercontent.com/giacomoarru/ransomware-extensions-2024/refs/heads/main/ransomware-extensions.txt' && sleep 1 || true
#rw 'https://raw.githubusercontent.com/kinomakino/ransomware_file_extensions/master/extensions.csv' && sleep 1 || true
rw 'https://raw.githubusercontent.com/nspoab/malicious_extensions/refs/heads/main/list1' && sleep 1 || true

if [ -s "${src_dir}/rw.txt" ]; then
    cat "${src_dir}/rw.txt" >> "${tmp_dir}/source_lst.txt"
fi

# normalize raw entries: keep only ASCII, trim whitespace, drop empty lines
LC_ALL=C grep -v '[^[:print:][:space:]]' "${tmp_dir}/source_lst.txt" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//' | sed '/^$/d' | sort -u > "${tmp_dir}/normalized_lst.txt"

# Treat "ext", ".ext", "_ext", "-ext", "*ext" and "*.ext" as the same idea:
# normalize all to "*.ext"
# - "ext"   (bare alnum start, no dot/asterisk) -> "*.ext"
# - ".ext"  (leading dot, no asterisk)          -> "*.ext"
# - "_ext"/"-ext" (leading underscore/hyphen)   -> "*._ext" / "*.-ext"
# - "*ext"  (leading wildcard, missing the dot) -> "*.ext"
# - "*.ext" (already correct)                   -> unchanged
sed -E 's/^([a-zA-Z0-9][^*[:space:]]*)$/*.\1/; s/^\.([^*[:space:]]*)$/*.\1/; s/^([_-][^*[:space:]]*)$/*.\1/; s/^\*([^.*[:space:]][^*[:space:]]*)$/*.\1/' "${tmp_dir}/normalized_lst.txt" | sort -u > "${tmp_dir}/normalized_lst2.txt"
mv "${tmp_dir}/normalized_lst2.txt" "${tmp_dir}/normalized_lst.txt"

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
# ([ ] @ { } ( ) ? ^ | \) are discarded as well: square brackets are
# character classes (not literals) in Squid regex, '?' and '^' are active
# wildcards/anchors, '|' is an alternation that would turn one entry into
# a match-anything rule, '\' escapes the next character, and '@'/'{'/'}'/
# '('/')' combined with brackets produce malformed or unintended ACL
# rules, e.g. "*.[attacker@tuta.io].kix" or "*.CROWN!?".
unsafe_pattern='\[[A-Za-z]*ID[A-Za-z_-]*\]|\[KEY\]|[][@{}()?^|\\]'
grep -E '^\*\.[^*[:space:]]+$' "${tmp_dir}/normalized_lst.txt" | grep -E -v "${unsafe_pattern}" > "${tmp_dir}/output_lst.txt" || true
grep -E -v '^\*\.[^*[:space:]]+$' "${tmp_dir}/normalized_lst.txt" > "${tmp_dir}/discarded_lst.txt" || true
grep -E '^\*\.[^*[:space:]]+$' "${tmp_dir}/normalized_lst.txt" | grep -E "${unsafe_pattern}" >> "${tmp_dir}/discarded_lst.txt" || true
sort -u -o "${tmp_dir}/discarded_lst.txt" "${tmp_dir}/discarded_lst.txt"

# Discarded lst
if [ -s "${tmp_dir}/discarded_lst.txt" ]; then
    log "INFO: $(wc -l < "${tmp_dir}/discarded_lst.txt") entries discarded"
fi

# Apply administrator-defined whitelist (exact match exclusions)
if [ -s "${src_dir}/wl.txt" ]; then
    grep -Fivx -f "${src_dir}/wl.txt" "${tmp_dir}/output_lst.txt" > "$tmp_file"
else
    cp "${tmp_dir}/output_lst.txt" "$tmp_file"
fi
mv "$tmp_file" "${tmp_dir}/output_lst.txt"

# Discard entries that look like ransom-note filenames rather than real
# encryption extensions:
# - ends in a whitelisted document extension (*.ext), or
# - ends in an extra segment plus a whitelisted extension (*.algo.ext),
#   e.g. "*.DATA_RECOVERY.html", "*.README.txt"
# - the extension segment itself is implausibly long (ransom note names
#   or attacker IDs, e.g. "*.NEED_TO_MAKE_THE_PAYMENT_IN_MAXIM_24_HOURS...")
if [ -s "${src_dir}/wl.txt" ]; then
    wl_extensions=$(grep -v '^#' "${src_dir}/wl.txt" | grep -v '^$' | sed 's/^\*\.//; s/[]^$.+*?{}()|[]/\\&/g' | paste -sd '|' -)
    grep -iE -v "^\*\.(${wl_extensions})\$|^\*\.[^.]+\.(${wl_extensions})\$" "${tmp_dir}/output_lst.txt" > "$tmp_file"
    mv "$tmp_file" "${tmp_dir}/output_lst.txt"
fi

awk '{seg=$0; sub(/^\*\./,"",seg); if (length(seg) <= 35) print}' "${tmp_dir}/output_lst.txt" > "$tmp_file"
mv "$tmp_file" "${tmp_dir}/output_lst.txt"

# For Squid Extensions/Patterns
sed -E 's/^\*\.//; s/([][(){}+.$])/\\\1/g; s/^/\\./; s/(.*)/\1([a-zA-Z][0-9]*)?(\\?.*)?$/' "${tmp_dir}/output_lst.txt" | sort -u > "${src_dir}/rwext.txt"
log "INFO: ransomware ACL for Squid: rwext.txt"

# ------------------------------------------------------------------------------
# END
# ------------------------------------------------------------------------------

log "fpack done at: $(date '+%Y-%m-%d %H:%M:%S')"
