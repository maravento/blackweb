#!/bin/bash
# maravento.com
#
################################################################################
#
# Domains Check with Host
# FILE: dofi/domcheck.sh
#
# USAGE:
# ./domcheck.sh <file> [procs]
#
# LOG: dofi.log, in the directory where this script is located
#      Emptied at the start of every run, holds the last execution only
#
################################################################################

set -uo pipefail

# ------------------------------------------------------------------------------
# REQUIREMENTS
# ------------------------------------------------------------------------------

# no-root check
if [ "$(id -u)" == "0" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: This script should not be run as root -abort" >&2
    exit 1
fi

# prevent overlapping runs
script_lock="/var/lock/$(basename "$0" .sh).lock"
(umask 077; : >> "$script_lock") || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: cannot open $(basename "$script_lock") -abort" >&2
    exit 1
}
exec 200>"$script_lock"
if ! flock -n 200; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: script $(basename "$0") is already running -abort" >&2
    exit 1
fi

# logging
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$script_dir/dofi.log"
{ > "$log_file"; } 2>/dev/null || true
log() {
    local log_msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$log_msg" >> "$log_file" 2>/dev/null || true
    if [[ "$1" == ERROR:* ]]; then
        echo "$log_msg" >&2
    else
        echo "$log_msg"
    fi
}

# Function: Report whether a package is installed, not merely residual
package_installed() {
    [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" = installed ]
}

# dependencies
for dep_pkg in bind9-host findutils grep sed coreutils util-linux; do
    if ! package_installed "$dep_pkg"; then
        log "ERROR: dependency '$dep_pkg' is not installed -abort"
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

# validation -- integer only; use directly with =~
UH_UINT='^(0|[1-9][0-9]*)$'
# parallel_processes
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    log "ERROR: use: $(basename "$0") <file> [procs] -abort"
    exit 1
fi

input_file="$1"

if [ "$#" -eq 2 ]; then
    if ! [[ "$2" =~ $UH_UINT ]] || [ "$2" -lt 1 ]; then
        log "ERROR: procs must be a positive integer -abort"
        exit 1
    fi
    if ! xargs -r -P "$2" true </dev/null 2>/dev/null; then
        log "ERROR: procs value is not supported by xargs -abort"
        exit 1
    fi
    parallel_procs="$2"
else
    parallel_procs=$(($(nproc) * 4))
    max_parallel_procs=200
    if [ "$parallel_procs" -gt "$max_parallel_procs" ]; then
        parallel_procs="$max_parallel_procs"
    fi
fi

if [ ! -f "$input_file" ]; then
    log "ERROR: '$(basename "$input_file")' does not exist -abort"
    exit 1
fi

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

cleanup_tmp() {
    rm -rf -- "$tmp_dir"
}

# Exclusive temporary directory -- every run processes its input list
# from scratch, and files of the working directory are never touched.
tmp_dir="$(mktemp -d)" || {
    log "ERROR: cannot create temporary directory -abort"
    exit 1
}
trap cleanup_tmp EXIT

clean="$tmp_dir/clean"
step2="$tmp_dir/step2"
lookup1="$tmp_dir/dnslookup"
lookup2="$tmp_dir/dnslookup2"
faultlist="$tmp_dir/faultlist"

# Start
start_time=$(date +%s)
log "EVENT: domcheck start..."

# ------------------------------------------------------------------------------
# DNS LOOKUP
# ------------------------------------------------------------------------------

if ! { sed '/^$/d; /^[[:space:]]*$/d; /#/d' -- "$input_file" |
    sed 's/\r//g; s/^\.//g' >"$clean"; }; then
    log "ERROR: cannot read input list -abort"
    exit 1
fi
rm -f fault.txt hit.txt

log "EVENT: Step 1..."
if ! xargs -d '\n' -I {} -P "$parallel_procs" sh -c 'd="$1"; case "$d" in *[!a-zA-Z0-9._-]*) printf "FAULT %s\n" "$d"; exit 0 ;; esac; if timeout 5 host "$d" >/dev/null 2>&1; then printf "HIT %s\n" "$d"; else printf "FAULT %s\n" "$d"; fi' _ {} <"$clean" >>"$lookup1"; then
    log "ERROR: $(basename "$input_file"): domain check command failed -abort"
    exit 1
fi
if ! sed -n 's/^HIT /./p' "$lookup1" | sort -u >hit.txt; then
    log "ERROR: cannot build hit.txt from DNS results -abort"
    exit 1
fi
if ! sed -n 's/^FAULT /./p' "$lookup1" | sort -u >"$faultlist"; then
    log "ERROR: cannot collect unresolved DNS results -abort"
    exit 1
fi
if ! comm -23 "$faultlist" hit.txt >fault.txt; then
    log "ERROR: cannot build fault.txt from DNS results -abort"
    exit 1
fi

log "EVENT: Step 2..."
if ! sed 's/^\.//g' fault.txt | sort -u >"$step2"; then
    log "ERROR: cannot prepare fault.txt for DNS recheck -abort"
    exit 1
fi
if ! xargs -d '\n' -I {} -P "$parallel_procs" sh -c 'd="$1"; case "$d" in *[!a-zA-Z0-9._-]*) printf "FAULT %s\n" "$d"; exit 0 ;; esac; if timeout 5 host "$d" >/dev/null 2>&1; then printf "HIT %s\n" "$d"; else printf "FAULT %s\n" "$d"; fi' _ {} <"$step2" >>"$lookup2"; then
    log "ERROR: fault.txt: domain check command failed -abort"
    exit 1
fi
if ! sed -n 's/^HIT /./p' "$lookup2" >>hit.txt; then
    log "ERROR: cannot add resolved domains to hit.txt -abort"
    exit 1
fi
if ! sort -o hit.txt -u hit.txt; then
    log "ERROR: cannot sort hit.txt -abort"
    exit 1
fi
if ! sed -n 's/^FAULT /./p' "$lookup2" | sort -u >"$faultlist"; then
    log "ERROR: cannot collect unresolved DNS recheck results -abort"
    exit 1
fi
if ! comm -23 "$faultlist" hit.txt >fault.txt; then
    log "ERROR: cannot build fault.txt from DNS recheck -abort"
    exit 1
fi
log "INFO: hit.txt: domains successfully resolved"
log "INFO: fault.txt: unresolved domains"

# ------------------------------------------------------------------------------
# END
# ------------------------------------------------------------------------------

end_time=$(date +%s)
elapsed_time=$((end_time - start_time))

total_domains=$(wc -l < "$clean")
hit_count=$(wc -l < hit.txt)
fault_count=$(wc -l < fault.txt)

log "INFO: Summary:"
log "INFO: Input domains: $total_domains"
log "INFO: Resolved: $hit_count"
log "INFO: Unresolved: $fault_count"
log "INFO: Elapsed time: ${elapsed_time}s"

log "EVENT: domcheck done"
