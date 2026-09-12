#!/bin/bash
# maravento.com
#
################################################################################
#
# Domains Check with Host
# Important:
# Ensure the input list has no 'http://', 'https://', or 'www.' prefixes.
# How to use:
# ./domcheck.sh my_domain_list.txt
# Optional (with parallel processes. By default: nproc x 4, max 200)
# ./domcheck.sh my_domain_list.txt 50
#
# NOTE on logging:
# - Writes to dofi.log, emptied at the start of every run, so it always
#   holds the last execution only.
#
################################################################################

set -uo pipefail

# ------------------------------------------------------------------------------
# REQUIREMENTS
# ------------------------------------------------------------------------------

# logging
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_file="$script_dir/dofi.log"
{ > "$log_file"; } 2>/dev/null || true
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$log_file" 2>/dev/null || true
}

# check no-root
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
for dep_pkg in bind9-host findutils grep sed coreutils util-linux; do
    if ! dpkg -s "$dep_pkg" &>/dev/null; then
        log "ERROR: '$dep_pkg' is not installed -- abort"
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
    log "ERROR: use: $(basename "$0") <file> [procs] -- abort"
    exit 1
fi

input_file="$1"

if [ "$#" -eq 2 ]; then
    if ! [[ "$2" =~ $UH_UINT ]] || [ "$2" -lt 1 ]; then
        log "ERROR: procs must be a positive integer -- abort"
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
    log "ERROR: '$(basename "$input_file")' does not exist -- abort"
    exit 1
fi

# ------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------

cleanup_tmp() {
    rm -f clean step2 dnslookup dnslookup2
}
trap cleanup_tmp EXIT

# Clean working directory before starting -- every run processes its
# input list from scratch, so leftover dnslookup/dnslookup2 from a
# previous run (possibly a different list) never contaminate this one.
rm -f dnslookup dnslookup2

# Start
start_time=$(date +%s)
log "domcheck start..."

# ------------------------------------------------------------------------------
# DNS LOOKUP
# ------------------------------------------------------------------------------

sed '/^$/d; /^[[:space:]]*$/d; /#/d' "$input_file" | sed 's/\r//g; s/^\.//g' >clean
rm -f step2 fault.txt hit.txt

log "Step 1..."
xargs -I {} -P "$parallel_procs" sh -c 'd="$1"; case "$d" in *[!a-zA-Z0-9._-]*) echo FAULT "$d"; exit 0 ;; esac; if timeout 5 host "$d" >/dev/null 2>&1; then echo HIT "$d"; else echo FAULT "$d"; fi' _ {} <clean >>dnslookup
sed '/^FAULT/d' dnslookup | awk '{print $2}' | awk '{print "."$1}' | sort -u >hit.txt
sed '/^HIT/d' dnslookup | awk '{print $2}' | awk '{print "."$1}' | sort -u >>fault.txt
sort -o fault.txt -u fault.txt
log "OK"

log "Step 2..."
sed 's/^\.//g' fault.txt | sort -u >step2
xargs -I {} -P "$parallel_procs" sh -c 'd="$1"; case "$d" in *[!a-zA-Z0-9._-]*) echo FAULT "$d"; exit 0 ;; esac; if timeout 5 host "$d" >/dev/null 2>&1; then echo HIT "$d"; else echo FAULT "$d"; fi' _ {} <step2 >>dnslookup2
sed '/^FAULT/d' dnslookup2 | awk '{print $2}' | awk '{print "."$1}' | sort -u >>hit.txt
sed '/^HIT/d' dnslookup2 | awk '{print $2}' | awk '{print "."$1}' | sort -u >fault.txt
log "hit.txt: domains successfully resolved"
log "fault.txt: unresolved domains"

# ------------------------------------------------------------------------------
# END
# ------------------------------------------------------------------------------

end_time=$(date +%s)
elapsed_time=$((end_time - start_time))

total_domains=$(wc -l < clean)
hit_count=$(wc -l < hit.txt)
fault_count=$(wc -l < fault.txt)

log "Summary:"
log "  Input domains : $total_domains"
log "  Resolved      : $hit_count"
log "  Unresolved    : $fault_count"
log "  Elapsed time  : ${elapsed_time}s"

log "domcheck done at: $(date)"
