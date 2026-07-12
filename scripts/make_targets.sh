#!/bin/sh
# make_targets.sh -- build a phantomprobe targets file by pairing a list of IPs
# with a trigger (a censored domain for http/https/dns, or a placeholder for stun).
#
# Usage:
#   scripts/make_targets.sh IPS_FILE TRIGGER            > targets.txt
#   scripts/make_targets.sh IPS_FILE DOMAINS_FILE --each > targets.txt
#
#   IPS_FILE      one IPv4 per line (e.g. ZMap output, or a live-host list).
#                 Blank lines and lines starting with '#' are ignored.
#   TRIGGER       a single trigger applied to every IP (a domain, qname, or
#                 "allocate" for stun).
#   DOMAINS_FILE --each   instead of one trigger, read triggers from a file and
#                 emit the full IP x trigger cross-product (one line each).
#
# Output is the phantomprobe format: "IP<TAB>TRIGGER", one per line.
# Portable POSIX sh + awk; no dependencies.

set -eu

if [ $# -lt 2 ]; then
    echo "usage: $0 IPS_FILE TRIGGER            > targets.txt" >&2
    echo "       $0 IPS_FILE DOMAINS_FILE --each > targets.txt" >&2
    exit 2
fi

ips=$1
trig=$2
mode=${3:-single}

[ -r "$ips" ] || { echo "cannot read IPS_FILE: $ips" >&2; exit 2; }

# valid dotted-quad IPv4?  (each octet 0-255).  NOTE: no `END{exit 0}` -- in awk an
# END exit code overrides a rule's exit, so we let a clean run fall through to exit 0.
is_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF!=4 { exit 1 }
        { for (i=1;i<=4;i++) if ($i !~ /^[0-9]+$/ || $i+0 > 255) exit 1 }'
}

emit() {  # emit IP TRIGGER
    printf '%s\t%s\n' "$1" "$2"
}

if [ "$mode" = "--each" ]; then
    [ -r "$trig" ] || { echo "cannot read DOMAINS_FILE: $trig" >&2; exit 2; }
    # cross-product: every IP x every trigger
    while IFS= read -r ip || [ -n "$ip" ]; do
        ip=$(printf '%s' "$ip" | tr -d '\r' | awk '{print $1}')
        case "$ip" in ''|\#*) continue ;; esac
        is_ipv4 "$ip" || { echo "skip (not IPv4): $ip" >&2; continue; }
        while IFS= read -r d || [ -n "$d" ]; do
            d=$(printf '%s' "$d" | tr -d '\r' | awk '{print $1}')
            case "$d" in ''|\#*) continue ;; esac
            emit "$ip" "$d"
        done < "$trig"
    done < "$ips"
else
    while IFS= read -r ip || [ -n "$ip" ]; do
        ip=$(printf '%s' "$ip" | tr -d '\r' | awk '{print $1}')
        case "$ip" in ''|\#*) continue ;; esac
        is_ipv4 "$ip" || { echo "skip (not IPv4): $ip" >&2; continue; }
        emit "$ip" "$trig"
    done < "$ips"
fi
