#!/bin/bash
# =============================================================================
# Extract destination IPs from a yarrpbox .yrp TCP/80 result file.
#
# Expected yarrpbox columns for this project:
#   $1  = destination IP
#   $3  = middlebox / hop IP associated with the modification
#   $22-$24 = modification flags; a zero in any of these marks modification
#
# Outputs:
#   inputs/uae_dests_full.txt
#   inputs/uae_dests_sample.txt
#   inputs/uae_mb_dest_pairs_80.txt
#   inputs/uae_mb_counts_80.txt
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IN="${1:-}"
SAMPLE_N="${SAMPLE_N:-1000}"

if [ -z "$IN" ] || [ ! -s "$IN" ]; then
    echo "Usage: bash scripts/extract_yarrp_dests.sh <port80-yarrpbox.yrp>"
    echo "Example: bash scripts/extract_yarrp_dests.sh /root/yarrpbox/dev-tcp-80.yrp"
    exit 1
fi

mkdir -p inputs outputs/yarrp_extract

echo "=== extracting yarrpbox TCP/80 candidates ==="
echo "  input:        $IN"
echo "  input lines:  $(wc -l < "$IN")"

awk '
function ipv4(s) { return s ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ }
!/^#/ && NF >= 24 && ipv4($1) && ipv4($3) && ($22 == 0 || $23 == 0 || $24 == 0) {
    dest[$1] = 1
    pair[$3 "," $1] = 1
    mb[$3 "|" $1] = 1
}
END {
    for (d in dest) print d > "outputs/yarrp_extract/uae_dests_full.unsorted"
    for (p in pair) print p > "outputs/yarrp_extract/uae_mb_dest_pairs_80.unsorted"
    for (k in mb) {
        split(k, a, "|")
        count[a[1]]++
    }
	    for (m in count) printf "%d %s\n", count[m], m > "outputs/yarrp_extract/uae_mb_counts_80.unsorted"
	}' "$IN"

touch outputs/yarrp_extract/uae_dests_full.unsorted \
      outputs/yarrp_extract/uae_mb_dest_pairs_80.unsorted \
      outputs/yarrp_extract/uae_mb_counts_80.unsorted

sort -u outputs/yarrp_extract/uae_dests_full.unsorted > inputs/uae_dests_full.txt
sort -u outputs/yarrp_extract/uae_mb_dest_pairs_80.unsorted > inputs/uae_mb_dest_pairs_80.txt
sort -rn outputs/yarrp_extract/uae_mb_counts_80.unsorted > inputs/uae_mb_counts_80.txt
head -n "$SAMPLE_N" inputs/uae_dests_full.txt > inputs/uae_dests_sample.txt

rm -f outputs/yarrp_extract/*.unsorted

echo "  unique modified destination IPs: $(wc -l < inputs/uae_dests_full.txt)"
echo "  sample destination IPs:          $(wc -l < inputs/uae_dests_sample.txt)"
echo "  middlebox/dest pairs:            $(wc -l < inputs/uae_mb_dest_pairs_80.txt)"
echo
echo "Wrote:"
echo "  inputs/uae_dests_full.txt"
echo "  inputs/uae_dests_sample.txt"
echo "  inputs/uae_mb_dest_pairs_80.txt"
echo "  inputs/uae_mb_counts_80.txt"
