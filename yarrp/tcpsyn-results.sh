#!/bin/bash
# =============================================================================
# tcpsyn-results.sh -- one-shot summary of a yarrpbox TCP_SYN .yrp result file.
# Reproduces the modification-rate report: headline rate, top modifying routers,
# unique middleboxes, per-modification-type breakdown, and affected targets.
#
# Field layout (from the .yrp `Output_Fields:` header, 1-indexed data columns):
#   $1 target  $3 hop  $22 ipMatch  $23 tcpMatch  $24 completeMatch
#   $26 TosModif  $27 pSizeModif  $29 tcpOffsetModif  $30 tcpFlagsModif
#   $34 mpCapablePresent  $38 nopNotAdded
# A "modification" = ipMatch==0 OR tcpMatch==0 OR completeMatch==0.
#
# Usage: bash tcpsyn-results.sh <file.yrp>
# =============================================================================
set -euo pipefail

IN="${1:-}"
[ -n "$IN" ] && [ -s "$IN" ] || { echo "usage: $0 <file.yrp>"; exit 2; }

echo "=================================================="
echo "TCP SYN RESULTS : $(basename "$IN")"
echo "=================================================="

awk '
!/^#/ && NF >= 41 {
    tot++
    tgt[$1] = 1
    if ($22 == 0) ip0++
    if ($23 == 0) tcp0++
    if ($24 == 0) comp0++
    mod = ($22 == 0 || $23 == 0 || $24 == 0)
    if (mod) {
        modhops++
        atgt[$1] = 1
        rc[$3]++          # modifying-router hit count
        mb[$3] = 1        # unique middleboxes
        # per-type breakdown is counted WITHIN modified hops: a ToS/DSCP-only rewrite
        # is normalized out of the hash, so counting over all hops would overcount.
        if ($26 == 1) tos++
        if ($27 == 1) psize++
        if ($29 == 1) toff++
        if ($30 == 1) tflags++
        if ($34 == 0) mpcap++     # MP_CAPABLE removed (option absent from the quote)
        if ($38 == 0) nop++       # NOP added (nopNotAdded == 0)
    }
}
END {
    surv = tot - modhops
    printf "\n[1] Headline Modification Rate\n"
    printf "Total hops      : %d\n", tot
    printf "Modified hops   : %d (%.4f%%)\n", modhops, tot ? 100.0*modhops/tot : 0
    printf "Survived hops   : %d (%.4f%%)\n", surv, tot ? 100.0*surv/tot : 0

    printf "\n[2] Top Modifying Routers (Top 30)\n"
    n = 0
    for (r in rc) { keys[n++] = r }
    # simple selection of the top 30 by count (n is small: #middleboxes)
    for (i = 0; i < 30 && i < n; i++) {
        best = -1; bi = -1
        for (j = 0; j < n; j++) if (keys[j] != "" && rc[keys[j]] > best) { best = rc[keys[j]]; bi = j }
        if (bi < 0) break
        printf "%d %s\n", rc[keys[bi]], keys[bi]
        keys[bi] = ""
    }

    printf "\n[3] Unique Middleboxes\n"
    umb = 0; for (k in mb) umb++
    printf "    %d\n", umb

    printf "\n[4] Modification Type Breakdown\n"
    printf "IP hash mismatch     : %d\n", ip0
    printf "TCP hash mismatch    : %d\n", tcp0
    printf "Complete mismatch    : %d\n", comp0
    printf "ToS modified         : %d\n", tos
    printf "Packet size modified : %d\n", psize
    printf "TCP offset modified  : %d\n", toff
    printf "TCP flags modified   : %d\n", tflags
    printf "MP_CAPABLE removed   : %d\n", mpcap
    printf "NOP added            : %d\n", nop

    printf "\n[5] Unique Targets Affected\n"
    ut = 0; for (k in tgt) ut++
    at = 0; for (k in atgt) at++
    printf "Total unique targets : %d\n", ut
    printf "Affected targets     : %d (%.4f%%)\n", at, ut ? 100.0*at/ut : 0
}
' "$IN"

echo
echo "=================================================="
echo "Analysis Complete"
echo "=================================================="
