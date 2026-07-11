/* stages.c -- raw stages 3-7: onset+route, in/off-path, backup, IP-ID same-box. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "phantomprobe.h"
#include "rawnet.h"
#include "stages.h"

static void msleep(int ms) { usleep(ms * 1000); }
static int  cdist(int a, int b) { int d = ((a - b) % 65536 + 65536) % 65536; return d < 65536 - d ? d : 65536 - d; }
static uint32_t rnd32(void) { return ((uint32_t)rand() << 16) ^ (uint32_t)rand(); }

/* ---------------- stage 3: route + onset (fixed sport = Paris) ----------------
 * Phase A: traceroute with raw SYNs on the fixed sport -> clean route[ttl].
 * Phase B: onset with a REAL-connection ClientHello (bound to the same sport, so it
 *          shares the path) -- the injected RST only fires on a genuine connection.
 * onset_router = the router at the injecting hop (route[onset-1], the last clean hop). */
int stage_localize(int rawfd, cap_t *cap, uint32_t tgt_be, const char *tgt_ip, int dport, uint16_t sport,
                   uint32_t src_be, const uint8_t *ch, int chlen, int maxttl, loc_t *out) {
    memset(out, 0, sizeof *out);
    for (int ttl = 1; ttl <= maxttl && ttl < 40; ttl++) {          /* Phase A: traceroute */
        cap_reset(cap);
        for (int k = 0; k < 2; k++) send_tcp(rawfd, src_be, tgt_be, sport, dport, rnd32(), 0, F_SYN, ttl, NULL, 0);
        msleep(220);
        icmp_ev *ic; int ni = cap_icmps(cap, &ic);
        for (int i = 0; i < ni; i++) if (ic[i].inner_dst == tgt_be) {
            struct in_addr a; a.s_addr = ic[i].rtr; snprintf(out->route[ttl], 32, "%s", inet_ntoa(a)); break;
        }
        if (out->route[ttl][0]) out->path_len = ttl;
    }
    for (int ttl = 4; ttl <= maxttl && ttl < 40; ttl++) {          /* Phase B: onset */
        cap_reset(cap);
        conn_send_ttl(tgt_ip, dport, 0, ch, chlen, ttl, 0, 2.0);      /* ephemeral: real conn must complete */
        conn_send_ttl(tgt_ip, dport, 0, ch, chlen, ttl, 0, 2.0);
        msleep(250);
        rst_ev *rs; int nr = cap_rsts(cap, &rs);
        if (nr >= 2) { out->onset = ttl; break; }
    }
    if (out->onset) {
        int h = (out->onset - 1 >= 1 && out->route[out->onset - 1][0]) ? out->onset - 1 : out->onset;
        snprintf(out->onset_router, sizeof out->onset_router, "%s", out->route[h]);
    }
    return out->onset > 0;
}

/* ---------------- stage 4: in-path / off-path (downstream survival) ---------------- */
static int reached_beyond(cap_t *cap, uint32_t tgt_be) {
    icmp_ev *ic; int n = cap_icmps(cap, &ic);
    for (int i = 0; i < n; i++) if (ic[i].inner_dst == tgt_be) return 1;
    return 0;
}
int stage_survival(cap_t *cap, uint32_t tgt_be, const char *tgt_ip, int dport, uint16_t sport,
                   const uint8_t *ben, int blen, const uint8_t *ch, int chlen,
                   int onset, int path_len, surv_t *out) {
    (void)sport;   /* survival triggers use ephemeral sports (like the validated Python) */
    memset(out, 0, sizeof *out);
    int ttls[4], nt = 0;
    for (int t = onset + 1; t <= onset + 4; t++) { if (path_len && t > path_len) break; ttls[nt++] = t; }
    if (nt == 0) { strcpy(out->verdict, "NO-ROOM"); return 0; }
    { char *p = out->tested; for (int i = 0; i < nt; i++) p += sprintf(p, "%s%d", i ? "|" : "", ttls[i]); }
    int bhit[4] = {0}, thit[4] = {0}; const int rounds = 4;   /* all rounds (no early stop) */
    for (int r = 0; r < rounds; r++) {
        for (int phase = 0; phase < 2; phase++) {
            int forbidden = (r % 2 == 0) ? (phase == 1) : (phase == 0);
            const uint8_t *pl = forbidden ? ch : ben; int pln = forbidden ? chlen : blen;
            for (int i = 0; i < nt; i++) {
                cap_reset(cap);
                conn_send_ttl(tgt_ip, dport, 0, pl, pln, ttls[i], 1, 2.0);   /* two clean real-conn */
                conn_send_ttl(tgt_ip, dport, 0, pl, pln, ttls[i], 1, 2.0);   /* TTL-limited sends    */
                msleep(300);
                if (reached_beyond(cap, tgt_be)) { if (forbidden) thit[i]++; else bhit[i]++; }
            }
        }
    }
    /* off-path only if the forbidden trigger survives REPEATEDLY (>=2/4) at some hop --
     * one lone survival is just an ECMP path that missed the DPI. in-path if benign
     * clears a hop but the forbidden essentially never does. */
    char *sp = out->survived, *dp = out->dropped; int nsurv = 0, ndrop = 0;
    for (int i = 0; i < nt; i++) if (thit[i] >= 2) sp += sprintf(sp, "%s%d(t%d)", nsurv++ ? "|" : "", ttls[i], thit[i]);
    for (int i = 0; i < nt; i++) if (bhit[i] >= 3 && thit[i] <= 1)
        dp += sprintf(dp, "%s%d(b%d/t%d)", ndrop++ ? "|" : "", ttls[i], bhit[i], thit[i]);
    if (nsurv) strcpy(out->verdict, "OFF-PATH");
    else if (ndrop) strcpy(out->verdict, "IN-PATH-DROP");
    else strcpy(out->verdict, "INCONCLUSIVE");
    return 1;
}

/* ---------------- stage 6: backup injector (dense track separation) ---------------- */
static int sep_tracks(const uint16_t *ids, int n, int maxstep, int *sizes, int cap) {
    static int tlast[512], tcnt[512];
    int nt = 0;
    for (int k = 0; k < n; k++) {
        int best = -1, bstep = 0;
        for (int j = 0; j < nt; j++) {
            int step = ((int)ids[k] - tlast[j]) & 0xffff;
            if (step > 0 && step < maxstep && (best < 0 || step < bstep)) { best = j; bstep = step; }
        }
        if (best < 0) { if (nt < 512) { tlast[nt] = ids[k]; tcnt[nt] = 1; nt++; } }
        else { tlast[best] = ids[k]; tcnt[best]++; }
    }
    int m = 0;
    for (int j = 0; j < nt; j++) if (tcnt[j] >= 3 && m < cap) sizes[m++] = tcnt[j];
    return m;
}
int stage_backup(int rawfd, cap_t *cap, uint32_t tgt_be, int dport, uint32_t src_be,
                 const uint8_t *ch, int chlen, int n, backup_t *out) {
    memset(out, 0, sizeof *out);
    cap_reset(cap);
    for (int k = 0; k < n; k++) {
        send_tcp(rawfd, src_be, tgt_be, 1025 + rand() % 63000, dport, rnd32(), rnd32(), F_PA, 64, ch, chlen);
        msleep(10);
    }
    msleep(800);
    rst_ev *rs; int nr = cap_rsts(cap, &rs);
    out->resets = nr;
    if (nr < 8) { snprintf(out->verdict, sizeof out->verdict, "NO-FIRE/too-few (stateless trigger silent here)"); return 0; }
    uint16_t *ids = malloc(nr * sizeof(uint16_t));
    for (int i = 0; i < nr; i++) ids[i] = rs[i].id;     /* capture is already time-ordered */
    int inc = 0, tot = 0;
    for (int i = 0; i + 1 < nr; i++) { int st = ((int)ids[i + 1] - ids[i]) & 0xffff; if (st > 0 && st < 32768) inc++; tot++; }
    out->frac = tot ? (double)inc / tot : 0;
    int sizes[16]; int nk = sep_tracks(ids, nr, 12000, sizes, 16);
    out->tracks = nk;
    char *p = out->sizes; for (int i = 0; i < nk && p - out->sizes < 70; i++) p += sprintf(p, "%s%d", i ? "|" : "", sizes[i]);
    int s0 = 0, s1 = 0;   /* largest, second-largest track */
    for (int i = 0; i < nk; i++) { if (sizes[i] > s0) { s1 = s0; s0 = sizes[i]; } else if (sizes[i] > s1) s1 = sizes[i]; }
    /* monotone-fraction is the primary signal (one fast counter -> ~1.0). Only call
     * primary+backup when the SECOND counter is substantial (>=20% of samples), so a
     * single counter with a tiny spurious fragment (e.g. 156|3) stays SINGLE. */
    if (out->frac >= 0.9 || nk <= 1)
        snprintf(out->verdict, sizeof out->verdict, "SINGLE injector (one counter)");
    else if (nk >= 2 && s1 >= 0.25 * nr)   /* two SUBSTANTIAL interleaved counters */
        snprintf(out->verdict, sizeof out->verdict, "PRIMARY+BACKUP (2 counters %d|%d)", s0, s1);
    else
        snprintf(out->verdict, sizeof out->verdict, "BORDERLINE (frac %.2f, %d tracks -- rerun/denser)", out->frac, nk);
    free(ids);
    return 1;
}

/* ---------------- stage 5/7: IP-ID same-box (router == injector?) ---------------- */
int stage_samebox(int rawfd, cap_t *cap, uint32_t tgt_be, int dport, uint16_t sport, uint32_t src_be,
                  const char *router_ip, int ttl, const uint8_t *ch, int chlen, int secs, samebox_t *out) {
    memset(out, 0, sizeof *out);
    snprintf(out->router_ip, sizeof out->router_ip, "%s", router_ip);
    out->ttl = ttl;
    uint32_t rip_be = inet_addr(router_ip);
    cap_reset(cap);
    double t_end = now_s() + secs;
    while (now_s() < t_end) {
        send_tcp(rawfd, src_be, tgt_be, sport, dport, rnd32(), 0, F_SYN, ttl, NULL, 0);       /* router counter */
        send_tcp(rawfd, src_be, tgt_be, sport, dport, rnd32(), rnd32(), F_PA, 64, ch, chlen); /* injector reset */
        msleep(25);
    }
    msleep(500);
    /* build router-counter series (icmp from router_ip) and reset series */
    icmp_ev *ic; int ni = cap_icmps(cap, &ic);
    rst_ev  *rs; int nr = cap_rsts(cap, &rs);
    double *rt = malloc(ni * sizeof(double)); int *rv = malloc(ni * sizeof(int)); int nR = 0;
    for (int i = 0; i < ni; i++) if (ic[i].rtr == rip_be) { rt[nR] = ic[i].ts; rv[nR] = ic[i].id; nR++; }
    out->router_samples = nR; out->reset_samples = nr;
    if (nR < 10) { snprintf(out->verdict, sizeof out->verdict, "ROUTER-SILENT (rate-limited / hidden)"); free(rt); free(rv); return 0; }
    if (nr < 10) { snprintf(out->verdict, sizeof out->verdict, "NO-RESETS (trigger did not fire)"); free(rt); free(rv); return 0; }
    int rmin = 65536, rmax = -1; for (int i = 0; i < nR; i++) { if (rv[i] < rmin) rmin = rv[i]; if (rv[i] > rmax) rmax = rv[i]; }
    out->router_span = rmax - rmin;
    /* interpolate router counter at each reset time (bracket within 0.2s); diff = reset - router */
    int *raw = malloc(nr * sizeof(int)); double *rawt = malloc(nr * sizeof(double)); int nraw = 0;
    for (int i = 0; i < nr; i++) {
        double tr = rs[i].ts; int bi = -1, ai = -1;
        for (int j = 0; j < nR; j++) { if (rt[j] <= tr) bi = j; else { ai = j; break; } }
        if (bi < 0 || ai < 0) continue;
        if (tr - rt[bi] > 0.20 || rt[ai] - tr > 0.20) continue;
        double dtt = rt[ai] - rt[bi]; int step = (rv[ai] - rv[bi]) & 0xffff; if (step > 32768) step -= 65536;
        int v = ((int)(rv[bi] + step * (tr - rt[bi]) / (dtt > 0 ? dtt : 1)) % 65536 + 65536) % 65536;
        raw[nraw] = (((int)rs[i].id - v) % 65536 + 65536) % 65536; rawt[nraw] = tr; nraw++;
    }
    if (nraw < 8) { snprintf(out->verdict, sizeof out->verdict, "INCONCLUSIVE (too few bracketed resets)"); goto done; }
    double chance = nraw * (1001.0 / 65536.0);
    int best_o = 0, best_c = -1;
    for (int o = 0; o < 65536; o += 50) { int cnt = 0; for (int i = 0; i < nraw; i++) if (cdist(raw[i], o) <= 500) cnt++; if (cnt > best_c) { best_c = cnt; best_o = o; } }
    out->best_offset = best_o;
    snprintf(out->offset_hits, sizeof out->offset_hits, "%d/%d", best_c, nraw);
    int third = nraw / 3, seg[3] = {0, 0, 0};
    for (int i = 0; i < nraw; i++) { int s = (third && i >= 2 * third) ? 2 : (third && i >= third) ? 1 : 0; if (cdist(raw[i], best_o) <= 500) seg[s]++; }
    snprintf(out->thirds, sizeof out->thirds, "%d|%d|%d", seg[0], seg[1], seg[2]);
    {
        int mn = seg[0], mx = seg[0]; for (int i = 1; i < 3; i++) { if (seg[i] < mn) mn = seg[i]; if (seg[i] > mx) mx = seg[i]; }
        int aligned = best_c > 5 * chance;
        int stable = aligned && mn >= 0.4 * mx && mn > chance / 3;
        if (aligned && stable) snprintf(out->verdict, sizeof out->verdict, "SAME-BOX (locked %dx chance) -- router IS injector", (int)(best_c / (chance > 1 ? chance : 1)));
        else if (aligned) snprintf(out->verdict, sizeof out->verdict, "SEPARATE (offset drifts %s => two counters)", out->thirds);
        else snprintf(out->verdict, sizeof out->verdict, "SEPARATE (no offset aligns; best ~chance)");
    }
done:
    free(raw); free(rawt); free(rt); free(rv);
    return 1;
}
