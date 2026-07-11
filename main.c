/* main.c -- driver: ordered pipeline on a route-consistent fixed source port,
 * navigable timestamped output tree, self-verify. Stages 1-2 always run
 * (portable, no root); stages 3-7 run when we have root + libpcap. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "phantomprobe.h"
#include "rawnet.h"
#include "stages.h"

#define MAXT 8192
typedef struct { char ip[64]; char trig[128]; } target_t;

static int mkpath(const char *path) {
    char tmp[1024]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
    return (mkdir(tmp, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}
static int load_targets(const char *file, target_t *t, int cap) {
    FILE *f = fopen(file, "r"); if (!f) { perror(file); return -1; }
    char line[256]; int n = 0;
    while (fgets(line, sizeof line, f) && n < cap) {
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        char ip[64] = {0}, tr[128] = {0};
        if (sscanf(s, "%63s %127s", ip, tr) < 1) continue;
        snprintf(t[n].ip, sizeof t[n].ip, "%s", ip);
        snprintf(t[n].trig, sizeof t[n].trig, "%s", tr[0] ? tr : "alhudood.net");
        n++;
    }
    fclose(f); return n;
}
static int is_private(const char *ip) {
    unsigned a, b; if (sscanf(ip, "%u.%u", &a, &b) < 2) return 1;
    return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 0 || a == 127;
}
static long count_rows(const char *p) { FILE *f = fopen(p, "r"); if (!f) return -1; long n = -1; char l[8192]; while (fgets(l, sizeof l, f)) n++; fclose(f); return n < 0 ? 0 : n; }
static int file_ok(const char *p) { return count_rows(p) >= 0; }

static int verify_run(const char *base, const char *mba) {
    char cen[1200], rf[1200], loc[1300], io[1300], bk[1300], rvm[1300], bb[1300], man[1200];
    snprintf(cen, sizeof cen, "%s/censored_targets.csv", base);
    snprintf(rf,  sizeof rf,  "%s/rf_targets.csv", base);
    snprintf(man, sizeof man, "%s/manifest.json", base);
    snprintf(loc, sizeof loc, "%s/injector_localized.csv", mba);
    snprintf(io,  sizeof io,  "%s/inpath_offpath.csv", mba);
    snprintf(bk,  sizeof bk,  "%s/backup_injector.csv", mba);
    snprintf(rvm, sizeof rvm, "%s/ipid_router_vs_middlebox.csv", mba);
    snprintf(bb,  sizeof bb,  "%s/backbone_middlebox.csv", mba);
    typedef struct { const char *name; int ok; } check_t;
    long ncen = count_rows(cen);
    check_t chk[13] = {
        {"censored_targets.csv exists & non-empty", ncen > 0},
        {"rf_targets.csv exists", file_ok(rf)},
        {"manifest.json present", file_ok(man)},
        {"injector_localized.csv present", file_ok(loc)},
        {"inpath_offpath.csv present", file_ok(io)},
        {"backup_injector.csv present", file_ok(bk)},
        {"ipid_router_vs_middlebox.csv present", file_ok(rvm)},
        {"backbone_middlebox.csv present", file_ok(bb)},
        {"rf rows == censored rows", count_rows(rf) == ncen},
        {"localized rows <= censored rows", file_ok(loc) ? count_rows(loc) <= ncen : 1},
        {"inpath rows <= censored rows", file_ok(io) ? count_rows(io) <= ncen : 1},
        {"router-vs-MB rows <= inpath rows", (file_ok(rvm) && file_ok(io)) ? count_rows(rvm) <= count_rows(io) : 1},
        {"no negative counts", ncen >= 0 && count_rows(rf) >= 0},
    };
    printf("\n[verify] 13 self-check passes:\n"); int all = 1;
    for (int i = 0; i < 13; i++) { printf("  pass %2d: [%s] %s\n", i + 1, chk[i].ok ? "OK" : "FAIL", chk[i].name); all &= chk[i].ok; }
    printf("[verify] %s\n", all ? "ALL 13 PASSES OK" : "SOME CHECKS FAILED");
    return all;
}

int main(int argc, char **argv) {
    const char *tfile = NULL, *country = "UAE"; int is_https = 1, N = 8, maxttl = 20, secs = 20;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--targets") && i + 1 < argc) tfile = argv[++i];
        else if (!strcmp(argv[i], "--protocol") && i + 1 < argc) is_https = strcmp(argv[++i], "http") != 0;
        else if (!strcmp(argv[i], "--country") && i + 1 < argc) country = argv[++i];
        else if (!strcmp(argv[i], "--N") && i + 1 < argc) N = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--maxttl") && i + 1 < argc) maxttl = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--secs") && i + 1 < argc) secs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--help")) { printf("usage: phantomprobe --targets FILE [--protocol http|https] [--country LABEL] [--N n] [--maxttl t] [--secs s]\n  --country LABEL is only an output-folder tag; it does not restrict targets. The tool works from/for any country.\n"); return 0; }
    }
    if (!tfile) { fprintf(stderr, "need --targets FILE (see --help)\n"); return 2; }
    srand((unsigned)time(NULL) ^ getpid());
    static target_t T[MAXT];
    int nt = load_targets(tfile, T, MAXT);
    if (nt <= 0) { fprintf(stderr, "no targets\n"); return 2; }
    const char *proto = is_https ? "https" : "http"; int dport = is_https ? 443 : 80;

    char stamp[32]; time_t tt = time(NULL); struct tm g; gmtime_r(&tt, &g);
    strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%SZ", &g);
    char base[512], mba[900];
    snprintf(base, sizeof base, "outputs_pipeline/%s_%s_%s", stamp, country, proto);
    snprintf(mba, sizeof mba, "%s/middlebox_analysis_%s_%s_%s", base, proto, country, stamp);
    if (mkpath(mba) != 0) { fprintf(stderr, "cannot create output tree\n"); return 1; }

    char p[8][1024];
    snprintf(p[0], 1024, "%s/censored_targets.csv", base);
    snprintf(p[1], 1024, "%s/rf_targets.csv", base);
    snprintf(p[2], 1024, "%s/injector_localized.csv", mba);
    snprintf(p[3], 1024, "%s/inpath_offpath.csv", mba);
    snprintf(p[4], 1024, "%s/backup_injector.csv", mba);
    snprintf(p[5], 1024, "%s/ipid_router_vs_middlebox.csv", mba);
    snprintf(p[6], 1024, "%s/backbone_middlebox.csv", mba);
    snprintf(p[7], 1024, "%s/manifest.json", base);
    FILE *fc = fopen(p[0], "w"), *fr = fopen(p[1], "w"), *fl = fopen(p[2], "w"), *fi = fopen(p[3], "w"),
         *fbk = fopen(p[4], "w"), *frvm = fopen(p[5], "w"), *fbb = fopen(p[6], "w");
    if (!fc || !fr || !fl || !fi || !fbk || !frvm || !fbb) { perror("open csv"); return 1; }
    fprintf(fc, "target,channel,sport,verdict,strength,mechanism,trig_rate,base_allow,note\n");
    fprintf(fr, "target,channel,sport,verdict,rf_status,rf_duration_s\n");
    fprintf(fl, "target,channel,sport,onset_ttl,onset_router,path_len,note\n");
    fprintf(fi, "target,channel,sport,onset_ttl,onset_router,hops_tested,verdict,forbidden_survived,benign_only_dropped\n");
    fprintf(fbk, "target,channel,sport,resets,monotone_frac,tracks,track_sizes,verdict\n");
    fprintf(frvm, "target,channel,sport,router_ip,ttl,router_samples,reset_samples,router_span,best_offset,offset_hits,thirds,verdict\n");
    fprintf(fbb, "target,channel,sport,hop_ttl,router_ip,router_samples,reset_samples,best_offset,offset_hits,thirds,verdict\n");

    int can_raw = (geteuid() == 0); int rawfd = -1; char dev[64] = "";
    if (can_raw) { rawfd = raw_send_sock(); if (default_dev(dev, sizeof dev) != 0) dev[0] = 0; }
    if (!can_raw) fprintf(stderr, "[note] not root: running stages 1-2 only (portable). re-run with sudo for stages 3-7.\n");
    else if (rawfd < 0) { fprintf(stderr, "[warn] raw socket failed; stages 1-2 only\n"); can_raw = 0; }

    int n_cen = 0, n_in = 0, n_off = 0;
    printf("[*] %d targets, protocol=%s, country=%s, raw_stages=%s\n", nt, proto, country, can_raw ? "on" : "off");
    for (int i = 0; i < nt; i++) {
        int sport = 1025 + rand() % 63000;   /* PARIS: fixed for every stage of this target */
        clsrow_t r; classify(T[i].ip, T[i].trig, "example.com", is_https, N, &r);
        fprintf(fc, "%s,%s,%d,%s,%s,%s,%.2f,%d,%s\n", T[i].ip, proto, sport, r.verdict, r.strength, r.mechanism, r.trig_rate, r.base_allow, r.note);
        char dur[16] = ""; const char *w = strstr(r.rf, "W="); if (w) snprintf(dur, sizeof dur, "%.1f", atof(w + 2));
        fprintf(fr, "%s,%s,%d,%s,%s,%s\n", T[i].ip, proto, sport, r.verdict, r.rf, dur);
        int censored = strcmp(r.verdict, "CENSORED") == 0;
        printf("  [%3d/%3d] %-18s %-11s %-14s %-14s rf=%s\n", i + 1, nt, T[i].ip, r.verdict, r.strength, r.mechanism, r.rf);
        if (!censored) continue;
        n_cen++;
        if (!can_raw) { fprintf(fl, "%s,%s,%d,,,,\"needs root for stages 3-7\"\n", T[i].ip, proto, sport); continue; }

        uint32_t tgt_be = inet_addr(T[i].ip); uint32_t src_be = local_ip_for(tgt_be);
        if (!src_be) { fprintf(fl, "%s,%s,%d,,,,\"no route/src ip\"\n", T[i].ip, proto, sport); continue; }
        cap_t *cap = cap_start(dev, tgt_be);
        if (!cap) { fprintf(fl, "%s,%s,%d,,,,\"pcap open failed\"\n", T[i].ip, proto, sport); continue; }
        unsigned char ch[1024], ben[1024];
        int chlen = is_https ? build_client_hello(T[i].trig, ch, sizeof ch) : build_http_get(T[i].trig, ch, sizeof ch);
        int blen  = is_https ? build_client_hello("example.com", ben, sizeof ben) : build_http_get("example.com", ben, sizeof ben);

        loc_t loc; stage_localize(rawfd, cap, tgt_be, T[i].ip, dport, sport, src_be, ch, chlen, maxttl, &loc);
        fprintf(fl, "%s,%s,%d,%d,%s,%d,%s\n", T[i].ip, proto, sport, loc.onset, loc.onset_router, loc.path_len, loc.onset ? "" : "no injected RST on this path");
        if (loc.onset == 0) { cap_stop(cap); continue; }

        surv_t sv; stage_survival(cap, tgt_be, T[i].ip, dport, sport, ben, blen, ch, chlen, loc.onset, loc.path_len, &sv);
        fprintf(fi, "%s,%s,%d,%d,%s,%s,%s,%s,%s\n", T[i].ip, proto, sport, loc.onset, loc.onset_router, sv.tested, sv.verdict, sv.survived, sv.dropped);
        if (!strcmp(sv.verdict, "OFF-PATH")) n_off++;

        backup_t bk; stage_backup(rawfd, cap, tgt_be, dport, src_be, ch, chlen, 150, &bk);
        fprintf(fbk, "%s,%s,%d,%d,%.2f,%d,%s,%s\n", T[i].ip, proto, sport, bk.resets, bk.frac, bk.tracks, bk.sizes, bk.verdict);

        if (!strcmp(sv.verdict, "IN-PATH-DROP")) {
            n_in++;
            samebox_t sb; stage_samebox(rawfd, cap, tgt_be, dport, sport, src_be, loc.onset_router, loc.onset, ch, chlen, secs, &sb);
            fprintf(frvm, "%s,%s,%d,%s,%d,%d,%d,%d,%d,%s,%s,%s\n", T[i].ip, proto, sport, sb.router_ip, sb.ttl, sb.router_samples, sb.reset_samples, sb.router_span, sb.best_offset, sb.offset_hits, sb.thirds, sb.verdict);
            for (int up = loc.onset - 1; up >= loc.onset - 2 && up >= 1; up--) {
                if (!loc.route[up][0] || is_private(loc.route[up])) continue;
                samebox_t bbx; stage_samebox(rawfd, cap, tgt_be, dport, sport, src_be, loc.route[up], up, ch, chlen, secs, &bbx);
                fprintf(fbb, "%s,%s,%d,%d,%s,%d,%d,%d,%s,%s,%s\n", T[i].ip, proto, sport, up, bbx.router_ip, bbx.router_samples, bbx.reset_samples, bbx.best_offset, bbx.offset_hits, bbx.thirds, bbx.verdict);
            }
        }
        cap_stop(cap);
    }
    fclose(fc); fclose(fr); fclose(fl); fclose(fi); fclose(fbk); fclose(frvm); fclose(fbb);
    if (rawfd >= 0) close(rawfd);

    FILE *fm = fopen(p[7], "w");
    if (fm) {
        fprintf(fm, "{\n  \"generated_utc\": \"%s\",\n  \"country\": \"%s\",\n  \"protocol\": \"%s\",\n"
                    "  \"targets\": %d,\n  \"censored\": %d,\n  \"in_path\": %d,\n  \"off_path\": %d,\n"
                    "  \"raw_stages\": %s,\n"
                    "  \"route_consistency\": \"one fixed source port per target across all stages (Paris)\",\n"
                    "  \"order\": [\"1 censored\",\"2 residual-filtering\",\"3 localize/onset\",\"4 in/off-path\",\"6 backup\",\"5 router==MB\",\"7 backbone\"]\n}\n",
                stamp, country, proto, nt, n_cen, n_in, n_off, can_raw ? "true" : "false");
        fclose(fm);
    }
    printf("\n[+] wrote run tree at: %s\n[+] censored=%d  in-path=%d  off-path=%d\n", base, n_cen, n_in, n_off);
    verify_run(base, mba);
    return 0;
}
