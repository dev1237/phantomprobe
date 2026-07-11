/* classify.c -- stage 1 (censorship taxonomy) + stage 2 (residual filtering),
 * a faithful C port of censor_classify.classify()/rf_test(). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "phantomprobe.h"

/* probe helpers: trigger call sets is_trigger=1 (matters only for STUN Allocate-vs-Binding). */
#define PT(name)  proto_probe(proto, ip, (name), 1, to)   /* trigger  */
#define PC(name)  proto_probe(proto, ip, (name), 0, to)   /* control  */

/* stage 2: residual filtering, only called for a CENSORED target. */
static void rf_test(const char *ip, const char *trig, const char *ctrl,
                    proto_t proto, double to, char *out, int cap) {
    /* re-baseline: benign must be spotless right now, else RF is undecidable */
    int pre_block = 0;
    for (int i = 0; i < 4; i++) if (is_block(PC(ctrl))) pre_block++;
    if (pre_block > 0) { snprintf(out, cap, "RF-UNDECIDABLE(dirty-baseline)"); return; }
    /* fire trigger until it bites (max 15) */
    int bit = 0;
    for (int i = 0; i < 15; i++) if (is_block(PT(trig))) { bit = 1; break; }
    if (!bit) { snprintf(out, cap, "RF-INCONCLUSIVE(no-bite)"); return; }
    /* hammer benign, timestamped */
    double t0 = now_s(); double first_block = -1, recovered = -1; int streak = 0;
    for (int i = 0; i < 160; i++) {
        double t = now_s() - t0;
        int blk = is_block(PC(ctrl));
        if (blk) { if (first_block < 0) first_block = t; streak = 0; }
        else {
            streak++;
            if (first_block < 0 && streak >= 3) { snprintf(out, cap, "STATELESS"); return; }
            if (first_block >= 0 && streak >= 3) { recovered = t; break; }
        }
        if (t > 45.0) break;
        usleep(200000);
    }
    if (first_block < 0) { snprintf(out, cap, "STATELESS"); return; }
    if (recovered >= 0) { snprintf(out, cap, "STATEFUL-RF(W=%.1fs)", recovered - first_block); return; }
    snprintf(out, cap, "STATEFUL-PERSIST(>45s)");
}

void classify(const char *ip, const char *trig, const char *ctrl,
              proto_t proto, int N, clsrow_t *row) {
    memset(row, 0, sizeof *row);
    double to = (proto == PROTO_HTTPS) ? 5.0 : (proto_is_udp(proto) ? 3.0 : 4.0);
    strcpy(row->strength, "-"); strcpy(row->mechanism, "-"); strcpy(row->rf, "-");

    /* P0 baseline */
    const int NB = 6; int base_allow = 0, base_block = 0;
    for (int i = 0; i < NB; i++) {
        outcome_t o = PC(ctrl);
        if (o == O_ALLOW) base_allow++;
        if (is_block(o)) base_block++;
    }
    row->base_allow = base_allow; row->base_block = base_block;
    if (base_allow == 0) {
        strcpy(row->verdict, "UNREACHABLE");
        snprintf(row->note, sizeof row->note, "benign control never completed");
        return;
    }

    /* P1 differential */
    int c_block = 0, t_block = 0, c_rst = 0, t_rst = 0, t_bp = 0;
    for (int i = 0; i < N; i++) {
        outcome_t oc = PC(ctrl);
        outcome_t ot = PT(trig);
        if (is_block(oc)) c_block++;
        if (is_block(ot)) t_block++;
        if (is_inject(oc)) c_rst++;
        if (is_inject(ot)) t_rst++;
        if (ot == O_BLOCKPAGE) t_bp++;
    }
    row->N = N; row->ctrl_block = c_block; row->trig_block = t_block;
    row->ctrl_rst = c_rst; row->trig_rst = t_rst;
    int excess = t_block - c_block;
    double trig_rate = (double)t_block / N;
    row->trig_rate = trig_rate;
    int margin = N / 4; if (margin < 3) margin = 3;

    int floor2 = N / 2; if (base_block + 2 > floor2) floor2 = base_block + 2;
    if (c_block >= floor2 && excess < margin) {
        strcpy(row->verdict, "PATH-LOSS");
        snprintf(row->note, sizeof row->note, "benign and trigger both lossy (excess<%d)", margin);
        return;
    }
    if (excess < margin) {
        strcpy(row->verdict, "CLEAN");
        snprintf(row->note, sizeof row->note, "trigger ~= control; keyword not censored here");
        return;
    }

    /* CENSORED -- grade strength and mechanism */
    double net = trig_rate - (double)c_block / N;
    strcpy(row->strength, net >= 0.9 ? "DETERMINISTIC" : (net >= 0.15 ? "PROBABILISTIC" : "WEAK"));
    int inj_excess = t_rst - c_rst;
    int tmo_excess = (t_block - t_rst) - (c_block - c_rst);
    if (inj_excess >= tmo_excess && inj_excess > 0) {
        int t_rstonly = t_rst - t_bp;
        strcpy(row->mechanism, (t_bp >= t_rstonly && t_bp > 0) ? "BLOCKPAGE" : "RST-INJECTION");
    } else {
        strcpy(row->mechanism, "DROP(timeout)");
    }
    strcpy(row->verdict, "CENSORED");
    rf_test(ip, trig, ctrl, proto, to, row->rf, sizeof row->rf);
}
