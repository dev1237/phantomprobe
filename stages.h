/* stages.h -- raw stages 3-7 (need root + libpcap). All share the per-target
 * fixed source port passed in from main (route-consistent "Paris" path). */
#ifndef STAGES_H
#define STAGES_H
#include <stdint.h>
#include "rawnet.h"

typedef struct {
    int  onset;                 /* injector hop distance; 0 if none found */
    char onset_router[32];      /* router IP at the onset hop             */
    int  path_len;
    char route[40][32];         /* route[ttl] router ip (ttl < 40)        */
} loc_t;

int stage_localize(int rawfd, cap_t *cap, uint32_t tgt_be, const char *tgt_ip, int dport, uint16_t sport,
                   uint32_t src_be, const uint8_t *ch, int chlen, int maxttl, loc_t *out);

typedef struct { char verdict[16]; char survived[48]; char dropped[80]; char tested[48]; } surv_t;
int stage_survival(cap_t *cap, uint32_t tgt_be, const char *tgt_ip, int dport, uint16_t sport,
                   const uint8_t *ben, int blen, const uint8_t *ch, int chlen,
                   int onset, int path_len, surv_t *out);

typedef struct { int resets; double frac; int tracks; char sizes[80]; char verdict[72]; } backup_t;
int stage_backup(int rawfd, cap_t *cap, uint32_t tgt_be, int dport, uint32_t src_be,
                 const uint8_t *ch, int chlen, int n, backup_t *out);

typedef struct { char router_ip[32]; int ttl; int router_samples; int reset_samples;
                 int router_span; int best_offset; char offset_hits[24]; char thirds[24];
                 char verdict[96]; } samebox_t;
/* dump_path (or NULL): if set, write the raw IP-ID evidence -- every router-counter
 * sample and every injected-reset sample, with each reset's offset-from-router and a
 * match flag -- so the SAME-BOX/SEPARATE verdict can be audited/visualised. */
int stage_samebox(int rawfd, cap_t *cap, uint32_t tgt_be, int dport, uint16_t sport, uint32_t src_be,
                  const char *router_ip, int ttl, const uint8_t *ch, int chlen, int secs,
                  const char *dump_path, samebox_t *out);

/* ---- UDP localization (DNS/STUN): mechanism-agnostic (drop OR injected reply) ----
 * A UDP censor may DROP silently, or INJECT a forged UDP response / ICMP-unreachable.
 * When it injects, that packet has a TTL + IP-ID -- so onset + same-box/count come back
 * (STUNTrace / DNS-trace lineage). When it purely drops, we localize the drop hop by
 * absence (benign survives the hop, forbidden no longer does). */
typedef struct {
    char mechanism[24];      /* DROP / RESPONSE-INJECT / ICMP-UNREACH-INJECT / RESPONSE+ICMP-INJECT */
    int  onset;              /* injector hop (injected) OR drop hop (drop); 0 if not localized */
    char onset_router[32];   /* router IP at that hop */
    int  path_len;
    char route[40][32];
    int  inj_samples;        /* injected replies captured in the dense burst */
    int  inj_tracks;         /* distinct IP-ID counters among injected replies */
    int  ttl_mirrored;       /* 1 = injector copies our probe TTL -> onset unreliable */
    char inj_verdict[80];    /* SINGLE / MULTIPLE injectors / N/A (pure drop) */
    char note[96];
} udploc_t;
int stage_udp_locate(int rawfd, cap_t *cap, uint32_t tgt_be, const char *tgt_ip,
                     int dport, uint16_t sport, uint32_t src_be,
                     const uint8_t *forb, int flen, const uint8_t *ben, int blen,
                     int maxttl, udploc_t *out);

#endif /* STAGES_H */
