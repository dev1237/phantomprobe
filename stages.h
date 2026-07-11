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
int stage_samebox(int rawfd, cap_t *cap, uint32_t tgt_be, int dport, uint16_t sport, uint32_t src_be,
                  const char *router_ip, int ttl, const uint8_t *ch, int chlen, int secs, samebox_t *out);

#endif /* STAGES_H */
