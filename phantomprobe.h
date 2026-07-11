/* phantomprobe.h -- portable C censorship-middlebox prober (shared decls).
 * Stages 1-2 (this header's probe/classify API) use only normal TCP sockets,
 * so they build and run anywhere with no root and no libpcap. Stages 3-7 (raw
 * sockets + libpcap) are added on top and declared here as they land. */
#ifndef PHANTOMPROBE_H
#define PHANTOMPROBE_H
#include <stdint.h>
#include <stddef.h>

/* ---- trigger builders (exact byte-for-byte match of the Python reference) ---- */
int build_client_hello(const char *sni, unsigned char *out, int cap);
int build_http_get(const char *host, unsigned char *out, int cap);

/* ---- normalized probe outcomes ---- */
typedef enum { O_ALLOW, O_RST, O_TIMEOUT, O_REFUSED, O_BLOCKPAGE, O_EMPTY, O_ERR } outcome_t;
const char *outcome_name(outcome_t o);
int is_block(outcome_t o);    /* TIMEOUT | RST | BLOCKPAGE  (looks blocked)      */
int is_inject(outcome_t o);   /* RST | BLOCKPAGE            (cannot be mere loss) */

/* ---- stage 1-2: normal-socket probes + classifier ---- */
outcome_t https_probe(const char *ip, const char *sni, double timeout);
outcome_t http_probe (const char *ip, const char *host, double timeout);

/* real TCP connect, set IP_TTL, send payload (the TTL-limited trigger on a genuine
 * connection -- what actually makes the injector fire). Injected RST/ICMP are read
 * out of band via libpcap. returns 0 ok, <0 could not connect. */
/* restore_ttl=0 (onset): every packet stays at the low ttl, so a trigger below the
 *   injector never reaches it -> no injected RST. restore_ttl=1 (survival): only the
 *   ClientHello is TTL-limited; retransmits/ACK/close-RST go full-distance so non-SNI
 *   packets don't emit ICMP at the survival hop. */
int conn_send_ttl(const char *ip, int port, int sport, const unsigned char *payload, int plen,
                  int ttl, int restore_ttl, double timeout);

typedef struct {
    char verdict[24];     /* UNREACHABLE | PATH-LOSS | CLEAN | CENSORED           */
    char strength[16];    /* DETERMINISTIC | PROBABILISTIC | WEAK | -             */
    char mechanism[20];   /* RST-INJECTION | BLOCKPAGE | DROP(timeout) | -        */
    char rf[48];          /* STATELESS | STATEFUL-RF(W=..s) | STATEFUL-PERSIST... */
    int  base_allow, base_block;
    int  N, ctrl_block, trig_block, ctrl_rst, trig_rst;
    double trig_rate;
    char note[96];
} clsrow_t;

void classify(const char *ip, const char *trig, const char *ctrl,
              int is_https, int N, clsrow_t *row);

/* small shared util */
double now_s(void);

#endif /* PHANTOMPROBE_H */
