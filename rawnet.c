/* rawnet.c -- raw IPv4/TCP sender + libpcap capture. POSIX, needs root. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "rawnet.h"

/* BSD/macOS raw sockets want ip_len & ip_off in HOST byte order; Linux wants network order. */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define RAW_HOSTORDER 1
#endif

/* ---------------- checksums + header assembly ---------------- */
static uint16_t csum16(const uint8_t *d, int n, uint32_t init) {
    uint32_t s = init;
    for (int i = 0; i + 1 < n; i += 2) s += (d[i] << 8) | d[i + 1];
    if (n & 1) s += d[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static void p16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void p32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

int raw_send_sock(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);
    return fd;
}

uint32_t local_ip_for(uint32_t dst_be) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(53); sa.sin_addr.s_addr = dst_be;
    uint32_t ip = 0;
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) == 0) {
        struct sockaddr_in me; socklen_t l = sizeof me;
        if (getsockname(s, (struct sockaddr *)&me, &l) == 0) ip = me.sin_addr.s_addr;
    }
    close(s); return ip;
}

int default_dev(char *buf, int cap) {
    char err[PCAP_ERRBUF_SIZE]; pcap_if_t *alldevs = NULL;
    if (pcap_findalldevs(&alldevs, err) != 0 || !alldevs) return -1;
    /* pick first non-loopback device that is up */
    const char *chosen = NULL;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (d->flags & PCAP_IF_UP || !(d->flags & PCAP_IF_CONNECTION_STATUS)) { chosen = d->name; break; }
    }
    if (!chosen) chosen = alldevs->name;
    snprintf(buf, cap, "%s", chosen);
    pcap_freealldevs(alldevs);
    return 0;
}

int send_tcp(int fd, uint32_t src_be, uint32_t dst_be, uint16_t sport, uint16_t dport,
             uint32_t seq, uint32_t ack, uint8_t flags, uint8_t ttl,
             const uint8_t *payload, int paylen) {
    uint8_t pkt[1600]; int tcplen = 20 + (payload ? paylen : 0);
    int tot = 20 + tcplen;
    memset(pkt, 0, tot);
    /* IPv4 header */
    pkt[0] = 0x45; pkt[1] = 0;
#ifdef RAW_HOSTORDER
    *(uint16_t *)(pkt + 2) = (uint16_t)tot;        /* ip_len host order (BSD/macOS) */
    *(uint16_t *)(pkt + 6) = (uint16_t)0x4000;     /* ip_off host order, DF          */
#else
    p16(pkt + 2, tot);                             /* ip_len network order (Linux)   */
    p16(pkt + 6, 0x4000);
#endif
    p16(pkt + 4, rand() & 0xffff);        /* our IP id (ours, not measured) */
    pkt[8] = ttl; pkt[9] = 6;             /* proto TCP */
    memcpy(pkt + 12, &src_be, 4);
    memcpy(pkt + 16, &dst_be, 4);
    p16(pkt + 10, 0);                     /* ip checksum: kernel fills it in */
    /* TCP header */
    uint8_t *t = pkt + 20;
    p16(t + 0, sport); p16(t + 2, dport);
    p32(t + 4, seq);   p32(t + 8, ack);
    t[12] = 0x50; t[13] = flags;
    p16(t + 14, 0xffff);                  /* window */
    if (payload && paylen) memcpy(t + 20, payload, paylen);
    /* TCP checksum with pseudo-header */
    uint8_t pseudo[12];
    memcpy(pseudo, &src_be, 4); memcpy(pseudo + 4, &dst_be, 4);
    pseudo[8] = 0; pseudo[9] = 6; p16(pseudo + 10, tcplen);
    uint32_t s = 0;
    for (int i = 0; i < 12; i += 2) s += (pseudo[i] << 8) | pseudo[i + 1];
    p16(t + 16, 0);
    p16(t + 16, csum16(t, tcplen, s));
    struct sockaddr_in to; memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_addr.s_addr = dst_be;
    return sendto(fd, pkt, tot, 0, (struct sockaddr *)&to, sizeof to);
}

int send_udp(int fd, uint32_t src_be, uint32_t dst_be, uint16_t sport, uint16_t dport,
             uint8_t ttl, const uint8_t *payload, int paylen) {
    uint8_t pkt[1600]; int udplen = 8 + (payload ? paylen : 0);
    int tot = 20 + udplen;
    memset(pkt, 0, tot);
    pkt[0] = 0x45; pkt[1] = 0;
#ifdef RAW_HOSTORDER
    *(uint16_t *)(pkt + 2) = (uint16_t)tot;
    *(uint16_t *)(pkt + 6) = (uint16_t)0x4000;
#else
    p16(pkt + 2, tot);
    p16(pkt + 6, 0x4000);
#endif
    p16(pkt + 4, rand() & 0xffff);
    pkt[8] = ttl; pkt[9] = 17;            /* proto UDP */
    memcpy(pkt + 12, &src_be, 4);
    memcpy(pkt + 16, &dst_be, 4);
    p16(pkt + 10, 0);                     /* ip checksum: kernel fills it in */
    uint8_t *u = pkt + 20;
    p16(u + 0, sport); p16(u + 2, dport); p16(u + 4, udplen);
    if (payload && paylen) memcpy(u + 8, payload, paylen);
    /* UDP checksum with pseudo-header (optional in IPv4; we compute it) */
    uint8_t pseudo[12];
    memcpy(pseudo, &src_be, 4); memcpy(pseudo + 4, &dst_be, 4);
    pseudo[8] = 0; pseudo[9] = 17; p16(pseudo + 10, udplen);
    uint32_t s = 0;
    for (int i = 0; i < 12; i += 2) s += (pseudo[i] << 8) | pseudo[i + 1];
    p16(u + 6, 0);
    uint16_t ck = csum16(u, udplen, s);
    p16(u + 6, ck ? ck : 0xffff);          /* 0 means "no checksum"; use 0xffff instead */
    struct sockaddr_in to; memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_addr.s_addr = dst_be;
    return sendto(fd, pkt, tot, 0, (struct sockaddr *)&to, sizeof to);
}

/* ---------------- capture ---------------- */
#define CAPMAX 60000
struct cap {
    pcap_t *ph; int linkhdr; pthread_t th; volatile int running;
    pthread_mutex_t mu; uint32_t target;
    rst_ev *rst; int rn; icmp_ev *icmp; int in; inj_ev *inj; int jn;
};

static double tv2d(const struct timeval *tv) { return tv->tv_sec + tv->tv_usec / 1e6; }

static void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct cap *c = (struct cap *)user;
    int off = c->linkhdr;
    if ((int)h->caplen < off + 20) return;
    const u_char *ip = bytes + off;
    if ((ip[0] >> 4) != 4) return;
    int ihl = (ip[0] & 0x0f) * 4;
    if ((int)h->caplen < off + ihl + 8) return;
    uint8_t proto = ip[9];
    uint16_t ipid = (ip[4] << 8) | ip[5];
    uint32_t src, dst; memcpy(&src, ip + 12, 4); memcpy(&dst, ip + 16, 4);
    double ts = tv2d(&h->ts);
    if (proto == 6 && src == c->target) {           /* TCP from target */
        const u_char *tcp = ip + ihl;
        if (tcp[13] & F_RST) {
            pthread_mutex_lock(&c->mu);
            if (c->rn < CAPMAX) { c->rst[c->rn].ts = ts; c->rst[c->rn].id = ipid; c->rst[c->rn].ttl = ip[8]; c->rn++; }
            pthread_mutex_unlock(&c->mu);
        }
    } else if (proto == 1) {                          /* ICMP */
        const u_char *icmp = ip + ihl;
        if (icmp[0] == 11 && (int)h->caplen >= off + ihl + 8 + 20) {  /* time-exceeded + inner IP */
            const u_char *inner = icmp + 8;
            uint32_t idst; memcpy(&idst, inner + 16, 4);
            pthread_mutex_lock(&c->mu);
            if (c->in < CAPMAX) {
                c->icmp[c->in].ts = ts; c->icmp[c->in].rtr = src;
                c->icmp[c->in].id = ipid; c->icmp[c->in].inner_dst = idst; c->in++;
            }
            pthread_mutex_unlock(&c->mu);
        } else if (icmp[0] == 3 && (int)h->caplen >= off + ihl + 8 + 20) {  /* dest-unreachable = injected UDP "RST" */
            const u_char *inner = icmp + 8;                 /* quoted original packet */
            uint32_t idst; memcpy(&idst, inner + 16, 4);
            if (idst == c->target && inner[9] == 17) {      /* our UDP probe to target was refused */
                pthread_mutex_lock(&c->mu);
                if (c->jn < CAPMAX) {
                    c->inj[c->jn].ts = ts; c->inj[c->jn].id = ipid;     /* outer IP-ID = injector counter */
                    c->inj[c->jn].ttl = ip[8]; c->inj[c->jn].kind = 1; c->inj[c->jn].src = src; c->jn++;
                }
                pthread_mutex_unlock(&c->mu);
            }
        }
    } else if (proto == 17 && src == c->target) {     /* forged UDP response from target (spoofed) */
        pthread_mutex_lock(&c->mu);
        if (c->jn < CAPMAX) {
            c->inj[c->jn].ts = ts; c->inj[c->jn].id = ipid;
            c->inj[c->jn].ttl = ip[8]; c->inj[c->jn].kind = 0; c->inj[c->jn].src = src; c->jn++;
        }
        pthread_mutex_unlock(&c->mu);
    }
}

static void *cap_thread(void *arg) {
    struct cap *c = arg;
    while (c->running) pcap_dispatch(c->ph, -1, handler, (u_char *)c);
    return NULL;
}

cap_t *cap_start(const char *dev, uint32_t target_be) {
    struct cap *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->rst = malloc(CAPMAX * sizeof(rst_ev)); c->icmp = malloc(CAPMAX * sizeof(icmp_ev)); c->inj = malloc(CAPMAX * sizeof(inj_ev));
    c->target = target_be; pthread_mutex_init(&c->mu, NULL);
    char err[PCAP_ERRBUF_SIZE];
    c->ph = pcap_create(dev, err);
    if (!c->ph) { free(c->rst); free(c->icmp); free(c->inj); free(c); return NULL; }
    pcap_set_snaplen(c->ph, 128);
    pcap_set_promisc(c->ph, 0);
    pcap_set_timeout(c->ph, 40);
    pcap_set_immediate_mode(c->ph, 1);
    if (pcap_activate(c->ph) != 0) { pcap_close(c->ph); free(c->rst); free(c->icmp); free(c->inj); free(c); return NULL; }
    int dl = pcap_datalink(c->ph);
    c->linkhdr = (dl == DLT_EN10MB) ? 14 : (dl == DLT_NULL || dl == DLT_LOOP) ? 4 :
                 (dl == DLT_LINUX_SLL) ? 16 : 0;
    char filt[128]; char ipbuf[32];
    struct in_addr a; a.s_addr = target_be; snprintf(ipbuf, sizeof ipbuf, "%s", inet_ntoa(a));
    snprintf(filt, sizeof filt, "icmp or ((tcp or udp) and src host %s)", ipbuf);
    struct bpf_program bp;
    if (pcap_compile(c->ph, &bp, filt, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(c->ph, &bp); pcap_freecode(&bp);
    }
    c->running = 1;
    pthread_create(&c->th, NULL, cap_thread, c);
    usleep(200000);   /* let the capture warm up */
    return c;
}

void cap_reset(cap_t *c) { pthread_mutex_lock(&c->mu); c->rn = 0; c->in = 0; c->jn = 0; pthread_mutex_unlock(&c->mu); }
int cap_rsts(cap_t *c, rst_ev **out)  { *out = c->rst;  return c->rn; }
int cap_icmps(cap_t *c, icmp_ev **out){ *out = c->icmp; return c->in; }
int cap_injs(cap_t *c, inj_ev **out) { *out = c->inj; return c->jn; }

void cap_stop(cap_t *c) {
    if (!c) return;
    c->running = 0; pcap_breakloop(c->ph); pthread_join(c->th, NULL);
    pcap_close(c->ph); free(c->rst); free(c->icmp); free(c->inj);
    pthread_mutex_destroy(&c->mu); free(c);
}
