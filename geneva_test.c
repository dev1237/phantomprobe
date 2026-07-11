/* geneva_test.c -- prove the UAE runs TWO parallel in-path injectors (not China's
 * hidden-backup-in-depth). Method: many parallel REAL TCP connections (kernel sockets,
 * so no server-RST confound), each sending the forbidden ClientHello, optionally split
 * into K in-order segments (a Geneva-style reassembly stress). We capture the injected
 * RSTs densely with libpcap and separate them into IP-ID counter tracks.
 *
 *   China (censorship-in-depth): plain ClientHello -> ONE counter (primary); the backup
 *     is hidden and only appears when the primary is evaded.
 *   UAE  (this test): plain ClientHello -> TWO counters at once => two boxes fire in
 *     PARALLEL, nothing hidden, no "backup".
 *
 * Build:  cc -O2 -std=c11 geneva_test.c rawnet.o net.o -lpcap -lpthread -o geneva_test
 * Run  :  sudo ./geneva_test <target> <sni> [threads] [secs] [segments]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "phantomprobe.h"
#include "rawnet.h"

static volatile int g_run;
static uint32_t g_dst_be;
static const unsigned char *g_ch; static int g_chlen; static int g_seg;

static int conn_timeout(uint32_t dst_be, int port, double to) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port); sa.sin_addr.s_addr = dst_be;
    int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (r != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (r != 0) {
        fd_set w; FD_ZERO(&w); FD_SET(fd, &w);
        struct timeval tv; tv.tv_sec = (int)to; tv.tv_usec = (int)((to - (int)to) * 1e6);
        if (select(fd + 1, NULL, &w, NULL, &tv) <= 0) { close(fd); return -1; }
        int err = 0; socklen_t el = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, 0);
    return fd;
}

static void *worker(void *_arg) {
    (void)_arg;
    while (g_run) {
        int fd = conn_timeout(g_dst_be, 443, 2.0);
        if (fd < 0) { usleep(20000); continue; }
        int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (g_seg <= 1) {
            if (send(fd, g_ch, g_chlen, 0) < 0) { /* reset already */ }
        } else {
            int sz = (g_chlen + g_seg - 1) / g_seg;
            for (int o = 0; o < g_chlen; o += sz) {
                int n = g_chlen - o; if (n > sz) n = sz;
                if (send(fd, g_ch + o, n, 0) < 0) break;
                usleep(1200);   /* force a separate in-order segment */
            }
        }
        usleep(60000);          /* let the injected RST arrive on the wire */
        close(fd);
    }
    return NULL;
}

/* separate time-ordered IP-IDs into rising counter tracks (one track = one box) */
static int sep_tracks(const uint16_t *ids, int n, int maxstep, int *sizes, int cap) {
    static int tlast[512], tcnt[512]; int nt = 0;
    for (int k = 0; k < n; k++) {
        int best = -1, bstep = 0;
        for (int j = 0; j < nt; j++) {
            int step = ((int)ids[k] - tlast[j]) & 0xffff;
            if (step > 0 && step < maxstep && (best < 0 || step < bstep)) { best = j; bstep = step; }
        }
        if (best < 0) { if (nt < 512) { tlast[nt] = ids[k]; tcnt[nt] = 1; nt++; } }
        else { tlast[best] = ids[k]; tcnt[best]++; }
    }
    int m = 0; for (int j = 0; j < nt; j++) if (tcnt[j] >= 5 && m < cap) sizes[m++] = tcnt[j];
    return m;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <target> <sni> [threads=24] [secs=20] [segments=1]\n", argv[0]); return 2; }
    if (geteuid() != 0) { fprintf(stderr, "run as root (libpcap)\n"); return 2; }
    const char *dst = argv[1], *sni = argv[2];
    int threads = argc > 3 ? atoi(argv[3]) : 24;
    int secs    = argc > 4 ? atoi(argv[4]) : 20;
    g_seg       = argc > 5 ? atoi(argv[5]) : 1;
    g_dst_be = inet_addr(dst);
    static unsigned char ch[1024]; g_chlen = build_client_hello(sni, ch, sizeof ch); g_ch = ch;

    char dev[64]; if (default_dev(dev, sizeof dev) != 0) { fprintf(stderr, "no dev\n"); return 1; }
    cap_t *cap = cap_start(dev, g_dst_be);
    if (!cap) { fprintf(stderr, "pcap open failed\n"); return 1; }

    printf("=== %s  sni=%s  threads=%d  secs=%d  segments=%d (%s) ===\n",
           dst, sni, threads, secs, g_seg, g_seg <= 1 ? "plain ClientHello" : "K in-order segments");
    g_run = 1;
    pthread_t th[256]; if (threads > 256) threads = 256;
    for (int i = 0; i < threads; i++) pthread_create(&th[i], NULL, worker, NULL);
    sleep(secs);
    g_run = 0;
    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
    usleep(500000);

    rst_ev *rs; int nr = cap_rsts(cap, &rs);   /* time-ordered */
    uint16_t *ids = malloc((nr ? nr : 1) * sizeof(uint16_t));
    for (int i = 0; i < nr; i++) ids[i] = rs[i].id;
    int inc = 0, tot = 0;
    for (int i = 0; i + 1 < nr; i++) { int s = ((int)ids[i+1] - ids[i]) & 0xffff; if (s > 0 && s < 32768) inc++; tot++; }
    double frac = tot ? (double)inc / tot : 0;
    int sizes[16]; int nk = sep_tracks(ids, nr, 12000, sizes, 16);
    int s0 = 0, s1 = 0; for (int i = 0; i < nk; i++) { if (sizes[i] > s0) { s1 = s0; s0 = sizes[i]; } else if (sizes[i] > s1) s1 = sizes[i]; }

    (void)nk; (void)s0; (void)s1; (void)sizes;
    /* TTL histogram of the injected RSTs: two boxes at different hops -> two TTL peaks.
     * This is counter-speed-independent, so it survives where the IP-ID method blurs. */
    int ttlh[256] = {0};
    for (int i = 0; i < nr; i++) ttlh[rs[i].ttl]++;
    int p1 = 0, c1 = 0;
    for (int t = 0; t < 256; t++) if (ttlh[t] > c1) { c1 = ttlh[t]; p1 = t; }
    /* a real second injection hop = a cluster of RSTs whose TTL is FAR (>3) from the main
     * peak; +/-1 around p1 is just path jitter (seen even for a single-box target). */
    int far = 0, p2 = -1, c2 = 0;
    for (int t = 0; t < 256; t++) if (t < p1 - 3 || t > p1 + 3) { far += ttlh[t]; if (ttlh[t] > c2) { c2 = ttlh[t]; p2 = t; } }
    int peaks = (far >= 0.15 * nr) ? 2 : 1;
    printf("injected RSTs captured : %d  (%.0f/s)\n", nr, secs ? (double)nr / secs : 0);
    printf("monotone-fraction      : %.2f   (IP-ID counter blurs on real conns; use TTL below)\n", frac);
    printf("RST TTL peaks (>=10%%)  : %d  -> ", peaks);
    for (int t = 0; t < 256; t++) if (ttlh[t] >= 0.10 * nr) printf("ttl=%d:%d(%.0f%%)  ", t, ttlh[t], 100.0 * ttlh[t] / nr);
    printf("\n");
    if (nr < 20) printf("VERDICT: too few RSTs (target unresponsive / evaded)\n");
    else if (peaks >= 2) printf("VERDICT: two RST-TTL clusters (ttl %d & %d) => two injectors at DIFFERENT hops\n", p1, p2);
    else printf("VERDICT: ONE TTL cluster (ttl %d, +/-1 jitter) => the injector(s) sit at a SINGLE hop; co-located boxes can't be split by TTL (use the dense bare-PA IP-ID method)\n", p1);
    cap_stop(cap); free(ids);
    return 0;
}
