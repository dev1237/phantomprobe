/* diag.c -- isolate raw send + pcap capture: fire N bare PA ClientHellos at a
 * known-censored target and report captured injected RSTs. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include "rawnet.h"
#include "phantomprobe.h"

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "195.229.213.67";
    const char *sni = argc > 2 ? argv[2] : "alhudood.net";
    const char *dev_arg = argc > 3 ? argv[3] : NULL;
    srand(time(NULL));
    uint32_t tgt = inet_addr(ip), src = local_ip_for(tgt);
    struct in_addr a; a.s_addr = src;
    char dev[64]; if (dev_arg) snprintf(dev, sizeof dev, "%s", dev_arg); else default_dev(dev, sizeof dev);
    printf("dev=%s  src=%s  tgt=%s\n", dev, inet_ntoa(a), ip);
    int fd = raw_send_sock(); printf("raw_send_sock=%d\n", fd);
    cap_t *c = cap_start(dev, tgt); printf("cap_start=%p\n", (void *)c);
    if (!c) { printf("cap open FAILED\n"); return 1; }
    unsigned char ch[1024]; int n = build_client_hello(sni, ch, sizeof ch);
    printf("clienthello_len=%d\n", n);
    uint16_t sport = 1025 + rand() % 60000;   /* fixed, like the pipeline */
    printf("TTL sweep (real-connection ClientHello per ttl, raw SYN for router ICMP):\n");
    for (int ttl = 1; ttl <= 18; ttl++) {
        cap_reset(c);
        send_tcp(fd, src, tgt, sport, 443, rand(), 0, F_SYN, ttl, NULL, 0);   /* router ICMP */
        conn_send_ttl(ip, 443, sport, ch, n, ttl, 0, 2.0);   /* real-conn trigger, fixed sport */
        conn_send_ttl(ip, 443, sport, ch, n, ttl, 0, 2.0);
        usleep(300000);
        rst_ev *rs; int nr = cap_rsts(c, &rs);
        icmp_ev *ic; int ni = cap_icmps(c, &ic);
        int icmp_tgt = 0; uint32_t rtr = 0;
        for (int i = 0; i < ni; i++) if (ic[i].inner_dst == tgt) { icmp_tgt++; if (!rtr) rtr = ic[i].rtr; }
        struct in_addr ra; ra.s_addr = rtr;
        printf("  ttl=%2d  RST=%d  ICMP(to-tgt)=%d  router=%s\n", ttl, nr, icmp_tgt, rtr ? inet_ntoa(ra) : "-");
    }
    cap_stop(c);
    return 0;
}
