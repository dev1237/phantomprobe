/* net.c -- trigger builders + normal-socket probes (portable, no root). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "phantomprobe.h"

double now_s(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

const char *outcome_name(outcome_t o) {
    switch (o) {
        case O_ALLOW: return "ALLOW";  case O_RST: return "RST";
        case O_TIMEOUT: return "TIMEOUT"; case O_REFUSED: return "REFUSED";
        case O_BLOCKPAGE: return "BLOCKPAGE"; case O_EMPTY: return "EMPTY";
        default: return "ERR";
    }
}
int is_block(outcome_t o)  { return o == O_TIMEOUT || o == O_RST || o == O_BLOCKPAGE; }
int is_inject(outcome_t o) { return o == O_RST || o == O_BLOCKPAGE; }

static void be16(unsigned char *p, int v) { p[0] = (v >> 8) & 0xff; p[1] = v & 0xff; }

/* TLS1.2 ClientHello carrying the SNI extension -- matches injector_locate.build_client_hello */
int build_client_hello(const char *sni, unsigned char *out, int cap) {
    int hlen = (int)strlen(sni);
    if (hlen > 250 || cap < hlen + 80) return -1;
    unsigned char body[512]; int b = 0;
    body[b++] = 0x03; body[b++] = 0x03;                 /* client_version TLS1.2 */
    for (int i = 0; i < 32; i++) body[b++] = rand() & 0xff;   /* random */
    body[b++] = 0x00;                                   /* session_id length 0 */
    body[b++] = 0x00; body[b++] = 0x02; body[b++] = 0x00; body[b++] = 0x2f; /* cipher suites */
    body[b++] = 0x01; body[b++] = 0x00;                 /* compression: null */
    int entrylen   = 3 + hlen;                          /* 0x00 + len(2) + host */
    int snilistlen = 2 + entrylen;                      /* server_name_list = len(2)+entry */
    int extlen     = 4 + snilistlen;                    /* ext = type(2)+len(2)+server_name_list */
    be16(&body[b], extlen); b += 2;                     /* extensions block length */
    body[b++] = 0x00; body[b++] = 0x00;                 /* extension type: server_name */
    be16(&body[b], snilistlen); b += 2;                 /* extension length */
    be16(&body[b], entrylen);   b += 2;                 /* server_name_list length */
    body[b++] = 0x00;                                   /* name type: host_name */
    be16(&body[b], hlen);       b += 2;                 /* host name length */
    memcpy(&body[b], sni, hlen); b += hlen;
    /* handshake: client_hello (1) + 3-byte length + body */
    int o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;  /* TLS record: handshake, TLS1.0 */
    int hs_len = 4 + b;
    be16(&out[o], hs_len); o += 2;                      /* record length */
    out[o++] = 0x01;                                    /* handshake type: client_hello */
    out[o++] = (b >> 16) & 0xff; out[o++] = (b >> 8) & 0xff; out[o++] = b & 0xff;
    memcpy(&out[o], body, b); o += b;
    return o;
}

int build_http_get(const char *host, unsigned char *out, int cap) {
    return snprintf((char *)out, cap,
        "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\nConnection: keep-alive\r\n\r\n", host);
}

/* connect with a wall-clock timeout, optionally bound to a fixed local port (sport>0)
 * so the flow hashes onto the same ECMP path as our raw probes (Paris consistency).
 * returns fd>=0, or -2 timeout, -3 refused, -1 error. */
static int conn_to_sport(const char *ip, int port, int sport, double timeout) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (sport > 0) {
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
        struct sockaddr_in la; memset(&la, 0, sizeof la);
        la.sin_family = AF_INET; la.sin_port = htons(sport);
        bind(fd, (struct sockaddr *)&la, sizeof la);   /* best-effort; ignore EADDRINUSE */
        struct linger lg = {1, 0};                     /* close() -> RST, skip TIME_WAIT so */
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);  /* the fixed sport is reusable */
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }
    int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (r != 0 && errno != EINPROGRESS) { int e = errno; close(fd); return e == ECONNREFUSED ? -3 : -1; }
    if (r != 0) {
        fd_set w; FD_ZERO(&w); FD_SET(fd, &w);
        struct timeval tv; tv.tv_sec = (int)timeout; tv.tv_usec = (int)((timeout - (int)timeout) * 1e6);
        r = select(fd + 1, NULL, &w, NULL, &tv);
        if (r <= 0) { close(fd); return -2; }
        int err = 0; socklen_t el = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) { close(fd); return err == ECONNREFUSED ? -3 : -1; }
    }
    fcntl(fd, F_SETFL, 0);
    struct timeval rt; rt.tv_sec = (int)timeout; rt.tv_usec = (int)((timeout - (int)timeout) * 1e6);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof rt);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &rt, sizeof rt);
    return fd;
}
static int conn_to(const char *ip, int port, double timeout) { return conn_to_sport(ip, port, 0, timeout); }

int conn_send_ttl(const char *ip, int port, int sport, const unsigned char *payload, int plen,
                  int ttl, int restore_ttl, double timeout) {
    int fd = conn_to_sport(ip, port, sport, timeout);
    if (fd < 0) return fd;
    struct linger lg = {1, 0};                 /* RST on close, no TIME_WAIT / no long retransmits */
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    int t = ttl, hi = 64;
    setsockopt(fd, IPPROTO_IP, IP_TTL, &t, sizeof t);
    if (payload && plen) { ssize_t s = send(fd, payload, plen, 0); (void)s; }
    if (restore_ttl) {                         /* survival: keep ONLY the ClientHello TTL-limited */
        usleep(3000);                          /* ensure the SNI segment left at the low TTL first */
        setsockopt(fd, IPPROTO_IP, IP_TTL, &hi, sizeof hi);
    }
    usleep(57000);
    close(fd);
    return 0;
}

outcome_t https_probe(const char *ip, const char *sni, double timeout) {
    int fd = conn_to(ip, 443, timeout);
    if (fd == -2) return O_TIMEOUT;
    if (fd == -3) return O_REFUSED;
    if (fd < 0)   return O_ERR;
    unsigned char ch[1024]; int n = build_client_hello(sni, ch, sizeof ch);
    if (n < 0 || send(fd, ch, n, 0) < 0) { int e = errno; close(fd); return e == ECONNRESET ? O_RST : O_ERR; }
    unsigned char resp[512];
    ssize_t r = recv(fd, resp, sizeof resp, 0);
    int e = errno; close(fd);
    if (r > 0)  return O_ALLOW;                 /* ServerHello / TLS alert => reached server */
    if (r == 0) return O_ALLOW;                 /* clean close after CH => reached server */
    if (e == ECONNRESET) return O_RST;          /* injected reset on the ClientHello */
    if (e == EAGAIN || e == EWOULDBLOCK) return O_TIMEOUT;
    return O_ERR;
}

outcome_t http_probe(const char *ip, const char *host, double timeout) {
    int fd = conn_to(ip, 80, timeout);
    if (fd == -2) return O_TIMEOUT;
    if (fd == -3) return O_REFUSED;
    if (fd < 0)   return O_ERR;
    unsigned char req[512]; int n = build_http_get(host, req, sizeof req);
    if (send(fd, req, n, 0) < 0) { int e = errno; close(fd); return e == ECONNRESET ? O_RST : O_ERR; }
    unsigned char resp[512];
    ssize_t r = recv(fd, resp, sizeof resp - 1, 0);
    int e = errno; close(fd);
    if (r > 0) {
        if (memmem(resp, r, "Access Blocked", 14)) return O_BLOCKPAGE;
        if (r >= 6 && memcmp(resp, "HTTP/1", 6) == 0) return O_ALLOW;
        return O_ALLOW;
    }
    if (r == 0) return O_EMPTY;
    if (e == ECONNRESET) return O_RST;
    if (e == EAGAIN || e == EWOULDBLOCK) return O_TIMEOUT;
    return O_ERR;
}
