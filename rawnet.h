/* rawnet.h -- raw packet send + libpcap capture (portable POSIX, needs root).
 * Used by stages 3-7. Design keeps it portable: we never open a kernel TCP
 * socket for the crafted flow, so there is no kernel-RST to suppress; we read
 * injected RSTs and ICMP time-exceeded straight off the wire with libpcap. */
#ifndef RAWNET_H
#define RAWNET_H
#include <stdint.h>

/* TCP flags */
#define F_SYN 0x02
#define F_RST 0x04
#define F_PA  0x18   /* PSH|ACK -- carries our ClientHello/GET payload */

int      raw_send_sock(void);                 /* IP_HDRINCL raw socket, or -1     */
uint32_t local_ip_for(uint32_t dst_be);       /* source IPv4 (be) that routes to dst */
int      default_dev(char *buf, int cap);     /* pcap capture device name; 0 ok    */

/* craft + send one IPv4/TCP packet (optionally TTL-limited, optional payload) */
int send_tcp(int fd, uint32_t src_be, uint32_t dst_be, uint16_t sport, uint16_t dport,
             uint32_t seq, uint32_t ack, uint8_t flags, uint8_t ttl,
             const uint8_t *payload, int paylen);

/* craft + send one IPv4/UDP packet (TTL-limited, with payload) -- for DNS/STUN localization */
int send_udp(int fd, uint32_t src_be, uint32_t dst_be, uint16_t sport, uint16_t dport,
             uint8_t ttl, const uint8_t *payload, int paylen);

/* ---- capture (one per target). Collects, with timestamps: ----
 *   RST events  : injected resets whose src == target        (ts, ip_id)
 *   ICMP events : time-exceeded (type 11)  (ts, router_ip, router_ip_id, inner_dst) */
typedef struct cap cap_t;
typedef struct { double ts; uint16_t id; uint8_t ttl; } rst_ev;
typedef struct { double ts; uint32_t rtr; uint16_t id; uint32_t inner_dst; } icmp_ev;
/* injected replies on UDP channels (DNS/STUN) -- the UDP analog of a TCP RST:
 *   kind 0 = forged UDP response from the target (spoofed src == target)
 *   kind 1 = injected ICMP dest-unreachable (port/admin-prohibited)
 * id  = the injected packet's OUTER IP-ID (the injector's counter, for same-box/count)
 * ttl = the injected packet's IP TTL (onset distance -- beware TTL-mirroring injectors)
 * src = sender of the injected packet (target for kind 0; the injector/router for kind 1) */
typedef struct { double ts; uint16_t id; uint8_t ttl; uint8_t kind; uint32_t src; } inj_ev;

cap_t *cap_start(const char *dev, uint32_t target_be);   /* filter: icmp / tcp / udp from target */
void   cap_stop(cap_t *c);
void   cap_reset(cap_t *c);                              /* clear events between phases     */
int    cap_rsts(cap_t *c, rst_ev **out);                 /* returns count, *out = array     */
int    cap_icmps(cap_t *c, icmp_ev **out);
int    cap_injs(cap_t *c, inj_ev **out);                 /* injected UDP/ICMP-unreach events */

#endif /* RAWNET_H */
