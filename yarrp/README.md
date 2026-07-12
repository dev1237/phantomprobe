# yarrp / yarrpbox — topology & middlebox discovery (Stage 0)

This folder documents the **upstream** step that produces phantomprobe's target list: a
high-rate topology scan of a country's address space that flags **packet-modifying
middleboxes** on the path. Destinations whose path already carries a middlebox are the
interesting ones — censorship concentrates there — so we probe those first.

```
country IP prefixes ──▶ yarrpbox scan (.yrp) ──▶ extract_yarrp_dests.sh ──▶ modified-path IPs
                                                                              │
                                                                              ▼
                                                          make_targets.sh ──▶ targets.txt ──▶ phantomprobe
```

## What it is

- **yarrp** — "Yelling at Random Routers Progressively," a stateless, high-rate active
  traceroute (Beverly, ACM IMC 2016). Upstream: <https://github.com/cmand/yarrp>.
- **yarrpbox** — a middlebox-detection extension of yarrp: alongside each hop it records
  whether the router **modified the probe in flight** (IP/TCP header hashes, ToS, packet size,
  TCP options, MP_CAPABLE, NOP, …) by comparing what we sent to the copy the router quotes back
  in its ICMP reply. Those per-field modification flags are what we mine.

## Build

```sh
# yarrp/yarrpbox is C++; build with make (needs g++, libpcap-dev)
git clone <yarrpbox-source>       # the middlebox-detection fork used in the study
cd yarrpbox && make
```

## The scan (exactly as run for the UAE study)

The reference file `dev-tcp-80.yrp` was produced from the India VM (`206.189.130.54`) with:

```sh
sudo ./yarrp -t TCP_SYN -i uae_ips.txt -o dev-tcp-80.yrp \
     -r 15000 -m 16 -a 206.189.130.54 -d 80
```

Every `.yrp` records its own config in the header — the reference scan's header reads:

```
# Dst_Port: 80          # Trace_Type: TCP_SYN     # Middlebox_Detection: 1
# Min_TTL: 1            # Max_TTL: 16             # Rate: 15000
# Program: Yarrp v0.7   # SourceIP: 206.189.130.54  # Targets: uae_ips.txt
```

`uae_ips.txt` is one destination IP per line (the country's announced prefixes, expanded).
The output is one line per probed hop, with ~60 fields; the header's `Output_Fields:` line
names them in order. The columns we use: `$1` target, `$3` hop router, `$22` ipMatch,
`$23` tcpMatch, `$24` completeMatch (a `0` in any = the router modified the probe), plus the
per-type flags (`$26` ToS, `$27` size, `$29` TCP-offset, `$30` TCP-flags, …).

## 1. Extract the modified-path destinations — `extract_yarrp_dests.sh`

```sh
bash extract_yarrp_dests.sh /path/to/dev-tcp-80.yrp
```

Keeps rows where a router modified the probe (`ipMatch==0 || tcpMatch==0 || completeMatch==0`)
and writes, under `inputs/`:

| file | contents |
|------|----------|
| `uae_dests_full.txt`      | unique **modified-path destination IPs** (the ~593k list phantomprobe runs on) |
| `uae_dests_sample.txt`    | first `SAMPLE_N` (default 1000) for a quick run |
| `uae_mb_dest_pairs_80.txt`| `middlebox,destination` pairs |
| `uae_mb_counts_80.txt`    | per-middlebox modification counts (desc) |

Then feed `uae_dests_full.txt` into the pairing helper and run the prober:

```sh
../scripts/make_targets.sh inputs/uae_dests_full.txt alhudood.net > targets.txt
sudo ../phantomprobe --targets targets.txt --protocol http --country AE
```

## 2. Summarize the scan — `tcpsyn-results.sh`

A one-shot report over a `.yrp`: overall modification rate, the top modifying routers, unique
middleboxes, a per-modification-type breakdown, and how many targets were affected.

```sh
bash tcpsyn-results.sh dev-tcp-80.yrp
```

The full saved report for the UAE reference scan is committed here:
[`dev-tcp-80.results.txt`](dev-tcp-80.results.txt) (produced by running this exact script over
`dev-tcp-80.yrp`). An excerpt:

**Reference output** (from the UAE `dev-tcp-80.yrp`, 16 GB, ~41.7 M hops):

```
[1] Headline Modification Rate
Total hops      : 41713591
Modified hops   : 1337234 (3.2058%)
Survived hops   : 40376357 (96.7942%)

[3] Unique Middleboxes
    2886

[4] Modification Type Breakdown
IP hash mismatch     : 1304329
TCP hash mismatch    : 45150
Complete mismatch    : 1316471
ToS modified         : 1275819
Packet size modified : 527
TCP offset modified  : 526
TCP flags modified   : 230
MP_CAPABLE removed   : 12673
NOP added            : 13062

[5] Unique Targets Affected
Total unique targets : 4094655
Affected targets     : 593043 (14.4833%)
```

The `593043` here is exactly the modified-path universe the report's funnel starts from.

**Validation.** This `tcpsyn-results.sh` is a faithful re-implementation of the original
one-shot analysis script. Run against the reference `dev-tcp-80.yrp`, it reproduces **every**
figure above exactly — total/modified hops, the 2886 unique middleboxes, all nine
modification-type counts, and the 593043 affected targets. Note the type breakdown in `[4]` is
counted **within** modified hops: a ToS/DSCP-only rewrite is normalized out of the packet hash,
so counting it over all hops (2.63 M) would overcount the true figure (1.28 M).

## Notes

- **Rate.** `-r 15000` is aggressive; be a good citizen — scan only address space you're
  authorized to measure, and lower the rate on shared uplinks.
- **Root** is required (raw sockets).
- yarrpbox writes **every** hop, modified or not; "survived" hops are the 96.8% the routers
  passed through untouched.
