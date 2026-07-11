# phantomprobe

A single, portable C tool that measures on-path censorship middleboxes end-to-end,
running every stage **back-to-back on one route-consistent source port per target**, so
readings don't drift between separate runs (the classic "in-path 22 → 14 on re-scan"
problem caused by BGP/ECMP churn).

Download, build, run — anywhere. One dependency (libpcap), and only for the raw stages.

## Build

```sh
# Linux:  apt-get install libpcap-dev        macOS: libpcap ships with the OS
make
```

Produces the `phantomprobe` binary. Builds with gcc or clang, `-std=c11`, POSIX
(Linux / macOS / BSD).

## Usage

```
phantomprobe --targets FILE [--protocol http|https] [--country LABEL]
             [--N n] [--maxttl t] [--secs s] [--help]
```

**This tool is not country-specific.** It probes whatever destinations you list, from
wherever you run it. Point it at any target list, from any vantage in the world.

### Flags

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--targets` | `FILE` | *(required)* | Target list: one `ip  trigger_domain` per line (see below). |
| `--protocol` | `http` \| `https` | `https` | Which channel to trigger on: HTTP `Host:` header, or HTTPS TLS `SNI`. |
| `--country` | `LABEL` | `UAE` | **Just a label** — a free-form tag stamped into the output folder name and `manifest.json`. It does **not** restrict or filter targets in any way; it's only for organising your runs. Use any string: `US`, `IR`, `mytest`, etc. |
| `--N` | `n` | `8` | Number of differential samples per target (censorship confirmation: trigger vs. benign control). Higher = more robust against loss. |
| `--maxttl` | `t` | `20` | Max TTL / traceroute depth for the injector-localization stage. |
| `--secs` | `s` | `20` | Duration (seconds) of the dense IP-ID capture used to count injecting boxes. |
| `--help` | — | — | Print usage and exit. |

Anything except `http` passed to `--protocol` is treated as `https`.

### Examples

```sh
# Stages 1-2 only (censored? + residual filtering) -- no root needed, fully portable:
./phantomprobe --targets targets.txt --protocol https

# Full pipeline (all stages -- needs raw sockets + libpcap, hence sudo):
sudo ./phantomprobe --targets targets.txt --protocol https --N 8 --maxttl 20 --secs 20

# A different country -- the --country label just names the output folder:
sudo ./phantomprobe --targets iran_targets.txt --protocol http --country IR

# HTTP channel, quick low-sample smoke test:
./phantomprobe --targets targets.txt --protocol http --N 4
```

### Target file format

One `ip  trigger_domain` per line (whitespace-separated). Lines starting with `#` are
comments. See [`targets.example.txt`](targets.example.txt).

```
# <destination IP>   <trigger/blacklisted domain to test on the path to that IP>
195.229.213.67   alhudood.net
83.111.118.217   alhudood.net
```

## The ordered pipeline (per target, one session, one fixed source port)

1. **censored?** — full taxonomy (CENSORED / CLEAN / PATH-LOSS / UNREACHABLE, with
   strength + mechanism). *(normal sockets)*
2. **residual filtering** — STATELESS / STATEFUL-RF(W=…s) / PERSIST, with duration. *(normal sockets)*
3. **localize / onset** — traceroute on the fixed sport + real-connection TTL-limited
   trigger to find the injection hop and its router. *(raw + libpcap)*
4. **in-path / off-path** — downstream-survival: does the forbidden ClientHello survive
   past the injector (off-path, inject-only) or get dropped (in-path, RST+drop)? *(raw + libpcap)*
6. **backup injector** — dense IP-ID capture + track separation: one counter (single box)
   or two (primary + backup). *(raw + libpcap)*
   *only if in-path:*
5. **router == middlebox?** — shared IP-ID counter test vs the onset-hop router. *(raw + libpcap)*
7. **backbone middlebox?** — same test against the upstream backbone routers. *(raw + libpcap)*

## Output tree (navigable, timestamped)

```
outputs_pipeline/<UTCstamp>_<country>_<proto>/
    censored_targets.csv          # stage 1
    rf_targets.csv                # stage 2 (+ duration)
    manifest.json                 # counts + provenance
    middlebox_analysis_<proto>_<country>_<stamp>/
        injector_localized.csv    # stage 3
        inpath_offpath.csv        # stage 4
        backup_injector.csv       # stage 6
        ipid_router_vs_middlebox.csv  # stage 5
        backbone_middlebox.csv    # stage 7
```

Every run is its own folder (nothing overwritten). Every CSV logs the per-target `sport`
so you can confirm the route was held constant across stages. On finishing, the tool runs
13 self-check passes over the tree.

## Notes / honest scope

- **Root + libpcap** are required for stages 3-7 (unavoidable for raw packet work).
  Stages 1-2 run without either.
- **Vantage matters.** The tool reads what the current path shows. In-path vs off-path is
  genuinely route- and time-dependent — that's *why* everything runs in one session.
- The injector spoofs its source, so the IP-ID stages **count and characterize** the
  injecting boxes; they don't hand you the injector's own IP (that needs an inside-country
  vantage). From vantages where routers rate-limit ICMP, stage 5/7 honestly report
  `ROUTER-SILENT`.
- Validated against the reference Python tools: identical censorship/RF verdicts, correct
  onset hop, matching in/off-path (concurrently), and matching backup result
  (single vs primary+backup).
```
