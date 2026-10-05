# dnsresolvr

A cross-platform DNS resolver benchmark with a live TUI and vim-style command mode.

## Features

- Five transports: plain UDP, DoT, DoH (HTTP/2), DoH3 (HTTP/3) and DoQ
- Encrypted transports reuse one connection per endpoint, so the latency columns compare like with like; connection setup is reported in its own column
- Bundled public resolvers (Cloudflare, Google, Quad9, AdGuard, Mullvad, DNS4EU, NextDNS, ControlD, DTAG, and more), plus the DNS servers your machine is configured to use
- Bring your own resolvers with `--resolvers <file>` or `--add-resolver`, no rebuild needed
- Two query classes per run:
  - **cached** — queries the domain as-is, after an untimed warm-up query (warm-cache path)
  - **uncached** — queries `<random>.<domain>` (forces recursion)
- Answers are checked: SERVFAIL, REFUSED or an empty answer counts as a failure, not as a fast reply
- Per-endpoint DNSSEC validation check and a filtering tag (malware / family / ads)
- Privacy checks per endpoint: which exit server (and operator) the resolver uses, and whether it sends a client subnet upstream (ECS)
- A verdict after each run: the fastest endpoint per category and where your own resolver ranks
- Percentiles: p50 / p90 / p95 / p99, stddev, reliability, error breakdown
- Ratatui TUI: live-updating table, sortable, detail pane per endpoint, progress gauge
- Vim-style command mode for in-app configuration
- CSV / JSON export, including the settings the run was made with
- IPv6 support (opt-in)
- Default domain set: Steam, Battle.net, League of Legends, Discord, YouTube, Google, Cloudflare, GitHub, Netflix, Amazon. Extend or replace at runtime.

## Build

Requires Rust 1.85+.

```
cargo build --release
```

The binary lands at `target/release/dnsresolvr` (`.exe` on Windows). To put it on your `PATH`:

```
cargo install --path crates/dnsresolvr-cli
```

## Usage

### Interactive (default)

```
dnsresolvr
```

Launches the TUI with sensible defaults. Configure everything inside via `:` commands. When you quit, the final table and verdict are printed to the terminal so they stay in your scrollback.

#### Normal-mode keys

| key | action |
|-----|--------|
| `:` | enter command mode |
| `Enter` | open / close detail pane for the selected endpoint |
| `s` | cycle sort column (cached p50 -> uncached p50 -> connection setup -> reliability -> name) |
| `r` | restart benchmark with current config |
| `v` | verdict: the fastest resolver per category |
| up / down / PgUp / PgDn | move selection |
| `?` | help overlay |
| `q` | quit |

#### Commands

| command | effect |
|---------|--------|
| `:q`  `:quit` | exit |
| `:w [path]`  `:write` | export to CSV or JSON (inferred from extension) |
| `:wq [path]` | export and quit |
| `:r`  `:start`  `:restart` | rerun benchmark |
| `:stop` | abort the running benchmark |
| `:set iter <N>` | iterations per domain |
| `:set sp <ms>` | spacing between queries |
| `:set to <ms>` | per-query timeout |
| `:set preset <quick\|standard\|thorough\|exhaustive>` | 1 / 4 / 20 / 50 iterations |
| `:set ipv6 on\|off\|toggle` | also probe IPv6 endpoints |
| `:set transports <list>` | `udp`, `dot`, `doh`, `doh3`, `doq` or `all` (comma-separated) |
| `:set cc <N>` | endpoints probed at the same time (0 = no limit, default 8) |
| `:set alladdrs on\|off` | probe every listed address of a resolver, not only the first |
| `:set warmup on\|off` | untimed query per domain before the cached class |
| `:set dnssec on\|off` | DNSSEC validation check |
| `:set privacy on\|off` | exit-server and client-subnet checks |
| `:set wildcard <domain>\|off` | uncached class queries `<random>.<domain>` and expects an address |
| `:set cached on\|off` | include the cached class (alias: `:cached`) |
| `:set uncached on\|off` | include the uncached class (alias: `:uncached`) |
| `:add <domain> [...]` | add domains to the probe set |
| `:rm <domain> [...]` | remove domains |
| `:reset` | restore the default domain list |
| `:domains` | show the current domain list |
| `:help`  `:?` | help overlay |

Config changes take effect on the next `:r`.

### Scripting / CI

```
# benchmark with the live view, then print the table and verdict
dnsresolvr bench

# headless: no live view, table and verdict only (automatic when piped)
dnsresolvr bench --plain

# preset + export
dnsresolvr bench --preset thorough --export results.csv

# one-shot per-resolver probe for a single host
dnsresolvr probe cloudflare.com

# print the resolver list
dnsresolvr list

# check that every endpoint in the list still answers (exit status 1 if not)
dnsresolvr check
```

### Your own resolvers

Every subcommand accepts the same resolver options:

```
# add one resolver on the command line (repeatable)
dnsresolvr bench --add-resolver "Home=192.168.1.2"
dnsresolvr bench --add-resolver "Home=192.168.1.2,dot=dns.example.net,doh=https://dns.example.net/dns-query,doh3"

# load a JSON file in the same format as the bundled list
dnsresolvr bench --resolvers my-resolvers.json

# only your own entries, nothing bundled, no system resolver
dnsresolvr bench --no-bundled --no-system --add-resolver "Home=192.168.1.2"
```

An entry with the same name as a bundled resolver replaces it. A resolver entry looks like this; only `name` and one address (or `doh_url`) are required:

```json
{
  "name": "Home",
  "provider": "LAN",
  "ipv4": ["192.168.1.2"],
  "ipv6": [],
  "port": 53,
  "plain": true,
  "dot_hostname": "dns.example.net",
  "dot_ipv4": [],
  "doq_hostname": "dns.example.net",
  "doh_url": "https://dns.example.net/dns-query",
  "doh3": true,
  "filtering": "ads"
}
```

Set `"plain": false` for services that only offer encrypted transports, and `dot_ipv4` when the DoT / DoQ endpoint lives at a different address than plain DNS.

The DNS servers your operating system is configured to use are added automatically as `System (<ip>)` unless the address is already in the list. Turn that off with `--no-system`.

All CLI flags:

```
dnsresolvr bench --help
```

## Column cheat sheet

All latencies are in milliseconds. Per-class metrics use a prefix (`c_` cached, `u_` uncached):

| column | meaning |
|--------|---------|
| `t` | transport: UDP, DoT, DoH, DoH3, DoQ |
| `filter` | what the resolver blocks, if anything |
| `sec` / `dnssec` | does the endpoint validate DNSSEC (`?` = check inconclusive) |
| `ecs` | does the endpoint send a client subnet upstream (see Privacy checks) |
| `setup` | time to open a fresh connection and get the first answer (encrypted transports only) |
| `c_p50` | cached median RTT on an open connection |
| `c_p90` / `c_p99` | tail latency; p99 is only shown with 100+ samples (use `--preset thorough`) |
| `c_rel` | cached reliability: valid answers / total queries |
| `u_*` | same, for the uncached class |

Rows sort fastest-first. `—` means no data: class disabled, endpoint unreachable, or not applicable.

### Verdict

After a run (`v` in the TUI, printed automatically by `bench`) the tool names the fastest endpoint per category: unfiltered, unfiltered and encrypted, malware blocking, ad blocking, family filter. It also shows where your own resolver ranks. "Your resolver" is any endpoint on a private address or at one of the DNS servers your system is configured to use; those are kept out of the public categories.

Endpoints are ranked by a blended score of 75% cached median + 25% uncached median. An endpoint with less than 97% reliability in either class is not recommended.

### Privacy checks

Two things are looked up per endpoint, with one TXT query for `o-o.myaddr.l.google.com` (Google's authoritative servers echo back what they saw):

- **Exit server.** The address the resolver used to reach the authoritative server, mapped to its network operator through Team Cymru's IP-to-ASN service. This is what a "DNS leak test" shows. For a local forwarder it tells you who actually does the resolving. Shown in the detail pane and in exports.
- **Client subnet (ECS).** Whether the resolver attached an EDNS Client Subnet to the query. With ECS, the sites you look up learn roughly where the request came from. Some resolvers send your real /24, others a substitute; the verdict lists the subnet each one sent so you can tell.

The check reflects what the resolver sends to Google's name servers. Resolvers that only use ECS for selected destinations may behave differently elsewhere. Turn the checks off with `--no-privacy-check`.

### How the numbers are measured

- **Connection reuse.** DoT, DoH, DoH3 and DoQ keep one connection open per endpoint. The RTT columns time the query/response exchange only, which is what a long-running forwarder or browser experiences. The one-off cost of connecting is the `setup` column.
- **Warm-up.** Before the cached class, each domain is queried once without timing, so the cached numbers are cache hits and not the first lookup. Disable with `--no-warmup`.
- **Valid answers only.** A cached query must return NOERROR with at least one address. An uncached query must return NXDOMAIN or NOERROR. Anything else (SERVFAIL, REFUSED, an empty answer) is counted as a `bad answer` failure. A domain without an A record, or one your resolver blocks, will therefore show up as failures in the cached class.
- **Concurrency.** Eight endpoints are probed at a time by default. Probing everything at once makes the client the bottleneck and inflates tail latencies; raise or lower it with `--concurrency`.
- **Dead endpoints.** After five straight timeouts or network errors with no success, an endpoint is abandoned and its remaining probes are recorded as failures (0% reliability).
- **DoH host lookup.** The DoH hostname is resolved once before timing starts and the connection is pinned to that address, so your system resolver does not leak into the results.
- **DNSSEC check.** One query for `dnssec-failed.org`, a zone with deliberately broken signatures. SERVFAIL means the resolver validates.

### What the uncached class measures

By default the uncached class asks for `<random>.<domain>`, which does not exist. That forces the resolver to go upstream, but the answer is negative (NXDOMAIN). Validating resolvers have to verify a proof of non-existence for signed zones, so this is a slightly pessimistic view of them compared with a real first-time lookup.

To measure uncached *positive* answers, point the tool at a domain with a wildcard record:

```
dnsresolvr bench --wildcard-domain wild.example.net
```

Every uncached query then asks for `<random>.wild.example.net` and expects an address back.

### Why the uncached class sometimes shows lower reliability

Dips in `u_rel` are usually specific to one resolver and one zone, not to a domain in general. Some resolvers answer SERVFAIL or drop queries when they see a burst of random subdomains for the same zone, which is also what a random-subdomain attack looks like. Open the detail pane (`Enter`) to see which domain is affected; lower the pressure with `:set sp <ms>` or fewer iterations.

## Keeping the resolver list healthy

`dnsresolvr check` sends one query to every endpoint of every resolver, over each transport it advertises, and exits with status 1 if any fails after three attempts. Endpoints on private addresses are skipped. The `Resolver health` workflow runs it every Monday and whenever `resolvers.json` changes, so an entry that has gone away shows up as a failed run.

## Layout

```
dnsresolvr/
  Cargo.toml              workspace
  crates/
    dnsresolvr-core/      library: probe, bench, stats, export, resolver catalog
    dnsresolvr-cli/       binary: CLI subcommands + ratatui TUI
```

## License

MIT
