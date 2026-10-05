# dnsresolvr

DNS resolver benchmark for the terminal. Tests public resolvers and your own over UDP, DoT, DoH, DoH3 and DoQ.

## Install

Needs Rust 1.85 or newer.

```
cargo install --path crates/dnsresolvr-cli
```

## Usage

```
dnsresolvr                  # live view
dnsresolvr bench --plain    # no live view, prints table and verdict
dnsresolvr probe github.com # one query per resolver
dnsresolvr list             # show the resolver list
dnsresolvr check            # test that every resolver still answers
```

`dnsresolvr bench --help` lists all flags.

### Keys

| key | action |
|-----|--------|
| `Enter` | details for the selected row |
| `s` | change sort column |
| `v` | verdict |
| `r` | restart |
| `:` | command mode |
| `?` | help |
| `q` | quit |

### Commands

| command | effect |
|---------|--------|
| `:w [path]` | export to `.csv` or `.json` |
| `:set iter <N>` | iterations per domain |
| `:set preset quick\|standard\|thorough\|exhaustive` | 1 / 4 / 20 / 50 iterations |
| `:set transports udp,dot,doh,doh3,doq` | limit transports |
| `:set cc <N>` | endpoints tested at once |
| `:set ipv6 on\|off` | include IPv6 |
| `:add <domain>` / `:rm <domain>` | change test domains |

Changes apply on the next `:r`. `:help` shows the rest.

## Your own resolvers

```
dnsresolvr bench --add-resolver "Home=192.168.1.2"
dnsresolvr bench --resolvers my-resolvers.json
dnsresolvr bench --no-bundled --no-system --add-resolver "Home=192.168.1.2"
```

The file uses the same format as [`resolvers.json`](crates/dnsresolvr-core/src/resolvers.json). Your system's DNS servers are added automatically unless you pass `--no-system`.

## Columns

Latencies are in milliseconds. `c_` is cached, `u_` is uncached.

| column | meaning |
|--------|---------|
| `t` | transport |
| `filter` | what the resolver blocks |
| `sec` | validates DNSSEC |
| `ecs` | sends a client subnet upstream |
| `setup` | new connection plus first answer |
| `p50` / `p90` / `p99` | median and tail latency (p99 needs 100+ samples) |
| `rel` | share of queries with a valid answer |

## How it measures

- **Cached**: the domain itself, after one untimed warm-up query.
- **Uncached**: a random subdomain, so the resolver has to ask upstream. The answer is normally NXDOMAIN.
- Encrypted transports keep one connection open. Latency columns time the query only; connecting is the `setup` column.
- SERVFAIL, REFUSED and empty answers count as failures.
- Eight endpoints run at a time by default (`--concurrency`).
- The verdict ranks by 75% cached + 25% uncached median and skips endpoints below 97% reliability.
- `ecs` and the exit server come from one lookup of `o-o.myaddr.l.google.com`. The exit server's operator comes from Team Cymru's IP-to-ASN service.

## License

MIT
