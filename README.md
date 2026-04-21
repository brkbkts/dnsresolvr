# dnsresolvr

A cross-platform DNS resolver benchmark with a live TUI and vim-style command mode.

## Features

- UDP/53 probes with true round-trip timing (no retries, no library cache)
- 20 bundled public resolvers (Cloudflare, Google, Quad9, AdGuard, Mullvad, DNS0.eu, NextDNS, ControlD, DTAG, and more)
- Two query classes per run:
  - **cached** — queries the domain as-is (warm-cache path)
  - **uncached** — queries `<random>.<domain>` (forces recursion)
- Percentiles: p50 / p95 / p99, stddev, reliability, error breakdown
- Ratatui TUI: live-updating table, sortable, detail pane per endpoint, progress gauge
- Vim-style command mode for in-app configuration
- CSV / JSON export
- IPv6 support (opt-in)
- Default domain set: Steam, Battle.net, League of Legends, Epic, Discord, YouTube, plus Google/Cloudflare/GitHub/Wikipedia/Netflix/Amazon. Extend or replace at runtime.

## Build

Requires Rust 1.75+.

```
cargo build --release
```

The binary lands at `target/release/dnsresolvr` (`.exe` on Windows).

## Usage

### Interactive (default)

```
dnsresolvr
```

Launches the TUI with sensible defaults. Configure everything inside via `:` commands.

#### Normal-mode keys

| key | action |
|-----|--------|
| `:` | enter command mode |
| `Enter` | open / close detail pane for the selected endpoint |
| `s` | cycle sort column (cached p50 -> uncached p50 -> reliability -> name) |
| `r` | restart benchmark with current config |
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
| `:set preset <quick\|standard\|thorough\|exhaustive>` | 1 / 5 / 20 / 50 iterations |
| `:set ipv6 on\|off\|toggle` | also probe IPv6 endpoints |
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
# headless benchmark, print to stdout
dnsresolvr bench

# preset + export
dnsresolvr bench --preset thorough --export results.csv

# one-shot per-resolver probe for a single host
dnsresolvr probe cloudflare.com

# print the bundled resolver list
dnsresolvr list
```

All CLI flags:

```
dnsresolvr bench --help
```

## Column cheat sheet

Per-class metrics use a prefix (`c_` cached, `u_` uncached) and a suffix (percentile or `rel`):

| column | meaning |
|--------|---------|
| `c_p50` | cached median RTT (ms) |
| `c_p95` / `c_p99` | tail latency (ms) |
| `c_rel` | cached reliability: successful answers / total queries |
| `u_*` | same, for the uncached class |

Rows sort fastest-first. `-` means no data (resolver unreachable or class disabled).

### Why the uncached class often shows lower reliability

Some authoritative servers (e.g. `battle.net`) drop random-subdomain queries by design. That is a property of the domain, not the resolver, so the dip appears across all resolvers.

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
