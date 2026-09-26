# netstat-lite

**Socket table viewer in pure Rust — /proc parser (Linux) + netstat backend (macOS/BSD), process mapping, filters, live refresh. Zero dependencies.**

[![CI](https://github.com/efealtiparmakoglu/netstat-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/efealtiparmakoglu/netstat-lite/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)

```
$ netstat-lite --once --state LISTEN
PROTO  LOCAL                        REMOTE                       STATE          PROCESS
----------------------------------------------------------------------------------------------------
tcp4   127.0.0.1.8080               *.*                          LISTEN         - (0)
tcp6   [::1]:80                     [::]:*                       LISTEN         myapp (4211)
```

Reads the kernel socket tables, maps sockets to processes and renders a
filterable, auto-refreshing table.

## Why netstat-lite

- **Two backends.** Linux parses `/proc/net/tcp{,6}/udp{,6}` directly
  (hex addresses with the kernel's little-endian word quirk decoded,
  IPv6 hex-pair form); macOS/BSD parse `netstat -anv` output.
- **Process mapping.** On macOS, `lsof -Fpcn -i` fills PID/command per
  socket (best effort, fixture-tested parser).
- **Filters.** `--state LISTEN`, `--port 443`, `--proc Safari` —
  combinable.
- **Live refresh.** Full-screen redraw on an interval (`--interval MS`),
  or `--once` for scripting.
- **Zero dependencies.**

## Known limitations

- macOS process mapping needs an unrestricted lsof run; some sockets
  stay unattributed.
- UDP "connections" have no state; shown as UNBOUND/-.

## Usage

```sh
netstat-lite --once                     # one shot
netstat-lite --state ESTABLISHED        # live, 1s refresh
netstat-lite --port 443 --proc Safari   # combined filters
```

Exit codes: 0 ok, 1 read failure, 2 usage error.

## Development

```sh
cargo test
cargo clippy --all-targets
```

Tests cover /proc hex address decoding (v4 LE quirk, v6 compression),
kernel state mapping, netstat/lsof parsers, all three filters and the
table renderer.
