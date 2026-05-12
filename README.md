# mdns-survey

A Go CLI for mapping mDNS / DNS-SD assets on a network. Given a CIDR or IP
range plus a port list, the tool sends unicast DNS-SD style PTR queries to
every target, chases the SRV / TXT / A / AAAA records that come back and
prints the discovered services in the layout used by `dns-sd` / Avahi.

The deeper rationale for this project — keeping AI-assisted development honest,
white-box and source-driven — lives in [CLAUDE.md](CLAUDE.md) and the
workspace rules.

## Why "unicast mDNS"?

Pure mDNS (RFC 6762) is link-local multicast on `224.0.0.251:5353`. The task
brief, though, asks for a **CIDR + port range** input and a service-by-service
banner output, which is the classic DNS-SD shape (RFC 6763). To satisfy both:

- Every probe is a DNS-SD style PTR question (e.g. `_http._tcp.local.`).
- The question is sent **unicast** to each `(IP, port)` pair the operator
  chose. Default port is `5353`; you can add `53`, `5000-5001`, etc.
- Responders that follow the Bonjour / Avahi conventions answer with the
  full SRV+TXT+A+AAAA bundle in the Additional section, which is how the
  parser recovers ports and banners in one round-trip.

Pure link-local discovery is intentionally out of scope; running it against
a single-IP target is also supported.

## Quick start

```bash
# build
go build -o survey ./cmd/survey

# scan a small subnet on the default mDNS port
./survey --cidr 192.168.1.0/24 --ports 5353

# scan a range, widen the port list, give slow devices more time
./survey --ip-range 192.168.1.1-192.168.1.50 --ports 5353,5000-5001 \
         --timeout 1.5s --workers 128

# scan a single host (useful for testing locally on macOS)
./survey --cidr 127.0.0.1/32 --ports 5353
```

Stdout carries the report, stderr carries progress and errors, so piping
through `tee`, `diff` or `jq` (when YAML lands) keeps the data clean.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--cidr` | _required_¹ | Target CIDR (`192.168.1.0/24`) |
| `--ip-range` | _required_¹ | Target range (`192.168.1.10-192.168.1.20` or `192.168.1.10-20`) |
| `--ports` | `5353` | Comma-separated ports / ranges (`5353,53,5000-5001`) |
| `--timeout` | `800ms` | Per-query timeout |
| `--workers` | `64` | Bounded in-flight probes |
| `--iface` | `""` | Outgoing interface (needed for IPv6 link-local) |
| `--ptr-list` | `""` | File with extra PTR names, one per line |
| `--enumerate` | `true` | Also ask `_services._dns-sd._udp.local.` |
| `--tcp` | `false` | Send queries over TCP in addition to UDP |
| `--format` | `text` | Output format (yaml reserved) |
| `--verbose` | `false` | Log every per-target error, not only non-timeouts |

¹ One of `--cidr` or `--ip-range` is required; they are mutually exclusive.

## Example output

```
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=192.168.1.50
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_afpovertcp._tcp.local
_device-info._tcp.local
_http._tcp.local
_qdiscover._tcp.local
_smb._tcp.local
_workstation._tcp.local
```

When the scan covers more than one host, each block is prefixed with
`host: <ip>:<port>/<transport>` so the IPs stay disambiguated.

## Project layout

```
cmd/survey/           CLI entrypoint (flag parsing, signal handling)
internal/config/      Tunables (timeouts, workers, default PTR list)
internal/ipgen/       CIDR / IP range / port-list parsing
internal/model/       Host / Service in-memory model with concurrent merge
internal/dnssd/       miekg/dns wrapper, response parser, service builder
internal/prober/      Worker pool that drives the PTR plan per target
internal/render/      Text renderer aligned with the task example
```

## Tests

```bash
go test ./cmd/... ./internal/...
```

The dnssd and render packages contain golden-style tests that build the
exact `dns.Msg` shape from the task example and assert the parser /
renderer recover every Name / IPv4 / IPv6 / Hostname / TTL field and every
TXT key (`path`, `accessType`, `model`, `fwVer`, ...).

## Safety / legality

Only run this against networks you own or are explicitly authorised to probe.
Even though the queries are valid DNS, sweeping arbitrary ranges may run
afoul of acceptable-use policies and local law.

## HTTP API (for the React frontend)

The contract for a future HTTP layer (scan submit, progress SSE, results
JSON) lives in [docs/API.md](docs/API.md). It is contract-first: types and
endpoint shapes are stable enough for the frontend to start integrating
before the Go HTTP server lands.

## Dependencies

- [`github.com/miekg/dns`](https://github.com/miekg/dns) for query
  construction and response parsing. The standard library covers everything
  else.
