// Package config centralises the runtime configuration for the survey CLI.
//
// All tunables (timeouts, worker count, default PTR list, ...) live here so
// the rest of the code receives a single immutable Config and never reaches
// into globals. This keeps the prober and dnssd packages easy to test in
// isolation.
package config

import "time"

// DefaultPTRList is the seed set of DNS-SD service types the prober queries
// when the user does not pass --ptr-list. It mirrors the services that appear
// in the task example plus a handful of common Bonjour/Avahi advertisements
// that are cheap to ask for and produce useful banners on typical LANs.
var DefaultPTRList = []string{
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_smb._tcp.local.",
	"_qdiscover._tcp.local.",
	"_device-info._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_ssh._tcp.local.",
	"_sftp-ssh._tcp.local.",
	"_ftp._tcp.local.",
	"_printer._tcp.local.",
	"_ipp._tcp.local.",
	"_ipps._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_googlecast._tcp.local.",
	"_homekit._tcp.local.",
	"_companion-link._tcp.local.",
	"_rdp._tcp.local.",
	"_nfs._tcp.local.",
	"_webdav._tcp.local.",
}

// EnumeratePTR is the meta-query that asks "what service types do you
// advertise?" per RFC 6763 §9.
const EnumeratePTR = "_services._dns-sd._udp.local."

// Config is the prober's runtime knobs. It is immutable after construction.
type Config struct {
	Ports     []uint16      // UDP/TCP destination ports to query (default: 5353)
	UseTCP    bool          // also try the same queries over TCP
	Timeout   time.Duration // per-query timeout
	Workers   int           // max in-flight probes
	Iface     string        // outgoing interface, needed for IPv6 link-local
	PTRList   []string      // explicit PTR list; falls back to DefaultPTRList
	Enumerate bool          // send the _services._dns-sd meta query first
	Format    string        // "text" or "yaml"
}

// PTRs returns the effective PTR set including the meta-enumeration name when
// Enumerate is true. The slice returned is a fresh copy so callers may sort
// or filter it without aliasing the configuration.
func (c *Config) PTRs() []string {
	src := c.PTRList
	if len(src) == 0 {
		src = DefaultPTRList
	}
	out := make([]string, 0, len(src)+1)
	if c.Enumerate {
		out = append(out, EnumeratePTR)
	}
	out = append(out, src...)
	return out
}
