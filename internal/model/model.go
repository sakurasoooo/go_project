// Package model defines the in-memory representation of mDNS/DNS-SD assets
// gathered by the survey CLI. The types here are deliberately small and
// pointer-friendly so the prober can merge partial answers from many
// independent DNS responses without copying large structs.
package model

import (
	"sort"
	"strings"
	"sync"
)

// Service is a single DNS-SD service instance observed on a host.
//
// A "service" in the example output corresponds to one of three shapes:
//
//  1. Full service:   "5000/tcp http:"     (PTR + SRV + TXT)
//  2. Meta service:   "device-info:"       (PTR + TXT only, no SRV/port)
//  3. Port-only PTR:  "9/tcp workstation:" (PTR + SRV, possibly empty TXT)
//
// The renderer decides which form to emit based on whether Port != 0.
type Service struct {
	Type      string   `json:"type"`        // FQDN PTR name, e.g. "_workstation._tcp.local."
	ShortName string   `json:"short_name"`  // human label derived from Type, e.g. "workstation"
	Transport string   `json:"transport"`   // "tcp" or "udp" (from the second label of Type)
	Port      uint16   `json:"port"`        // target port from SRV; 0 when no SRV is present
	Name      string   `json:"name"`        // instance name (left-most label of the PTR target)
	Hostname  string   `json:"hostname"`    // SRV target FQDN, e.g. "slw-nas.local."
	IPv4      string   `json:"ipv4"`        // best-known A record
	IPv6      string   `json:"ipv6"`        // best-known AAAA record
	TTL       uint32   `json:"ttl"`         // smallest TTL across the records that built this service
	TXT       []string `json:"txt"`         // raw TXT strings, preserved in arrival order
}

// Host aggregates all services discovered behind a single target IP/port pair.
//
// Source records the (IP, port, transport) the prober used to elicit the
// response. The same logical asset may appear behind several Sources when the
// caller scans a port range; the renderer merges those into one block per
// (IP, port).
type Host struct {
	Source    string     `json:"source"`      // "ip:port/transport" for diagnostics
	IP        string     `json:"ip"`
	ProbePort uint16     `json:"probe_port"`
	Services  []*Service `json:"services"`
	PTRs      []string   `json:"ptrs"` // distinct PTR question names that returned answers
}

// Result is the aggregated output for the whole scan. It is safe to mutate
// concurrently via AddHost / MergeService; the mutex guards the maps below.
type Result struct {
	mu      sync.Mutex
	hosts   map[string]*Host // key = Source
	svcKeys map[string]map[string]*Service
	ptrs    map[string]map[string]struct{}
}

// NewResult returns an empty Result ready for concurrent use.
func NewResult() *Result {
	return &Result{
		hosts:   make(map[string]*Host),
		svcKeys: make(map[string]map[string]*Service),
		ptrs:    make(map[string]map[string]struct{}),
	}
}

// EnsureHost lazily creates the Host entry for a probe source.
func (r *Result) EnsureHost(source, ip string, port uint16) *Host {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.hosts[source]; ok {
		return h
	}
	h := &Host{Source: source, IP: ip, ProbePort: port}
	r.hosts[source] = h
	r.svcKeys[source] = make(map[string]*Service)
	r.ptrs[source] = make(map[string]struct{})
	return h
}

// MergeService inserts or merges a service record under the given host source.
//
// The merge key intentionally combines ShortName, Port and Hostname so that
// the same logical service appearing in multiple responses (e.g. answered via
// two different PTR queries) collapses to one entry, while different ports on
// the same shortname (e.g. two HTTP instances) stay distinct.
//
// The bool is true when a new distinct service row was added (not merged into
// an existing row). Callers use this for incremental HTTP/SSE notifications.
func (r *Result) MergeService(source string, svc *Service) bool {
	if svc == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	host := r.hosts[source]
	if host == nil {
		return false
	}
	key := svc.ShortName + "|" + svc.Hostname + "|" + uitoa(svc.Port)
	if existing, ok := r.svcKeys[source][key]; ok {
		mergeInto(existing, svc)
		return false
	}
	host.Services = append(host.Services, svc)
	r.svcKeys[source][key] = svc
	return true
}

// AddPTR records that a PTR question name produced an answer for this source.
// PTR names are deduplicated and emitted under the trailing "answers:" block.
func (r *Result) AddPTR(source, ptr string) {
	if ptr == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.ptrs[source]
	if !ok {
		return
	}
	if _, seen := set[ptr]; seen {
		return
	}
	set[ptr] = struct{}{}
	r.hosts[source].PTRs = append(r.hosts[source].PTRs, ptr)
}

// Hosts returns hosts sorted by (IP, ProbePort) so the renderer is
// deterministic across runs and goroutine schedules.
func (r *Result) Hosts() []*Host {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Host, 0, len(r.hosts))
	for _, h := range r.hosts {
		sortServices(h.Services)
		sort.Strings(h.PTRs)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].ProbePort < out[j].ProbePort
	})
	return out
}

// SnapshotHost returns a deep copy of the host for the given probe source, or nil.
func (r *Result) SnapshotHost(source string) *Host {
	r.mu.Lock()
	defer r.mu.Unlock()
	return CloneHost(r.hosts[source])
}

// sortServices orders services so meta services (Port == 0) trail the port
// blocks but keep stable order within each bucket; this matches the example
// where "device-info:" appears between full services.
func sortServices(s []*Service) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Port != s[j].Port {
			return s[i].Port < s[j].Port
		}
		return s[i].ShortName < s[j].ShortName
	})
}

func mergeInto(dst, src *Service) {
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	if dst.IPv4 == "" {
		dst.IPv4 = src.IPv4
	}
	if dst.IPv6 == "" {
		dst.IPv6 = src.IPv6
	}
	if src.TTL != 0 && (dst.TTL == 0 || src.TTL < dst.TTL) {
		dst.TTL = src.TTL
	}
	if dst.Transport == "" {
		dst.Transport = src.Transport
	}
	if dst.Port == 0 {
		dst.Port = src.Port
	}
	for _, t := range src.TXT {
		if t == "" {
			continue
		}
		if !containsString(dst.TXT, t) {
			dst.TXT = append(dst.TXT, t)
		}
	}
}

func containsString(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

func uitoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// ShortNameFromType strips the leading underscore and trailing transport/.local
// labels from a DNS-SD service type, producing the human label used in the
// example output (e.g. "_workstation._tcp.local." -> "workstation").
func ShortNameFromType(t string) string {
	t = strings.TrimSuffix(t, ".")
	parts := strings.Split(t, ".")
	if len(parts) == 0 {
		return ""
	}
	first := parts[0]
	return strings.TrimPrefix(first, "_")
}

// TransportFromType returns "tcp" or "udp" if the service type encodes one,
// otherwise the empty string.
func TransportFromType(t string) string {
	t = strings.TrimSuffix(t, ".")
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return ""
	}
	switch parts[1] {
	case "_tcp":
		return "tcp"
	case "_udp":
		return "udp"
	}
	return ""
}

// CloneService returns a deep copy safe to retain after concurrent merges.
func CloneService(s *Service) *Service {
	if s == nil {
		return nil
	}
	cp := *s
	if len(s.TXT) > 0 {
		cp.TXT = append([]string(nil), s.TXT...)
	}
	return &cp
}

// CloneHost returns a snapshot of the host suitable for JSON/SSE payloads.
func CloneHost(h *Host) *Host {
	if h == nil {
		return nil
	}
	out := &Host{
		Source:    h.Source,
		IP:        h.IP,
		ProbePort: h.ProbePort,
		PTRs:      append([]string(nil), h.PTRs...),
	}
	if len(h.Services) > 0 {
		out.Services = make([]*Service, len(h.Services))
		for i, s := range h.Services {
			out.Services[i] = CloneService(s)
		}
	}
	return out
}
