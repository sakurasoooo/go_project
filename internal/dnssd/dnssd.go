// Package dnssd builds and parses mDNS / DNS-SD style queries.
//
// The package is intentionally split into two layers:
//
//  1. Query construction + transport (BuildQuery, Exchange) — what to send.
//  2. Response interpretation (Parse, ServicesFromMsg)      — what came back.
//
// The prober uses both layers; tests exercise (2) directly with synthetic
// dns.Msg objects so we never need a live network to assert correctness.
package dnssd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/zjw-swun/mdns-survey/internal/model"
)

// Client wraps a dns.Client so we can pin its transport and timeout for the
// whole survey run. It is safe for concurrent use by many goroutines.
type Client struct {
	c       *dns.Client
	timeout time.Duration
}

// NewClient returns a Client that sends queries over the given transport
// ("udp" or "tcp"). The timeout applies to a single Exchange round-trip.
func NewClient(transport string, timeout time.Duration) *Client {
	c := &dns.Client{
		Net:          transport,
		Timeout:      timeout,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		// UDPSize raised so a single response carries the SRV+TXT+A+AAAA
		// bundle Bonjour devices put in Additional Records without forcing
		// us into TCP. 4096 matches what dns-sd / Avahi negotiate.
		UDPSize: 4096,
	}
	return &Client{c: c, timeout: timeout}
}

// BuildQuery returns a freshly constructed PTR query for the given service
// type name. The recursion-desired bit is cleared because mDNS responders do
// not recurse, and asking for it confuses some embedded stacks.
func BuildQuery(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = []dns.Question{{
		Name:   dns.Fqdn(qname),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}}
	return m
}

// Exchange sends q to addr ("ip:port") and returns the response. The context
// is honoured even when the underlying dns.Client would otherwise block on
// the socket read.
func (c *Client) Exchange(ctx context.Context, addr string, q *dns.Msg) (*dns.Msg, error) {
	type result struct {
		msg *dns.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		resp, _, err := c.c.ExchangeContext(ctx, q, addr)
		ch <- result{resp, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			// Translate timeouts into a stable error string so the prober
			// can log them at a lower severity than real failures.
			if isTimeout(r.err) {
				return nil, fmt.Errorf("timeout: %w", r.err)
			}
			return nil, r.err
		}
		return r.msg, nil
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// recordSet indexes a dns.Msg by record type so the service builder can do
// O(1) joins between PTR/SRV/TXT/A/AAAA records.
type recordSet struct {
	PTRs  []*dns.PTR
	SRVs  map[string][]*dns.SRV
	TXTs  map[string][]*dns.TXT
	As    map[string][]*dns.A
	AAAAs map[string][]*dns.AAAA
}

// Parse walks every section of a response and indexes records for lookup.
// It deliberately reads Answer, Ns and Extra because many mDNS responders
// stuff the SRV+TXT+A+AAAA bundle into Additional Records.
func Parse(msg *dns.Msg) *recordSet {
	rs := &recordSet{
		SRVs:  make(map[string][]*dns.SRV),
		TXTs:  make(map[string][]*dns.TXT),
		As:    make(map[string][]*dns.A),
		AAAAs: make(map[string][]*dns.AAAA),
	}
	if msg == nil {
		return rs
	}
	for _, rr := range append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...) {
		switch r := rr.(type) {
		case *dns.PTR:
			rs.PTRs = append(rs.PTRs, r)
		case *dns.SRV:
			k := strings.ToLower(r.Hdr.Name)
			rs.SRVs[k] = append(rs.SRVs[k], r)
		case *dns.TXT:
			k := strings.ToLower(r.Hdr.Name)
			rs.TXTs[k] = append(rs.TXTs[k], r)
		case *dns.A:
			k := strings.ToLower(r.Hdr.Name)
			rs.As[k] = append(rs.As[k], r)
		case *dns.AAAA:
			k := strings.ToLower(r.Hdr.Name)
			rs.AAAAs[k] = append(rs.AAAAs[k], r)
		}
	}
	return rs
}

// MetaTargets returns the service types discovered when a response answered
// the DNS-SD meta question "_services._dns-sd._udp.local.". The caller uses
// these to extend the follow-up query plan.
func MetaTargets(rs *recordSet) []string {
	if rs == nil {
		return nil
	}
	const meta = "_services._dns-sd._udp.local."
	var out []string
	seen := make(map[string]struct{})
	for _, ptr := range rs.PTRs {
		if !strings.EqualFold(ptr.Hdr.Name, meta) {
			continue
		}
		t := strings.ToLower(dns.Fqdn(ptr.Ptr))
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

// ServicesFromMsg turns a parsed response into a slice of model.Service
// records ready to merge into the global result set. The function is total:
// PTR records lacking SRV (e.g. "_device-info._tcp.local.") still produce a
// Service entry with Port == 0 and any TXT carried back.
func ServicesFromMsg(msg *dns.Msg) []*model.Service {
	if msg == nil {
		return nil
	}
	rs := Parse(msg)
	var services []*model.Service
	const meta = "_services._dns-sd._udp.local."

	for _, ptr := range rs.PTRs {
		if strings.EqualFold(ptr.Hdr.Name, meta) {
			continue // meta records are handled separately
		}
		svcType := strings.ToLower(dns.Fqdn(ptr.Hdr.Name))
		instance := strings.ToLower(dns.Fqdn(ptr.Ptr))
		svc := newServiceFromPTR(svcType, instance, ptr.Hdr.Ttl)

		if srvs, ok := rs.SRVs[instance]; ok && len(srvs) > 0 {
			s := srvs[0]
			svc.Port = s.Port
			svc.Hostname = strings.TrimSuffix(s.Target, ".")
			if s.Hdr.Ttl > 0 && (svc.TTL == 0 || s.Hdr.Ttl < svc.TTL) {
				svc.TTL = s.Hdr.Ttl
			}
		}
		if txts, ok := rs.TXTs[instance]; ok {
			for _, t := range txts {
				svc.TXT = append(svc.TXT, t.Txt...)
				if t.Hdr.Ttl > 0 && (svc.TTL == 0 || t.Hdr.Ttl < svc.TTL) {
					svc.TTL = t.Hdr.Ttl
				}
			}
		}
		fillAddresses(svc, rs)
		services = append(services, svc)
	}

	// SRV/TXT can appear without a parent PTR when we queried them directly
	// (e.g. a follow-up TXT lookup). Surface them too, keyed by the question.
	for qname := range rs.SRVs {
		if hasServiceForInstance(services, qname) {
			continue
		}
		svc := newServiceFromInstance(qname)
		if srvs := rs.SRVs[qname]; len(srvs) > 0 {
			s := srvs[0]
			svc.Port = s.Port
			svc.Hostname = strings.TrimSuffix(s.Target, ".")
			svc.TTL = ttlMin(svc.TTL, s.Hdr.Ttl)
		}
		if txts := rs.TXTs[qname]; len(txts) > 0 {
			for _, t := range txts {
				svc.TXT = append(svc.TXT, t.Txt...)
				svc.TTL = ttlMin(svc.TTL, t.Hdr.Ttl)
			}
		}
		fillAddresses(svc, rs)
		services = append(services, svc)
	}
	return services
}

func newServiceFromPTR(svcType, instance string, ttl uint32) *model.Service {
	svc := &model.Service{
		Type:      svcType,
		ShortName: model.ShortNameFromType(svcType),
		Transport: model.TransportFromType(svcType),
		TTL:       ttl,
	}
	svc.Name = instanceLabel(instance, svcType)
	return svc
}

func newServiceFromInstance(instance string) *model.Service {
	// best-effort recovery of service type from the instance FQDN: take
	// everything past the first label, e.g.
	//   "slw-nas._http._tcp.local." -> "_http._tcp.local."
	inst := strings.TrimSuffix(instance, ".")
	parts := strings.SplitN(inst, ".", 2)
	if len(parts) != 2 {
		return &model.Service{}
	}
	svcType := strings.ToLower(dns.Fqdn(parts[1]))
	svc := newServiceFromPTR(svcType, instance, 0)
	return svc
}

func instanceLabel(instance, svcType string) string {
	inst := strings.TrimSuffix(instance, ".")
	suffix := strings.TrimSuffix(svcType, ".")
	if strings.HasSuffix(inst, "."+suffix) {
		return inst[:len(inst)-len(suffix)-1]
	}
	if dot := strings.Index(inst, "."); dot > 0 {
		return inst[:dot]
	}
	return inst
}

func fillAddresses(svc *model.Service, rs *recordSet) {
	if svc.Hostname == "" {
		return
	}
	key := strings.ToLower(dns.Fqdn(svc.Hostname))
	if as := rs.As[key]; len(as) > 0 {
		svc.IPv4 = as[0].A.String()
		svc.TTL = ttlMin(svc.TTL, as[0].Hdr.Ttl)
	}
	if aaaas := rs.AAAAs[key]; len(aaaas) > 0 {
		svc.IPv6 = aaaas[0].AAAA.String()
		svc.TTL = ttlMin(svc.TTL, aaaas[0].Hdr.Ttl)
	}
}

func hasServiceForInstance(services []*model.Service, instance string) bool {
	want := strings.ToLower(strings.TrimSuffix(instance, "."))
	for _, s := range services {
		if s == nil {
			continue
		}
		full := strings.ToLower(s.Name + "." + strings.TrimSuffix(s.Type, "."))
		if full == want {
			return true
		}
	}
	return false
}

func ttlMin(cur, next uint32) uint32 {
	if next == 0 {
		return cur
	}
	if cur == 0 || next < cur {
		return next
	}
	return cur
}
