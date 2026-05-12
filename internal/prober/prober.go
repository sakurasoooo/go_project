// Package prober drives the per-target query plan and aggregates responses.
//
// A Prober owns a fixed-size worker pool. Each worker picks a (IP, port,
// transport) tuple from the input channel and runs the DNS-SD query plan
// against it. Responses are merged into a single shared model.Result that is
// safe for concurrent access.
package prober

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"

	"github.com/zjw-swun/mdns-survey/internal/config"
	"github.com/zjw-swun/mdns-survey/internal/dnssd"
	"github.com/zjw-swun/mdns-survey/internal/model"
)

// Querier abstracts the DNS exchange so tests can swap in a fake without
// touching real sockets. dnssd.Client satisfies it for real runs.
type Querier interface {
	Exchange(ctx context.Context, addr string, q *dns.Msg) (*dns.Msg, error)
}

// Target is a single probe destination derived from the CLI inputs.
type Target struct {
	IP        netip.Addr
	Port      uint16
	Transport string // "udp" or "tcp"
}

// Source returns the canonical Result key for this target.
func (t Target) Source() string {
	return fmt.Sprintf("%s:%d/%s", t.IP.String(), t.Port, t.Transport)
}

// Addr returns the "ip:port" string suitable for net.Dial-style helpers.
func (t Target) Addr() string {
	return netip.AddrPortFrom(t.IP, t.Port).String()
}

// Notify receives incremental scan updates for HTTP/SSE layers. All fields are optional.
type Notify struct {
	OnProgress func(done, total int)
	OnHost     func(h *model.Host)
	OnService  func(source string, svc *model.Service)
}

type runCallbacks struct {
	notify   *Notify
	hostOnce sync.Map // probe source -> emitted first "host" event
}

// Prober is the entrypoint used by the CLI runner.
type Prober struct {
	cfg     *config.Config
	udp     Querier
	tcp     Querier
	logf    func(format string, args ...any) // nil = quiet
	verbose bool
}

// New returns a Prober ready to run with real network clients. Use NewWithQueriers
// to supply mocks in tests.
func New(cfg *config.Config) *Prober {
	p := &Prober{cfg: cfg}
	p.udp = dnssd.NewClient("udp", cfg.Timeout)
	if cfg.UseTCP {
		p.tcp = dnssd.NewClient("tcp", cfg.Timeout)
	}
	return p
}

// NewWithQueriers is the seam tests use to inject fake transports. Either
// queriers may be nil; targets whose transport has no querier are skipped.
func NewWithQueriers(cfg *config.Config, udp, tcp Querier) *Prober {
	return &Prober{cfg: cfg, udp: udp, tcp: tcp}
}

// SetLogger installs a structured logger. When v is false the logger only
// receives errors that are not plain timeouts (which are expected on cold
// hosts and would otherwise drown out signal).
func (p *Prober) SetLogger(fn func(format string, args ...any), verbose bool) {
	p.logf = fn
	p.verbose = verbose
}

// Targets fans out the cartesian product of (IPs, Ports, transports). The
// resulting slice respects the CLI's UseTCP flag so we never queue work for
// a transport we cannot drive.
func (p *Prober) Targets(ips []netip.Addr) []Target {
	out := make([]Target, 0, len(ips)*len(p.cfg.Ports))
	for _, ip := range ips {
		for _, port := range p.cfg.Ports {
			out = append(out, Target{IP: ip, Port: port, Transport: "udp"})
			if p.cfg.UseTCP {
				out = append(out, Target{IP: ip, Port: port, Transport: "tcp"})
			}
		}
	}
	return out
}

// Run executes the query plan for every target using a bounded worker pool
// and returns the aggregated result. The context cancels in-flight queries
// promptly so Ctrl+C does not leave the program waiting on UDP timeouts.
// When notify is non-nil, OnProgress is invoked after each target finishes;
// OnService / OnHost fire when new DNS-SD rows are merged (see docs/API.md).
func (p *Prober) Run(ctx context.Context, targets []Target, notify *Notify) *model.Result {
	res := model.NewResult()
	if len(targets) == 0 {
		return res
	}
	var rc *runCallbacks
	if notify != nil {
		rc = &runCallbacks{notify: notify}
	}
	total := len(targets)
	var doneAtomic int32
	workers := p.cfg.Workers
	if workers <= 0 {
		workers = 64
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	jobs := make(chan Target, workers*2)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					return
				}
				p.probe(ctx, t, res, rc)
				if notify != nil && notify.OnProgress != nil {
					d := int(atomic.AddInt32(&doneAtomic, 1))
					notify.OnProgress(d, total)
				}
			}
		}()
	}
	for _, t := range targets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return res
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()
	return res
}

// probe runs the full PTR plan for a single target. The plan is:
//
//  1. (optional) ask the meta-enumeration question to learn extra service types.
//  2. for every PTR name in cfg.PTRs() (+ discovered ones), send a query.
//  3. parse each response, merge services and PTRs into the shared Result.
//
// We always create the Host entry up front so renderers can show "no services"
// rows for targets we probed but got nothing useful from.
func (p *Prober) probe(ctx context.Context, t Target, res *model.Result, rc *runCallbacks) {
	q := p.querierFor(t.Transport)
	if q == nil {
		return
	}
	src := t.Source()
	res.EnsureHost(src, t.IP.String(), t.Port)

	plan := p.cfg.PTRs()
	extra := p.runMetaEnum(ctx, q, t, res)
	plan = appendUnique(plan, extra...)

	for _, name := range plan {
		if ctx.Err() != nil {
			return
		}
		p.runPTRQuery(ctx, q, t, name, res, rc)
	}
}

func (p *Prober) querierFor(transport string) Querier {
	switch transport {
	case "udp":
		return p.udp
	case "tcp":
		return p.tcp
	}
	return nil
}

func (p *Prober) runMetaEnum(ctx context.Context, q Querier, t Target, res *model.Result) []string {
	if !p.cfg.Enumerate {
		return nil
	}
	msg := dnssd.BuildQuery(config.EnumeratePTR, dns.TypePTR)
	resp, err := q.Exchange(ctx, t.Addr(), msg)
	if err != nil {
		p.log(err, "meta enum %s", t.Source())
		return nil
	}
	rs := dnssd.Parse(resp)
	return dnssd.MetaTargets(rs)
}

func (p *Prober) runPTRQuery(ctx context.Context, q Querier, t Target, name string, res *model.Result, rc *runCallbacks) {
	msg := dnssd.BuildQuery(name, dns.TypePTR)
	resp, err := q.Exchange(ctx, t.Addr(), msg)
	if err != nil {
		p.log(err, "ptr %s @ %s", name, t.Source())
		return
	}
	if resp == nil || (len(resp.Answer) == 0 && len(resp.Extra) == 0) {
		return
	}
	services := dnssd.ServicesFromMsg(resp)
	if len(services) == 0 {
		return
	}
	src := t.Source()
	for _, svc := range services {
		isNew := res.MergeService(src, svc)
		res.AddPTR(src, svc.Type)
		if rc == nil || rc.notify == nil {
			continue
		}
		if isNew && rc.notify.OnService != nil {
			rc.notify.OnService(src, model.CloneService(svc))
		}
		if isNew {
			if _, loaded := rc.hostOnce.LoadOrStore(src, true); !loaded {
				if rc.notify.OnHost != nil {
					rc.notify.OnHost(res.SnapshotHost(src))
				}
			}
		}
	}
}

func (p *Prober) log(err error, format string, args ...any) {
	if p.logf == nil {
		return
	}
	if !p.verbose && err != nil && isTimeout(err) {
		return
	}
	p.logf(format+": %v", append(args, err)...)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	// dnssd.Client wraps timeouts with the literal "timeout:" prefix so we
	// can suppress them here without importing net just for net.Error.
	s := err.Error()
	return len(s) >= 7 && s[:7] == "timeout"
}

func appendUnique(dst []string, src ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, d := range dst {
		seen[d] = struct{}{}
	}
	for _, s := range src {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		dst = append(dst, s)
	}
	return dst
}
