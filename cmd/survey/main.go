// Command survey is the mDNS / DNS-SD network surveying CLI.
//
// Given a CIDR or IP range plus one or more destination ports, it sends
// DNS-SD style PTR queries to each target, parses the responses and prints
// the discovered services in the layout shown in 题目.md.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zjw-swun/mdns-survey/internal/config"
	"github.com/zjw-swun/mdns-survey/internal/ipgen"
	"github.com/zjw-swun/mdns-survey/internal/prober"
	"github.com/zjw-swun/mdns-survey/internal/render"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "survey:", err)
		os.Exit(1)
	}
}

// run is the testable entrypoint. It parses flags, builds the prober and
// writes the rendered report to stdout. All logs go to stderr so machine
// consumers can pipe stdout through diff/jq without contamination.
func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("survey", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		cidr      = fs.String("cidr", "", "target CIDR (e.g. 192.168.1.0/24)")
		ipRange   = fs.String("ip-range", "", "target IP range (e.g. 192.168.1.10-192.168.1.20)")
		portsStr  = fs.String("ports", "5353", "ports to query, comma-separated (e.g. 5353,53,5000-5001)")
		timeout   = fs.Duration("timeout", 800*time.Millisecond, "per-query timeout")
		workers   = fs.Int("workers", 64, "max in-flight probes")
		iface     = fs.String("iface", "", "outgoing interface (required for IPv6 link-local)")
		ptrList   = fs.String("ptr-list", "", "path to a file with additional PTR names, one per line")
		enumerate = fs.Bool("enumerate", true, "send the _services._dns-sd._udp.local meta query")
		useTCP    = fs.Bool("tcp", false, "also send queries over TCP")
		format    = fs.String("format", "text", "output format: text|yaml")
		verbose   = fs.Bool("verbose", false, "log every query failure (off by default to keep noise low)")
	)

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: survey --cidr 192.168.1.0/24 [--ports 5353] [--timeout 800ms]")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}

	// Smoke / CI: help must exit 0 with full flag list (stdlib alone treats -h as unknown).
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fs.Usage()
		return nil
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workers < 1 {
		return fmt.Errorf("--workers must be at least 1 (got %d)", *workers)
	}
	if *cidr == "" && *ipRange == "" {
		fs.Usage()
		return fmt.Errorf("either --cidr or --ip-range is required")
	}
	if *cidr != "" && *ipRange != "" {
		return fmt.Errorf("--cidr and --ip-range are mutually exclusive")
	}

	ips, err := loadTargets(*cidr, *ipRange)
	if err != nil {
		return err
	}
	ports, err := ipgen.ParsePorts(*portsStr)
	if err != nil {
		return err
	}
	extraPTR, err := loadPTRList(*ptrList)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Ports:     ports,
		UseTCP:    *useTCP,
		Timeout:   *timeout,
		Workers:   *workers,
		Iface:     *iface,
		PTRList:   appendUnique(config.DefaultPTRList, extraPTR...),
		Enumerate: *enumerate,
		Format:    *format,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := prober.New(cfg)
	p.SetLogger(func(format string, args ...any) {
		fmt.Fprintln(stderr, "[probe] "+strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
	}, *verbose)
	targets := p.Targets(ips)
	fmt.Fprintf(stderr, "[survey] %d targets across %d ips × %d ports (timeout=%s workers=%d)\n",
		len(targets), len(ips), len(ports), cfg.Timeout, cfg.Workers)
	start := time.Now()
	res := p.Run(ctx, targets, nil, nil)
	fmt.Fprintf(stderr, "[survey] scan complete in %s\n", time.Since(start).Round(time.Millisecond))

	switch cfg.Format {
	case "text", "":
		return render.Text(stdout, res)
	case "yaml":
		return render.YAML(stdout, res)
	default:
		return fmt.Errorf("unsupported --format %q (use \"text\" or \"yaml\")", cfg.Format)
	}
}

// loadTargets unifies --cidr / --ip-range into a single []netip.Addr slice.
// The function never returns an empty list without an error so callers can
// trust that a successful return means real work is queued.
func loadTargets(cidr, ipRange string) ([]netip.Addr, error) {
	switch {
	case cidr != "":
		return ipgen.ExpandCIDR(cidr)
	case ipRange != "":
		return ipgen.ExpandRange(ipRange)
	}
	return nil, fmt.Errorf("no targets supplied")
}

// loadPTRList reads a file of PTR names (one per line, blank lines and
// "#" comments ignored). An empty path returns no names, not an error,
// so the caller can pass through unconditionally.
func loadPTRList(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ptr-list %s: %w", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasSuffix(line, ".") {
			line += "."
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read ptr-list %s: %w", path, err)
	}
	return out, nil
}

func appendUnique(dst []string, src ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, d := range dst {
		seen[d] = struct{}{}
	}
	out := append([]string{}, dst...)
	for _, s := range src {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
