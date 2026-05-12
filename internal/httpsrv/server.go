package httpsrv

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zjw-swun/mdns-survey/internal/config"
	"github.com/zjw-swun/mdns-survey/internal/ipgen"
	"github.com/zjw-swun/mdns-survey/internal/model"
	"github.com/zjw-swun/mdns-survey/internal/prober"
)

const version = "1.0.0"

// Options configures the HTTP API server.
type Options struct {
	Addr        string
	MaxScans    int
	CORSOrigins []string
}

// Server implements docs/API.md.
type Server struct {
	addr     string
	started  time.Time
	maxScans int
	cors     map[string]struct{}

	mu   sync.Mutex
	jobs map[string]*job
	ids  []string
}

type loggedEvent struct {
	id   uint64
	name string
	data []byte
}

type job struct {
	id          string
	summary     ScanSummary
	result      *model.Result
	cfg         *config.Config
	targets     []prober.Target
	cancel      context.CancelFunc
	mu          sync.Mutex
	eventID     uint64
	eventLog    []loggedEvent
	subs        map[uint64]chan loggedEvent
	nextSub     uint64
	subMu       sync.Mutex
	hostSources map[string]struct{}
}

// New returns an API server. Default listen address is ":8080".
func New(opt Options) *Server {
	if opt.Addr == "" {
		opt.Addr = ":8080"
	}
	if opt.MaxScans <= 0 {
		opt.MaxScans = 8
	}
	cors := map[string]struct{}{
		"http://localhost:5173":  {},
		"http://127.0.0.1:5173": {},
	}
	for _, o := range opt.CORSOrigins {
		if o != "" {
			cors[o] = struct{}{}
		}
	}
	return &Server{
		addr:     opt.Addr,
		started:  time.Now(),
		maxScans: opt.MaxScans,
		cors:     cors,
		jobs:     make(map[string]*job),
	}
}

func (s *Server) allowOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	_, ok := s.cors[origin]
	return ok
}

// Handler returns the root http.Handler (with middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/defaults/ptr-list", s.handleDefaultsPTR)
	mux.HandleFunc("POST /api/v1/scans", s.handlePostScan)
	mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/results", s.handleGetResults)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", s.handleDeleteScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/events", s.handleScanEvents)
	return withRequestID(withCORS(mux, s.allowOrigin))
}

// ListenAndServe binds and serves until the server shuts down.
func (s *Server) ListenAndServe() error {
	log.Printf("mdns-survey API listening on %s", s.addr)
	return http.ListenAndServe(s.addr, s.Handler())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:        "ok",
		Version:       version,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleDefaultsPTR(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ptrDefaultsResponse{PTRList: append([]string{}, config.DefaultPTRList...)})
}

func (s *Server) handlePostScan(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, rid, http.StatusBadRequest, "INVALID_JSON", "decode body: "+err.Error(), "")
		return
	}
	norm, verr := normalizeScanRequest(&req)
	if verr != nil {
		writeAPIError(w, rid, verr.HTTP, verr.Code, verr.Message, verr.Field)
		return
	}
	ips, terr := targetsFromRequest(norm)
	if terr != nil {
		writeAPIError(w, rid, terr.HTTP, terr.Code, terr.Message, terr.Field)
		return
	}
	ports, err := ipgen.ParsePorts(deref(norm.Ports))
	if err != nil {
		writeAPIError(w, rid, http.StatusBadRequest, "INVALID_PORT_RANGE", err.Error(), "ports")
		return
	}
	wk := *norm.Workers
	if wk < 1 || wk > 4096 {
		writeAPIError(w, rid, http.StatusBadRequest, "INVALID_PARAM", "workers must be between 1 and 4096", "workers")
		return
	}
	if _, err := time.ParseDuration(deref(norm.Timeout)); err != nil {
		writeAPIError(w, rid, http.StatusBadRequest, "INVALID_PARAM", "timeout: "+err.Error(), "timeout")
		return
	}

	s.mu.Lock()
	if s.activeScanCountLocked() >= s.maxScans {
		s.mu.Unlock()
		writeAPIError(w, rid, http.StatusTooManyRequests, "RATE_LIMITED", "too many concurrent scans", "")
		return
	}
	id := newScanID()
	now := time.Now().UTC()
	sum := ScanSummary{
		ID:               id,
		Status:           "queued",
		Request:          *norm,
		TargetsTotal:     0,
		TargetsDone:      0,
		HostsWithResults: 0,
		CreatedAt:        now,
	}

	ctx, cancel := context.WithCancel(context.Background())
	j := &job{
		id:          id,
		summary:     sum,
		result:      model.NewResult(),
		cfg:         buildConfig(norm, ports),
		cancel:      cancel,
		subs:        make(map[uint64]chan loggedEvent),
		hostSources: make(map[string]struct{}),
	}
	p := prober.New(j.cfg)
	j.targets = p.Targets(ips)
	j.summary.TargetsTotal = len(j.targets)

	s.jobs[id] = j
	s.ids = append(s.ids, id)
	s.mu.Unlock()

	go s.runJob(j, ctx)

	writeJSON(w, http.StatusCreated, j.snapshotSummary())
}

func (s *Server) activeScanCountLocked() int {
	n := 0
	for _, j := range s.jobs {
		j.mu.Lock()
		st := j.summary.Status
		j.mu.Unlock()
		if st == "queued" || st == "running" {
			n++
		}
	}
	return n
}

func buildConfig(norm *ScanRequest, ports []uint16) *config.Config {
	ptrBase := append([]string{}, config.DefaultPTRList...)
	for _, e := range norm.ExtraPTRList {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.HasSuffix(e, ".") {
			e += "."
		}
		ptrBase = appendUniqueStrings(ptrBase, e)
	}
	to, _ := time.ParseDuration(deref(norm.Timeout))
	return &config.Config{
		Ports:     ports,
		UseTCP:    derefBoolPtr(norm.TCP, false),
		Timeout:   to,
		Workers:   *norm.Workers,
		Iface:     deref(norm.Iface),
		PTRList:   ptrBase,
		Enumerate: derefBoolPtr(norm.Enumerate, true),
		Format:    "text",
	}
}

func appendUniqueStrings(dst []string, items ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, d := range dst {
		seen[d] = struct{}{}
	}
	out := append([]string{}, dst...)
	for _, s := range items {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (s *Server) runJob(j *job, ctx context.Context) {
	select {
	case <-ctx.Done():
		j.mu.Lock()
		j.summary.Status = "canceled"
		t := time.Now().UTC()
		j.summary.FinishedAt = &t
		j.mu.Unlock()
		s.pushEvent(j, "status", j.snapshotSummary())
		s.closeSubs(j)
		return
	default:
	}

	j.mu.Lock()
	j.summary.Status = "running"
	t0 := time.Now().UTC()
	j.summary.StartedAt = &t0
	j.mu.Unlock()

	s.pushEvent(j, "status", j.snapshotSummary())

	p := prober.New(j.cfg)
	p.SetLogger(nil, false)

	notify := &prober.Notify{
		OnProgress: func(done, total int) {
			j.mu.Lock()
			j.summary.TargetsDone = done
			j.mu.Unlock()
			s.pushEvent(j, "progress", progressEvent{TargetsDone: done, TargetsTotal: total})
		},
		OnHost: func(h *model.Host) {
			j.mu.Lock()
			if _, ok := j.hostSources[h.Source]; !ok && len(h.Services) > 0 {
				j.hostSources[h.Source] = struct{}{}
				j.summary.HostsWithResults++
			}
			j.mu.Unlock()
			s.pushEvent(j, "host", h)
		},
		OnService: func(source string, svc *model.Service) {
			s.pushEvent(j, "service", serviceEvent{Source: source, Service: svc})
		},
	}

	_ = p.Run(ctx, j.targets, j.result, notify)

	j.mu.Lock()
	switch j.summary.Status {
	case "canceled":
		// user canceled via API; leave as canceled
	default:
		if ctx.Err() == context.Canceled {
			j.summary.Status = "canceled"
		} else {
			j.summary.Status = "succeeded"
		}
	}
	j.summary.TargetsDone = j.summary.TargetsTotal
	t1 := time.Now().UTC()
	j.summary.FinishedAt = &t1
	j.mu.Unlock()

	s.pushEvent(j, "status", j.snapshotSummary())
	s.closeSubs(j)
}

func (s *Server) pushEvent(j *job, name string, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		b = []byte("{}")
	}
	j.mu.Lock()
	j.eventID++
	id := j.eventID
	ev := loggedEvent{id: id, name: name, data: b}
	j.eventLog = append(j.eventLog, ev)
	const maxLog = 512
	if len(j.eventLog) > maxLog {
		j.eventLog = j.eventLog[len(j.eventLog)-maxLog:]
	}
	j.mu.Unlock()

	j.subMu.Lock()
	subs := make([]chan loggedEvent, 0, len(j.subs))
	for _, ch := range j.subs {
		subs = append(subs, ch)
	}
	j.subMu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Server) closeSubs(j *job) {
	j.subMu.Lock()
	defer j.subMu.Unlock()
	for id, ch := range j.subs {
		close(ch)
		delete(j.subs, id)
	}
}

func (j *job) snapshotSummary() ScanSummary {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.summary
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	id := r.PathValue("id")
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		writeAPIError(w, rid, http.StatusNotFound, "SCAN_NOT_FOUND", "scan not found", "")
		return
	}
	writeJSON(w, http.StatusOK, j.snapshotSummary())
}

func (s *Server) handleGetResults(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	id := r.PathValue("id")
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		writeAPIError(w, rid, http.StatusNotFound, "SCAN_NOT_FOUND", "scan not found", "")
		return
	}
	j.mu.Lock()
	sum := j.summary
	hosts := j.result.Hosts()
	j.mu.Unlock()
	writeJSON(w, http.StatusOK, ScanResult{Scan: sum, Hosts: hosts})
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	id := r.PathValue("id")
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		writeAPIError(w, rid, http.StatusNotFound, "SCAN_NOT_FOUND", "scan not found", "")
		return
	}
	j.mu.Lock()
	st := j.summary.Status
	if st == "succeeded" || st == "failed" || st == "canceled" {
		j.mu.Unlock()
		writeAPIError(w, rid, http.StatusConflict, "SCAN_ALREADY_RUNNING", "scan already finished", "")
		return
	}
	j.summary.Status = "canceled"
	if j.cancel != nil {
		j.cancel()
	}
	j.mu.Unlock()
	writeJSON(w, http.StatusAccepted, deleteScanResponse{ID: id, Status: "canceled"})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > 100 {
				limit = 100
			}
		}
	}
	cursor := r.URL.Query().Get("cursor")
	offset := 0
	if cursor != "" {
		if b, err := base64.URLEncoding.DecodeString(cursor); err == nil {
			var m struct {
				O int `json:"o"`
			}
			if json.Unmarshal(b, &m) == nil && m.O > 0 {
				offset = m.O
			}
		}
	}

	s.mu.Lock()
	ids := append([]string(nil), s.ids...)
	s.mu.Unlock()

	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}

	var items []ScanSummary
	skipped := 0
	for _, scanID := range ids {
		s.mu.Lock()
		j, ok := s.jobs[scanID]
		s.mu.Unlock()
		if !ok {
			continue
		}
		sum := j.snapshotSummary()
		if status != "" && sum.Status != status {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		if len(items) >= limit {
			break
		}
		items = append(items, sum)
	}

	resp := scanListResponse{Items: items}
	if len(items) == limit {
		nextOff := offset + len(items)
		b, _ := json.Marshal(struct {
			O int `json:"o"`
		}{O: nextOff})
		resp.NextCursor = base64.URLEncoding.EncodeToString(b)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "Accept must include text/event-stream", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	lastID := uint64(0)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			lastID = n
		}
	}

	j.subMu.Lock()
	subID := j.nextSub
	j.nextSub++
	ch := make(chan loggedEvent, 64)
	j.subs[subID] = ch
	j.subMu.Unlock()

	defer func() {
		j.subMu.Lock()
		delete(j.subs, subID)
		j.subMu.Unlock()
	}()

	j.mu.Lock()
	replay := append([]loggedEvent(nil), j.eventLog...)
	j.mu.Unlock()
	for _, ev := range replay {
		if ev.id > lastID {
			writeSSEFrame(w, fl, ev)
		}
	}

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSEFrame(w, fl, ev)
		}
	}
}

func writeSSEFrame(w http.ResponseWriter, fl http.Flusher, ev loggedEvent) {
	fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.id, ev.name, string(ev.data))
	fl.Flush()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type validationErr struct {
	HTTP    int
	Code    string
	Message string
	Field   string
}

func normalizeScanRequest(req *ScanRequest) (*ScanRequest, *validationErr) {
	hasC := req.CIDR != nil && strings.TrimSpace(*req.CIDR) != ""
	hasR := req.IPRange != nil && strings.TrimSpace(*req.IPRange) != ""
	switch {
	case !hasC && !hasR:
		return nil, &validationErr{http.StatusBadRequest, "MISSING_FIELD", "cidr or ip_range is required", "cidr"}
	case hasC && hasR:
		return nil, &validationErr{http.StatusBadRequest, "INVALID_PARAM", "cidr and ip_range are mutually exclusive", "cidr"}
	}
	ports := "5353"
	if req.Ports != nil && strings.TrimSpace(*req.Ports) != "" {
		ports = strings.TrimSpace(*req.Ports)
	}
	timeout := "800ms"
	if req.Timeout != nil && strings.TrimSpace(*req.Timeout) != "" {
		timeout = strings.TrimSpace(*req.Timeout)
	}
	workers := 64
	if req.Workers != nil {
		workers = *req.Workers
	}
	out := &ScanRequest{
		CIDR:         req.CIDR,
		IPRange:      req.IPRange,
		Ports:        &ports,
		Timeout:      &timeout,
		Workers:      &workers,
		Iface:        req.Iface,
		ExtraPTRList: append([]string(nil), req.ExtraPTRList...),
		Enumerate:    req.Enumerate,
		TCP:          req.TCP,
	}
	return out, nil
}

func targetsFromRequest(norm *ScanRequest) ([]netip.Addr, *validationErr) {
	var ips []netip.Addr
	var err error
	if norm.CIDR != nil && strings.TrimSpace(*norm.CIDR) != "" {
		ips, err = ipgen.ExpandCIDR(strings.TrimSpace(*norm.CIDR))
	} else {
		ips, err = ipgen.ExpandRange(strings.TrimSpace(*norm.IPRange))
	}
	if err != nil {
		msg := err.Error()
		code := "INVALID_CIDR"
		status := http.StatusBadRequest
		field := "cidr"
		if norm.IPRange != nil && strings.TrimSpace(*norm.IPRange) != "" && (norm.CIDR == nil || strings.TrimSpace(*norm.CIDR) == "") {
			field = "ip_range"
			code = "INVALID_PARAM"
		}
		if strings.Contains(msg, "max") || strings.Contains(msg, "MaxHosts") {
			code = "CIDR_TOO_LARGE"
			status = http.StatusUnprocessableEntity
		}
		return nil, &validationErr{status, code, msg, field}
	}
	return ips, nil
}

func writeAPIError(w http.ResponseWriter, rid string, status int, code, msg, field string) {
	if rid == "" {
		rid = newScanID()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiErrorResponse{
		Error:     apiErrorBody{Code: code, Message: msg, Field: field},
		RequestID: rid,
	})
}

func newScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefBoolPtr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = newScanID()
			r.Header.Set("X-Request-ID", rid)
		}
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler, allow func(origin string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allow(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Last-Event-ID,X-Request-ID")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
