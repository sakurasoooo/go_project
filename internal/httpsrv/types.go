package httpsrv

import (
	"time"

	"github.com/zjw-swun/mdns-survey/internal/model"
)

// API payloads mirror docs/API.md (snake_case JSON).

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

type apiErrorResponse struct {
	Error     apiErrorBody `json:"error"`
	RequestID string       `json:"request_id"`
}

type ScanRequest struct {
	CIDR         *string  `json:"cidr,omitempty"`
	IPRange      *string  `json:"ip_range,omitempty"`
	Ports        *string  `json:"ports,omitempty"`
	Timeout      *string  `json:"timeout,omitempty"`
	Workers      *int     `json:"workers,omitempty"`
	Iface        *string  `json:"iface,omitempty"`
	ExtraPTRList []string `json:"extra_ptr_list,omitempty"`
	Enumerate    *bool    `json:"enumerate,omitempty"`
	TCP          *bool    `json:"tcp,omitempty"`
}

type ScanSummary struct {
	ID                 string         `json:"id"`
	Status             string         `json:"status"`
	Request            ScanRequest    `json:"request"`
	TargetsTotal       int            `json:"targets_total"`
	TargetsDone        int            `json:"targets_done"`
	HostsWithResults   int            `json:"hosts_with_results"`
	CreatedAt          time.Time      `json:"created_at"`
	StartedAt          *time.Time     `json:"started_at,omitempty"`
	FinishedAt         *time.Time     `json:"finished_at,omitempty"`
	Error              *apiErrorBody  `json:"error,omitempty"`
}

type ScanResult struct {
	Scan  ScanSummary   `json:"scan"`
	Hosts []*model.Host `json:"hosts"`
}

type scanListResponse struct {
	Items      []ScanSummary `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type progressEvent struct {
	TargetsDone  int `json:"targets_done"`
	TargetsTotal int `json:"targets_total"`
}

type serviceEvent struct {
	Source  string         `json:"source"`
	Service *model.Service `json:"service"`
}

type healthResponse struct {
	Status         string `json:"status"`
	Version        string `json:"version"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
}

type ptrDefaultsResponse struct {
	PTRList []string `json:"ptr_list"`
}

type deleteScanResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}
