// Mirrors docs/API.md §2

export type UUID = string
export type ISO8601 = string
export type DurationStr = string

export interface ApiError {
  error: { code: string; message: string; field?: string }
  request_id: string
}

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'canceled'

export interface ScanRequest {
  cidr?: string
  ip_range?: string
  ports?: string
  timeout?: DurationStr
  workers?: number
  iface?: string
  extra_ptr_list?: string[]
  enumerate?: boolean
  tcp?: boolean
}

export interface ScanSummary {
  id: UUID
  status: ScanStatus
  request: ScanRequest
  targets_total: number
  targets_done: number
  hosts_with_results: number
  created_at: ISO8601
  started_at?: ISO8601
  finished_at?: ISO8601
  error?: ApiError['error']
}

export interface Service {
  type: string
  short_name: string
  transport: string
  port: number
  name: string
  hostname: string
  ipv4: string
  ipv6: string
  ttl: number
  txt: string[]
}

export interface Host {
  source: string
  ip: string
  probe_port: number
  services: Service[]
  ptrs: string[]
}

export interface ScanResult {
  scan: ScanSummary
  hosts: Host[]
}

export interface ScanListResponse {
  items: ScanSummary[]
  next_cursor?: string
}
