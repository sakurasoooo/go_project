import type { Host, ScanListResponse, ScanRequest, ScanResult, ScanSummary } from '../types/api'

const API = '/api/v1'

async function parseError(res: Response): Promise<Error> {
  try {
    const body = (await res.json()) as { error?: { code: string; message: string } }
    const msg = body.error?.message ?? res.statusText
    const code = body.error?.code ?? String(res.status)
    return new Error(`${code}: ${msg}`)
  } catch {
    return new Error(res.statusText || String(res.status))
  }
}

export async function createScan(req: ScanRequest): Promise<ScanSummary> {
  const res = await fetch(`${API}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ScanSummary>
}

export async function getScan(id: string): Promise<ScanSummary> {
  const res = await fetch(`${API}/scans/${encodeURIComponent(id)}`)
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ScanSummary>
}

export async function listScans(params?: {
  status?: string
  limit?: number
  cursor?: string
}): Promise<ScanListResponse> {
  const u = new URL(`${API}/scans`, window.location.origin)
  if (params?.status) u.searchParams.set('status', params.status)
  if (params?.limit) u.searchParams.set('limit', String(params.limit))
  if (params?.cursor) u.searchParams.set('cursor', params.cursor)
  const res = await fetch(u.pathname + u.search)
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ScanListResponse>
}

export async function getScanResults(id: string): Promise<ScanResult> {
  const res = await fetch(`${API}/scans/${encodeURIComponent(id)}/results`)
  if (!res.ok) throw await parseError(res)
  return res.json() as Promise<ScanResult>
}

export async function cancelScan(id: string): Promise<void> {
  const res = await fetch(`${API}/scans/${encodeURIComponent(id)}`, { method: 'DELETE' })
  if (!res.ok) throw await parseError(res)
}

export function scanEventsUrl(id: string): string {
  return `${API}/scans/${encodeURIComponent(id)}/events`
}

export function upsertHost(hosts: Host[], h: Host): Host[] {
  const i = hosts.findIndex((x) => x.source === h.source)
  if (i === -1) return [...hosts, h]
  const next = [...hosts]
  next[i] = h
  return next
}
