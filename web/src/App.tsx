import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  cancelScan,
  createScan,
  getScanResults,
  scanEventsUrl,
  upsertHost,
} from './api/client'
import type { Host, ScanSummary } from './types/api'
import './App.css'

type Mode = 'cidr' | 'ip_range'

export default function App() {
  const [mode, setMode] = useState<Mode>('cidr')
  const [cidr, setCidr] = useState('192.168.1.0/24')
  const [ipRange, setIpRange] = useState('')
  const [ports, setPorts] = useState('5353')
  const [workers, setWorkers] = useState(64)
  const [timeout, setTimeoutStr] = useState('800ms')
  const [enumerate, setEnumerate] = useState(true)
  const [tcp, setTcp] = useState(false)

  const [scanId, setScanId] = useState<string | null>(null)
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const progress = useMemo(() => {
    if (!summary?.targets_total) return 0
    return summary.targets_done / summary.targets_total
  }, [summary])

  const subscribeSSE = useCallback((id: string) => {
    const url = scanEventsUrl(id)
    const es = new EventSource(url)
    es.addEventListener('progress', (e) => {
      const p = JSON.parse(e.data) as { targets_done: number; targets_total: number }
      setSummary((s) =>
        s
          ? { ...s, targets_done: p.targets_done, targets_total: p.targets_total }
          : s,
      )
    })
    es.addEventListener('host', (e) => {
      const h = JSON.parse(e.data) as Host
      setHosts((prev) => upsertHost(prev, h))
    })
    es.addEventListener('status', (e) => {
      const s = JSON.parse(e.data) as ScanSummary
      setSummary(s)
      if (s.status !== 'running' && s.status !== 'queued') {
        es.close()
        void getScanResults(id).then((r) => {
          setSummary(r.scan)
          setHosts(r.hosts)
          setBusy(false)
        })
      }
    })
    es.onerror = () => {
      /* browser may auto-reconnect; leave as-is until status closes */
    }
    return () => es.close()
  }, [])

  useEffect(() => {
    if (!scanId) return
    const close = subscribeSSE(scanId)
    return close
  }, [scanId, subscribeSSE])

  async function startScan() {
    setError(null)
    setBusy(true)
    setHosts([])
    setSummary(null)
    try {
      const body =
        mode === 'cidr'
          ? { cidr, ports, workers, timeout, enumerate, tcp }
          : { ip_range: ipRange, ports, workers, timeout, enumerate, tcp }
      const sum = await createScan(body)
      setScanId(sum.id)
      setSummary(sum)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  async function stopScan() {
    if (!scanId) return
    try {
      await cancelScan(scanId)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="app">
      <header>
        <h1>mdns-survey</h1>
        <p className="sub">DNS-SD / unicast mDNS probe UI — API per docs/API.md</p>
      </header>

      <section className="panel">
        <div className="row">
          <label>
            <input
              type="radio"
              name="m"
              checked={mode === 'cidr'}
              onChange={() => setMode('cidr')}
            />{' '}
            CIDR
          </label>
          <label>
            <input
              type="radio"
              name="m"
              checked={mode === 'ip_range'}
              onChange={() => setMode('ip_range')}
            />{' '}
            IP range
          </label>
        </div>
        {mode === 'cidr' ? (
          <label className="block">
            CIDR
            <input value={cidr} onChange={(e) => setCidr(e.target.value)} />
          </label>
        ) : (
          <label className="block">
            IP range
            <input
              value={ipRange}
              onChange={(e) => setIpRange(e.target.value)}
              placeholder="192.168.1.1-192.168.1.20"
            />
          </label>
        )}
        <label className="block">
          Ports
          <input value={ports} onChange={(e) => setPorts(e.target.value)} />
        </label>
        <div className="row2">
          <label>
            Workers
            <input
              type="number"
              min={1}
              max={4096}
              value={workers}
              onChange={(e) => setWorkers(Number(e.target.value))}
            />
          </label>
          <label>
            Timeout
            <input value={timeout} onChange={(e) => setTimeoutStr(e.target.value)} />
          </label>
        </div>
        <label className="inline">
          <input
            type="checkbox"
            checked={enumerate}
            onChange={(e) => setEnumerate(e.target.checked)}
          />{' '}
          Enumerate (_services._dns-sd._udp.local.)
        </label>
        <label className="inline">
          <input type="checkbox" checked={tcp} onChange={(e) => setTcp(e.target.checked)} />{' '}
          TCP probes
        </label>
        <div className="actions">
          <button type="button" disabled={busy} onClick={() => void startScan()}>
            Start scan
          </button>
          <button type="button" disabled={!busy || !scanId} onClick={() => void stopScan()}>
            Cancel
          </button>
        </div>
      </section>

      {error && <div className="err">{error}</div>}

      {summary && (
        <section className="panel">
          <h2>Status</h2>
          <dl className="dl">
            <dt>ID</dt>
            <dd>{summary.id}</dd>
            <dt>State</dt>
            <dd>{summary.status}</dd>
            <dt>Progress</dt>
            <dd>
              {summary.targets_done} / {summary.targets_total} targets ·{' '}
              {summary.hosts_with_results} hosts with results
            </dd>
          </dl>
          <div className="bar">
            <div className="fill" style={{ width: `${Math.round(progress * 100)}%` }} />
          </div>
        </section>
      )}

      {hosts.length > 0 && (
        <section className="panel">
          <h2>Hosts ({hosts.length})</h2>
          <div className="hosts">
            {hosts.map((h) => (
              <article key={h.source} className="host">
                <h3>
                  {h.source} — {h.ip}:{h.probe_port}
                </h3>
                <ul className="svc">
                  {(h.services ?? []).map((s, i) => (
                    <li key={`${s.type}-${i}`}>
                      <strong>
                        {s.port}/{s.transport} {s.short_name}
                      </strong>{' '}
                      <span className="muted">{s.name}</span>
                      <div className="meta">
                        hostname={s.hostname} ttl={s.ttl} ipv4={s.ipv4} ipv6={s.ipv6}
                      </div>
                      {(s.txt ?? []).length > 0 && (
                        <pre className="txt">{(s.txt ?? []).join('\n')}</pre>
                      )}
                    </li>
                  ))}
                </ul>
                {(h.ptrs ?? []).length > 0 && (
                  <div className="ptrs">
                    <span className="label">PTRs:</span> {(h.ptrs ?? []).join(', ')}
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
