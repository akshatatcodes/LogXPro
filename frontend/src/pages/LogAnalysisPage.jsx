import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { searchLogs, fetchSavedSearches, saveSearch, deleteSavedSearch, enrichIndicator } from '../api'
import {
  Search, Filter, Clock, ChevronRight, Save, Trash2, Code, ShieldAlert, Zap,
  ExternalLink, FileWarning, ArrowUpRight, Activity, Terminal
} from 'lucide-react'
import { formatTime, formatTimeMs, severityBadgeClass } from '../utils'
import { useNavigate } from 'react-router-dom'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function extractIPs(obj) {
  const ips = new Set()
  const str = JSON.stringify(obj)
  const regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
  let match
  while ((match = regex.exec(str)) !== null) {
    if (!match[0].startsWith('10.') && !match[0].startsWith('192.168.') && !match[0].startsWith('127.')) {
        ips.add(match[0])
    }
  }
  return Array.from(ips)
}

function extractHashes(obj) {
  const hashes = new Set()
  const str = JSON.stringify(obj)
  // Simple MD5/SHA1/SHA256 regex
  const regex = /\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g
  let match
  while ((match = regex.exec(str)) !== null) {
    hashes.add(match[1])
  }
  return Array.from(hashes)
}

// ---------------------------------------------------------------------------
// Event Detail Panel
// ---------------------------------------------------------------------------
function LogEventDetail({ log, onClose }) {
  const [enrichedData, setEnrichedData] = useState({})
  const [enriching, setEnriching] = useState(null)

  const handleEnrich = async (ind, type) => {
    setEnriching(ind)
    try {
      const res = await enrichIndicator(ind, type)
      setEnrichedData(prev => ({ ...prev, [ind]: res.data }))
    } catch (err) {
      setEnrichedData(prev => ({ ...prev, [ind]: { error: 'Failed' } }))
    }
    setEnriching(null)
  }

  const ips = extractIPs(log.raw_event)
  const hashes = extractHashes(log.raw_event)
  
  return (
    <div style={{
      width: 500, background: 'var(--bg-sidebar)', borderLeft: '1px solid var(--border)',
      height: '100%', display: 'flex', flexDirection: 'column',
      position: 'sticky', top: 0
    }} className="fade-in">
      
      {/* Header */}
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Log Event Details</h2>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{log.id}</div>
        </div>
        <button className="btn btn-ghost" onClick={onClose} style={{ padding: 6 }}>
          <ChevronRight size={18} />
        </button>
      </div>

      <div style={{ padding: '20px 24px', flex: 1, overflowY: 'auto' }}>
        {/* Core Info */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Timestamp</div>
            <div style={{ fontSize: 13, fontWeight: 500 }}>{formatTime(log.timestamp)}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Event Type</div>
            <div style={{ fontSize: 13, fontWeight: 500 }}>{log.event_type || '—'}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>Host</div>
            <div className="mono" style={{ fontSize: 13, color: 'var(--accent-bright)' }}>{log.host || '—'}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>User</div>
            <div style={{ fontSize: 13, fontWeight: 500 }}>{log.user || '—'}</div>
          </div>
        </div>

        {/* Indicators & Enrichment */}
        {(ips.length > 0 || hashes.length > 0) && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 12, fontWeight: 700, borderBottom: '1px solid var(--border)', paddingBottom: 8, marginBottom: 12 }}>
              Extracted Indicators
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {ips.map(ip => (
                <div key={ip} className="glass-card" style={{ padding: '12px 14px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div className="mono" style={{ fontSize: 13 }}>{ip} <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 4 }}>(IP)</span></div>
                    {!enrichedData[ip] ? (
                      <button className="btn btn-ghost" style={{ padding: '4px 8px', fontSize: 11 }} onClick={() => handleEnrich(ip, 'ip')} disabled={enriching === ip}>
                        {enriching === ip ? 'Enriching…' : 'Run Enrichment'}
                      </button>
                    ) : (
                      <span className="badge badge-high">Enriched</span>
                    )}
                  </div>
                  {enrichedData[ip] && (
                    <div style={{ marginTop: 10, padding: 10, background: 'rgba(0,0,0,0.2)', borderRadius: 6, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                      {JSON.stringify(enrichedData[ip], null, 2)}
                    </div>
                  )}
                </div>
              ))}
              {hashes.map(h => (
                <div key={h} className="glass-card" style={{ padding: '12px 14px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div className="mono" style={{ fontSize: 11 }}>{h.slice(0, 16)}… <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 4 }}>(Hash)</span></div>
                    {!enrichedData[h] ? (
                      <button className="btn btn-ghost" style={{ padding: '4px 8px', fontSize: 11 }} onClick={() => handleEnrich(h, 'hash')} disabled={enriching === h}>
                        {enriching === h ? 'Enriching…' : 'Run Enrichment'}
                      </button>
                    ) : (
                      <span className="badge badge-high">Enriched</span>
                    )}
                  </div>
                  {enrichedData[h] && (
                    <div style={{ marginTop: 10, padding: 10, background: 'rgba(0,0,0,0.2)', borderRadius: 6, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                      {JSON.stringify(enrichedData[h], null, 2)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Raw JSON */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 700, borderBottom: '1px solid var(--border)', paddingBottom: 8, marginBottom: 12 }}>
            <Code size={14} /> Raw Event JSON
          </div>
          <pre style={{
            background: '#0d1117', border: '1px solid #30363d', padding: '14px 16px',
            borderRadius: 8, fontSize: 11.5, fontFamily: '"JetBrains Mono", monospace',
            color: '#e6edf3', overflowX: 'auto', whiteSpace: 'pre-wrap', lineHeight: 1.6
          }}>
            {JSON.stringify(log.raw_event, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Log Analysis Page
// ---------------------------------------------------------------------------
export default function LogAnalysisPage() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  
  const [q, setQ] = useState('')
  const [host, setHost] = useState('')
  const [timeRange, setTimeRange] = useState('now-24h')
  const [selectedLog, setSelectedLog] = useState(null)
  
  // Search Query
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['logs', q, host, timeRange],
    queryFn: () => searchLogs({ q, host, _from: timeRange }),
    keepPreviousData: true,
    refetchOnWindowFocus: false,
  })

  // Saved Searches
  const { data: savedSearches = [] } = useQuery({
    queryKey: ['saved_searches'],
    queryFn: fetchSavedSearches
  })

  const mutSave = useMutation({
    mutationFn: (name) => saveSearch({ name, query: q }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved_searches'] })
  })

  const mutDelete = useMutation({
    mutationFn: (id) => deleteSavedSearch(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved_searches'] })
  })

  const handleSavePrompt = () => {
    if (!q) return alert("Enter a query first to save.")
    const name = prompt("Enter a name for this saved search:")
    if (name) {
      mutSave.mutate(name)
    }
  }

  const applyShortcut = (queryStr) => {
    setQ(queryStr)
    // Refetch happens automatically due to queryKey change
  }

  const logs = data?.logs || []
  const total = data?.total || 0

  return (
    <div style={{ display: 'flex', height: '100%' }}>
      {/* Main Content */}
      <div style={{ flex: 1, padding: '28px 32px', overflowY: 'auto' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
          <div>
            <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={22} color="var(--accent-bright)" /> Log Analysis
            </h1>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              Direct Elasticsearch query interface. Lucene syntax supported.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn btn-ghost" onClick={handleSavePrompt} disabled={!q || mutSave.isPending}>
              <Save size={14} /> Save Search
            </button>
            <button className="btn btn-primary" onClick={() => refetch()} disabled={isFetching}>
              <Search size={14} /> {isFetching ? 'Searching…' : 'Search'}
            </button>
          </div>
        </div>

        {/* Search Controls */}
        <div className="glass-card" style={{ padding: '16px 20px', marginBottom: 20 }}>
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Elasticsearch query string (e.g. event_type: \u0022Process Creation\u0022 AND powershell)"
                value={q}
                onChange={e => setQ(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && refetch()}
                style={{ width: '100%', paddingLeft: 36, fontSize: 14 }}
              />
            </div>
            <input
              type="text"
              placeholder="Host filter"
              value={host}
              onChange={e => setHost(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && refetch()}
              style={{ width: 180 }}
            />
            <select value={timeRange} onChange={e => setTimeRange(e.target.value)} style={{ width: 140 }}>
              <option value="now-1h">Last 1 Hour</option>
              <option value="now-24h">Last 24 Hours</option>
              <option value="now-7d">Last 7 Days</option>
              <option value="now-30d">Last 30 Days</option>
              <option value="all">All Time</option>
            </select>
          </div>

          {/* Shortcuts */}
          <div style={{ display: 'flex', gap: 8, marginTop: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginRight: 4 }}>Shortcuts:</span>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11.5 }} onClick={() => applyShortcut('severity:(high OR critical)')}>
              High/Critical Events
            </button>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11.5 }} onClick={() => applyShortcut('event_type:"Failed Logon"')}>
              Failed Logons
            </button>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11.5 }} onClick={() => applyShortcut('powershell.exe OR pwsh.exe')}>
              PowerShell Executions
            </button>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11.5 }} onClick={() => applyShortcut('event_type:"Outbound Connection"')}>
              Outbound Connections
            </button>
          </div>

          {/* Saved Searches */}
          {savedSearches.length > 0 && (
            <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent-bright)', textTransform: 'uppercase', marginRight: 4 }}>Saved:</span>
              {savedSearches.map(s => (
                <div key={s.id} style={{ display: 'flex', alignItems: 'center', background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.2)', borderRadius: 6, overflow: 'hidden' }}>
                  <button
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', padding: '4px 8px', fontSize: 11.5, cursor: 'pointer' }}
                    onClick={() => applyShortcut(s.query)}
                  >
                    {s.name}
                  </button>
                  <button
                    style={{ background: 'rgba(244,63,94,0.1)', border: 'none', borderLeft: '1px solid rgba(139,92,246,0.2)', color: '#f43f5e', padding: '4px 6px', cursor: 'pointer' }}
                    onClick={() => mutDelete.mutate(s.id)}
                    title="Delete saved search"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Results Info */}
        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
          {isLoading || isFetching ? 'Searching...' : `Found ${total} matching events`}
        </div>

        {/* Table */}
        <div className="glass-card" style={{ overflow: 'hidden' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Host</th>
                <th>User</th>
                <th>Event Type</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && !isLoading && !isFetching && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: 48, color: 'var(--text-muted)' }}>
                    No logs matched the query.
                  </td>
                </tr>
              )}
              {logs.map(log => {
                const isSelected = selectedLog?.id === log.id
                return (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(isSelected ? null : log)}
                    style={{ background: isSelected ? 'rgba(139,92,246,0.08)' : undefined }}
                  >
                    <td style={{ whiteSpace: 'nowrap', fontFamily: '"JetBrains Mono", monospace', fontSize: 12 }}>{formatTimeMs(log.timestamp)}</td>
                    <td className="mono">{log.host || '—'}</td>
                    <td>{log.user || '—'}</td>
                    <td>{log.event_type || '—'}</td>
                    <td><span className={severityBadgeClass(log.severity)}>{log.severity}</span></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

      </div>

      {/* Details Side Panel */}
      {selectedLog && (
        <LogEventDetail log={selectedLog} onClose={() => setSelectedLog(null)} />
      )}
    </div>
  )
}
