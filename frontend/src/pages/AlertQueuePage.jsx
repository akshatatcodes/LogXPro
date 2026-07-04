import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAlerts, assignAlert, closeAlert, markFalsePositive } from '../api'
import {
  ChevronDown, ChevronRight, Shield, User, Monitor, Clock,
  CheckCircle2, XCircle, AlertTriangle, ExternalLink,
  GitBranch, Brain, Layers, Search, Filter, RefreshCw,
  UserCheck, FileWarning, Gavel, ArrowUpRight
} from 'lucide-react'
import {
  severityFromScore, statusBadgeClass, severityBadgeClass,
  formatTime, relativeTime, ANALYSTS, mitreLabel
} from '../utils'
import { useNavigate } from 'react-router-dom'

// ---------------------------------------------------------------------------
// Enrichment Cards
// ---------------------------------------------------------------------------
function EnrichmentCard({ ip, data }) {
  const vt = data?.virustotal || {}
  const ab = data?.abuseipdb  || {}
  const ms = data?.misp       || {}

  const vtScore = vt.malicious && vt.total ? Math.round((vt.malicious / vt.total) * 100) : 0

  return (
    <div className="glass-card" style={{ padding: '14px 16px' }}>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600, color: 'var(--accent-bright)', marginBottom: 12 }}>
        🌐 {ip}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        {/* VT */}
        <div style={{ background: 'rgba(244,63,94,0.08)', borderRadius: 8, padding: '10px 12px', border: '1px solid rgba(244,63,94,0.2)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#f43f5e', marginBottom: 6 }}>VirusTotal</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#f43f5e' }}>{vt.malicious ?? '—'}<span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/{vt.total ?? '—'}</span></div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>malicious · {vt.country || '—'}</div>
        </div>
        {/* AbuseIPDB */}
        <div style={{ background: 'rgba(249,115,22,0.08)', borderRadius: 8, padding: '10px 12px', border: '1px solid rgba(249,115,22,0.2)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#f97316', marginBottom: 6 }}>AbuseIPDB</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#f97316' }}>{ab.abuse_score ?? '—'}<span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/100</span></div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{ab.total_reports ?? '—'} reports</div>
        </div>
        {/* MISP */}
        <div style={{ background: 'rgba(139,92,246,0.08)', borderRadius: 8, padding: '10px 12px', border: '1px solid rgba(139,92,246,0.2)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent-bright)', marginBottom: 6 }}>MISP</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: ms.found ? '#a78bfa' : 'var(--text-muted)' }}>
            {ms.found ? '✓' : '—'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            {ms.tags?.slice(0,2).join(', ') || (ms.found ? 'Known IOC' : 'Not found')}
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Kill Chain Timeline
// ---------------------------------------------------------------------------
function KillChainTimeline({ events, stages }) {
  // Build timeline from events if available, else from matched_stages
  const items = events?.length > 0
    ? events.map((e, i) => ({
        step: i + 1,
        time: e.event_time || e.ingestion_time,
        title: e.event_type || e.mitre_technique,
        mitre: e.mitre_technique,
        detail: e.raw_event?.command_line || e.raw_event?.destination_ip || e.raw_event?.source_ip || ''
      }))
    : (stages || []).map((s, i) => ({
        step: s.stage || i + 1,
        time: null,
        title: mitreLabel(s.mitre),
        mitre: s.mitre,
        detail: ''
      }))

  const stepColors = ['#06b6d4', '#eab308', '#f97316', '#f43f5e', '#a78bfa', '#f43f5e']

  return (
    <div>
      {items.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No chain steps recorded.</div>
      ) : (
        items.map((item, idx) => (
          <div key={idx} className="timeline-step">
            {/* Step dot */}
            <div style={{
              width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
              background: `rgba(${hexToRgb(stepColors[idx % stepColors.length])}, 0.15)`,
              border: `2px solid ${stepColors[idx % stepColors.length]}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700,
              color: stepColors[idx % stepColors.length],
              boxShadow: `0 0 8px ${stepColors[idx % stepColors.length]}40`,
              zIndex: 1, position: 'relative'
            }}>
              {item.step}
            </div>
            <div style={{ flex: 1, paddingTop: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2, flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{item.title}</span>
                {item.mitre && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                    background: 'rgba(139,92,246,0.15)', color: 'var(--accent-bright)',
                    border: '1px solid rgba(139,92,246,0.3)', fontFamily: 'monospace'
                  }}>{item.mitre}</span>
                )}
                {item.time && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{formatTime(item.time)}</span>
                )}
              </div>
              {item.detail && (
                <div style={{
                  fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace',
                  background: 'rgba(0,0,0,0.3)', padding: '4px 8px', borderRadius: 5, marginTop: 4,
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 520
                }}>
                  {String(item.detail).slice(0, 120)}
                </div>
              )}
            </div>
          </div>
        ))
      )}
    </div>
  )
}

function hexToRgb(hex) {
  const res = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return res ? `${parseInt(res[1],16)},${parseInt(res[2],16)},${parseInt(res[3],16)}` : '255,255,255'
}

// ---------------------------------------------------------------------------
// AI Narrative renderer (basic markdown → HTML-ish)
// ---------------------------------------------------------------------------
function AINarrative({ text }) {
  if (!text) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No AI narrative available.</div>

  const parts = text.split(/(\*\*[^*]+\*\*)/g)
  return (
    <div style={{
      fontSize: 13.5, lineHeight: 1.75, color: 'var(--text-secondary)',
      whiteSpace: 'pre-wrap'
    }}>
      {parts.map((p, i) =>
        p.startsWith('**') && p.endsWith('**')
          ? <strong key={i} style={{ color: 'var(--text-primary)', fontWeight: 700 }}>{p.slice(2, -2)}</strong>
          : <span key={i}>{p}</span>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Expanded alert detail panel
// ---------------------------------------------------------------------------
function AlertDetail({ alert, onClose }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [analyst, setAnalyst] = useState(alert.assigned_to || '')
  const [actionMsg, setActionMsg] = useState(null)

  const bid = alert.basket_id

  const mutAssign = useMutation({
    mutationFn: (name) => assignAlert(bid, name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Assigned ✓') }
  })
  const mutClose = useMutation({
    mutationFn: () => closeAlert(bid, analyst || 'analyst'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Closed as Resolved ✓') }
  })
  const mutFP = useMutation({
    mutationFn: () => markFalsePositive(bid, { analyst_name: analyst || 'analyst', host_name: alert.host_name, user_name: alert.user_name }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Marked as False Positive ✓ · Suppression added') }
  })

  const enrichmentEntries = Object.entries(alert.enrichment || {})

  return (
    <div style={{
      borderTop: '1px solid rgba(139,92,246,0.2)',
      background: 'rgba(139,92,246,0.04)',
      padding: '20px 24px 24px'
    }} className="fade-in">

      {/* Three sections in tabs conceptually — shown as blocks */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>

        {/* Kill Chain */}
        <div className="glass-card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <GitBranch size={15} color="var(--accent-bright)" />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Kill Chain Timeline</span>
          </div>
          <KillChainTimeline events={alert.events} stages={alert.matched_stages} />
        </div>

        {/* Enrichment + AI */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Enrichment */}
          <div className="glass-card" style={{ padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
              <Shield size={15} color="#f97316" />
              <span style={{ fontWeight: 700, fontSize: 14 }}>Threat Intelligence</span>
            </div>
            {enrichmentEntries.length > 0 ? (
              enrichmentEntries.map(([ip, data]) => (
                <EnrichmentCard key={ip} ip={ip} data={data} />
              ))
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No enrichment data.</div>
            )}
          </div>

          {/* AI Narrative */}
          <div className="glass-card" style={{ padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
              <Brain size={15} color="#a78bfa" />
              <span style={{ fontWeight: 700, fontSize: 14 }}>AI Narrative</span>
            </div>
            <AINarrative text={alert.ai_narrative} />
          </div>
        </div>
      </div>

      {/* Actions bar */}
      <div className="glass-card" style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 200 }}>
            <UserCheck size={15} color="var(--text-muted)" />
            <span style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>Assign to:</span>
            <select
              value={analyst}
              onChange={e => setAnalyst(e.target.value)}
              style={{ flex: 1, minWidth: 140 }}
            >
              <option value="">— Select analyst —</option>
              {ANALYSTS.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
            <button
              className="btn btn-primary"
              disabled={!analyst || mutAssign.isPending}
              onClick={() => mutAssign.mutate(analyst)}
              style={{ whiteSpace: 'nowrap' }}
            >
              {mutAssign.isPending ? 'Assigning…' : 'Assign'}
            </button>
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              className="btn btn-success"
              onClick={() => mutClose.mutate()}
              disabled={mutClose.isPending}
            >
              <CheckCircle2 size={14} />
              {mutClose.isPending ? 'Closing…' : 'Close as Resolved'}
            </button>
            <button
              className="btn btn-warning"
              onClick={() => mutFP.mutate()}
              disabled={mutFP.isPending}
            >
              <FileWarning size={14} />
              {mutFP.isPending ? 'Marking…' : 'Mark False Positive'}
            </button>
            <button
              className="btn btn-ghost"
              onClick={() => navigate('/cases/write', { state: { alert } })}
            >
              <ArrowUpRight size={14} />
              Escalate to Case
            </button>
          </div>
        </div>

        {actionMsg && (
          <div style={{
            marginTop: 10, padding: '8px 14px', borderRadius: 7,
            background: 'rgba(16,185,129,0.12)', color: '#10b981',
            fontSize: 13, fontWeight: 600,
            border: '1px solid rgba(16,185,129,0.3)'
          }}>
            ✓ {actionMsg}
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Alert Queue Page
// ---------------------------------------------------------------------------
export default function AlertQueuePage() {
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const LIMIT = 8

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['alerts', page, statusFilter],
    queryFn: () => fetchAlerts({ page, limit: LIMIT, status: statusFilter || undefined }),
    keepPreviousData: true,
    refetchInterval: 30000,
  })

  const alerts = (data?.alerts || []).filter(a => {
    if (!searchTerm) return true
    const s = searchTerm.toLowerCase()
    return (
      a.host_name?.toLowerCase().includes(s) ||
      a.user_name?.toLowerCase().includes(s) ||
      a.source_ip?.toLowerCase().includes(s) ||
      a.basket_id?.toLowerCase().includes(s)
    )
  })

  const total = data?.total || 0
  const pages = data?.pages || 1

  function toggleRow(id) {
    setExpandedId(prev => prev === id ? null : id)
  }

  const STATUS_OPTS = [
    { value: '', label: 'All Statuses' },
    { value: 'open', label: 'Open' },
    { value: 'closed', label: 'Closed' },
    { value: 'fp', label: 'False Positive' },
    { value: 'confirmed', label: 'Confirmed' },
  ]

  return (
    <div style={{ padding: '28px 32px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 4 }}>Alert Queue</h1>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            {isLoading ? 'Loading…' : `${total} alert${total !== 1 ? 's' : ''} — click any row to expand`}
          </div>
        </div>
        <button className="btn btn-ghost" onClick={() => refetch()}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 18, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search host, user, IP…"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            style={{ paddingLeft: 32, width: 240 }}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Filter size={14} color="var(--text-muted)" />
          <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}>
            {STATUS_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
            <ShieldOff />
            <div style={{ marginTop: 10 }}>No alerts found.</div>
          </div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>Severity</th>
                <th>Host</th>
                <th>User</th>
                <th>Chain / MITRE</th>
                <th>Confidence</th>
                <th>Time</th>
                <th>Assigned</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => {
                const severity = severityFromScore(alert.confidence_score)
                const isExpanded = expandedId === alert.basket_id
                const stages = alert.matched_stages || []

                return (
                  <>
                    <tr
                      key={alert.basket_id}
                      onClick={() => toggleRow(alert.basket_id)}
                      style={{ background: isExpanded ? 'rgba(139,92,246,0.08)' : undefined }}
                    >
                      {/* Expand chevron */}
                      <td style={{ paddingLeft: 16, paddingRight: 4 }}>
                        {isExpanded
                          ? <ChevronDown size={15} color="var(--accent-bright)" />
                          : <ChevronRight size={15} color="var(--text-muted)" />
                        }
                      </td>

                      {/* Severity badge */}
                      <td>
                        <span className={severityBadgeClass(severity)}>
                          {severity}
                        </span>
                      </td>

                      {/* Host */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <Monitor size={13} color="var(--text-muted)" />
                          <span className="mono" style={{ fontSize: 13 }}>{alert.host_name}</span>
                        </div>
                      </td>

                      {/* User */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <User size={12} color="var(--text-muted)" />
                          <span style={{ fontSize: 13 }}>{alert.user_name || '—'}</span>
                        </div>
                      </td>

                      {/* Chain */}
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {stages.slice(0, 2).map((s, i) => (
                            <span key={i} style={{
                              fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                              background: 'rgba(139,92,246,0.15)', color: 'var(--accent-bright)',
                              border: '1px solid rgba(139,92,246,0.25)', fontFamily: 'monospace'
                            }}>{s.mitre}</span>
                          ))}
                          {stages.length > 2 && (
                            <span style={{ fontSize: 11, color: 'var(--text-muted)', alignSelf: 'center' }}>
                              +{stages.length - 2}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Confidence */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{
                            width: 48, height: 5, borderRadius: 3,
                            background: 'rgba(255,255,255,0.08)', overflow: 'hidden'
                          }}>
                            <div style={{
                              height: '100%',
                              width: `${alert.confidence_score}%`,
                              background: severity === 'critical' ? '#f43f5e'
                                : severity === 'high' ? '#f97316'
                                : severity === 'medium' ? '#eab308'
                                : '#06b6d4',
                              borderRadius: 3
                            }} />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)' }}>
                            {alert.confidence_score}%
                          </span>
                        </div>
                      </td>

                      {/* Time */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <Clock size={12} color="var(--text-muted)" />
                          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                            {relativeTime(alert.updated_at)}
                          </span>
                        </div>
                      </td>

                      {/* Assigned */}
                      <td>
                        <span style={{ fontSize: 12, color: alert.assigned_to ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                          {alert.assigned_to || 'Unassigned'}
                        </span>
                      </td>

                      {/* Status */}
                      <td onClick={e => e.stopPropagation()}>
                        <span className={statusBadgeClass(alert.status)}>
                          {alert.status}
                        </span>
                      </td>
                    </tr>

                    {/* Expanded detail row */}
                    {isExpanded && (
                      <tr key={`${alert.basket_id}-detail`}>
                        <td colSpan={9} style={{ padding: 0 }}>
                          <AlertDetail alert={alert} onClose={() => setExpandedId(null)} />
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 20 }}>
          <button
            className="btn btn-ghost"
            disabled={page <= 1}
            onClick={() => setPage(p => p - 1)}
          >
            ← Previous
          </button>
          {Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1).map(p => (
            <button
              key={p}
              onClick={() => setPage(p)}
              style={{
                width: 36, height: 36, borderRadius: 8, border: 'none',
                background: p === page ? 'rgba(139,92,246,0.25)' : 'rgba(255,255,255,0.05)',
                color: p === page ? 'var(--accent-bright)' : 'var(--text-secondary)',
                fontWeight: 600, fontSize: 13, cursor: 'pointer',
                transition: 'all 0.15s'
              }}
            >
              {p}
            </button>
          ))}
          <button
            className="btn btn-ghost"
            disabled={page >= pages}
            onClick={() => setPage(p => p + 1)}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}

function ShieldOff() {
  return (
    <div style={{ color: 'var(--text-muted)', opacity: 0.4 }}>
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.25C17.25 23.15 21 18.25 21 13V7L12 2z" />
        <line x1="3" y1="3" x2="21" y2="21" />
      </svg>
    </div>
  )
}
