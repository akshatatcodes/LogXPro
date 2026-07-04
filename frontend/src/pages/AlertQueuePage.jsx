import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAlerts, assignAlert, closeAlert, markFalsePositive, fetchAnalysts } from '../api'
import {
  ChevronDown, ChevronRight, Shield, User, Monitor, Clock,
  CheckCircle2, XCircle, AlertTriangle, GitBranch, Brain,
  Search, RefreshCw, UserCheck, FileWarning, FileText, ArrowUpRight
} from 'lucide-react'
import {
  severityFromScore, statusBadgeClass, severityBadgeClass,
  formatTime, relativeTime, mitreLabel
} from '../utils'
import { useNavigate } from 'react-router-dom'

/* ── Helpers ──────────────────────────────────────────────── */
function hexToRgb(hex) {
  const res = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return res ? `${parseInt(res[1],16)},${parseInt(res[2],16)},${parseInt(res[3],16)}` : '0,0,0'
}

/* ── Threat Intelligence Card ─────────────────────────────── */
function ThreatIntelCard({ ip, data }) {
  const vt = data?.virustotal || {}
  const ab = data?.abuseipdb  || {}
  const ms = data?.misp       || {}

  return (
    <div style={{
      background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 10, padding: '14px 16px', marginBottom: 10
    }}>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600, color: '#4f46e5', marginBottom: 12 }}>
        🌐 {ip}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        <div style={{ background: '#fff', borderRadius: 8, padding: '10px 12px', border: '1px solid #fecaca' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: '#dc2626', marginBottom: 6 }}>VirusTotal</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#dc2626' }}>{vt.malicious ?? '—'}<span style={{ fontSize: 12, color: '#94a3b8' }}>/{vt.total ?? '—'}</span></div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>malicious · {vt.country || '—'}</div>
        </div>
        <div style={{ background: '#fff', borderRadius: 8, padding: '10px 12px', border: '1px solid #fed7aa' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: '#ea580c', marginBottom: 6 }}>AbuseIPDB</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#ea580c' }}>{ab.abuse_score ?? '—'}<span style={{ fontSize: 12, color: '#94a3b8' }}>/100</span></div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>{ab.total_reports ?? '—'} reports</div>
        </div>
        <div style={{ background: '#fff', borderRadius: 8, padding: '10px 12px', border: '1px solid #c7d2fe' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: '#4f46e5', marginBottom: 6 }}>MISP</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: ms.found ? '#4f46e5' : '#94a3b8' }}>
            {ms.found ? '✓' : '—'}
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
            {ms.tags?.slice(0,2).join(', ') || (ms.found ? 'Known IOC' : 'Not found')}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Kill Chain Timeline ──────────────────────────────────── */
function KillChainTimeline({ events, stages }) {
  const stepColors = ['#0891b2', '#ca8a04', '#ea580c', '#dc2626', '#4f46e5']
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

  return (
    <div>
      {items.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No chain steps recorded.</div>
      ) : (
        items.map((item, idx) => (
          <div key={idx} className="timeline-step">
            <div style={{
              width: 30, height: 30, borderRadius: '50%', flexShrink: 0,
              background: stepColors[idx % stepColors.length] + '15',
              border: `2px solid ${stepColors[idx % stepColors.length]}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 700,
              color: stepColors[idx % stepColors.length],
              zIndex: 1, position: 'relative'
            }}>
              {item.step}
            </div>
            <div style={{ flex: 1, paddingTop: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2, flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{item.title || '—'}</span>
                {item.mitre && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 4,
                    background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe', fontFamily: 'monospace'
                  }}>{item.mitre}</span>
                )}
                {item.time && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{formatTime(item.time)}</span>
                )}
              </div>
              {item.detail && (
                <div style={{
                  fontSize: 11, color: '#64748b', fontFamily: 'JetBrains Mono, monospace',
                  background: '#f8fafc', padding: '4px 8px', borderRadius: 5, marginTop: 4,
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 480
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

/* ── AI Narrative ─────────────────────────────────────────── */
function AINarrative({ text }) {
  if (!text) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No AI narrative available for this alert.</div>
  const parts = text.split(/(\*\*[^*]+\*\*)/g)
  return (
    <div style={{ fontSize: 13.5, lineHeight: 1.75, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
      {parts.map((p, i) =>
        p.startsWith('**') && p.endsWith('**')
          ? <strong key={i} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{p.slice(2, -2)}</strong>
          : <span key={i}>{p}</span>
      )}
    </div>
  )
}

/* ── Expanded Alert Detail ────────────────────────────────── */
function AlertDetail({ alert, onClose }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [analyst, setAnalyst] = useState(alert.assigned_to || '')
  const [actionMsg, setActionMsg] = useState(null)

  // Live analyst list from Admin Panel
  const { data: analysts = [] } = useQuery({
    queryKey: ['analysts'],
    queryFn: fetchAnalysts,
    staleTime: 60_000,
  })

  const bid = alert.basket_id

  const mutAssign = useMutation({
    mutationFn: (name) => assignAlert(bid, name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Alert assigned successfully.') }
  })
  const mutClose = useMutation({
    mutationFn: () => closeAlert(bid, analyst || 'analyst'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Alert closed as resolved.') }
  })
  const mutFP = useMutation({
    mutationFn: () => markFalsePositive(bid, { analyst_name: analyst || 'analyst', host_name: alert.host_name, user_name: alert.user_name }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Marked as False Positive. Suppression rule added.') }
  })

  const enrichmentEntries = Object.entries(alert.enrichment || {})

  return (
    <tr>
      <td colSpan={9} style={{ padding: 0, background: '#f8fafc', borderBottom: '1px solid #e2e8f0' }}>
        <div style={{ padding: '20px 24px' }} className="fade-in">

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
            {/* Kill Chain */}
            <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 12, padding: '18px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <GitBranch size={15} color="var(--accent)" />
                <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Kill Chain Timeline</span>
              </div>
              <KillChainTimeline events={alert.events} stages={alert.matched_stages} />
            </div>

            {/* Right column: TI + AI */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 12, padding: '18px 20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                  <Shield size={15} color="#ea580c" />
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Threat Intelligence</span>
                </div>
                {enrichmentEntries.length > 0 ? (
                  enrichmentEntries.map(([ip, data]) => (
                    <ThreatIntelCard key={ip} ip={ip} data={data} />
                  ))
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '8px 0' }}>
                    No enrichment data for this alert. IPs may not have been enriched yet.
                  </div>
                )}
              </div>

              <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 12, padding: '18px 20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                  <Brain size={15} color="#7c3aed" />
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>AI Narrative</span>
                </div>
                <AINarrative text={alert.ai_narrative} />
              </div>
            </div>
          </div>

          {/* Actions bar */}
          <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 12, padding: '14px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              {/* Assign */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 200 }}>
                <UserCheck size={15} color="var(--text-muted)" />
                <span style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>Assign to:</span>
                <select
                  value={analyst}
                  onChange={e => setAnalyst(e.target.value)}
                  style={{ flex: 1, minWidth: 140, fontSize: 13 }}
                >
                  <option value="">— Select analyst —</option>
                  {analysts.map(a => (
                    <option key={a.id} value={a.name}>
                      {a.name}{a.role ? ` (${a.role})` : ''}
                    </option>
                  ))}
                </select>
                <button
                  className="btn btn-primary"
                  disabled={!analyst || mutAssign.isPending}
                  onClick={() => mutAssign.mutate(analyst)}
                  style={{ whiteSpace: 'nowrap', fontSize: 13 }}
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
                  {mutFP.isPending ? 'Marking…' : 'False Positive'}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() => navigate('/cases/write', { state: { alert } })}
                  style={{ borderColor: '#c7d2fe', color: '#4f46e5' }}
                >
                  <ArrowUpRight size={14} />
                  Escalate to Case
                </button>
              </div>
            </div>

            {actionMsg && (
              <div style={{
                marginTop: 12, padding: '8px 14px', borderRadius: 8,
                background: '#f0fdf4', color: '#16a34a',
                fontSize: 13, fontWeight: 500, border: '1px solid #bbf7d0'
              }}>
                ✓ {actionMsg}
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}

/* ── Main Alert Queue Page ────────────────────────────────── */
export default function AlertQueuePage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const LIMIT = 10

  const { data, isLoading, isFetching } = useQuery({
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
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>Alert Queue</h1>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            {isLoading ? 'Loading…' : `${total} alert${total !== 1 ? 's' : ''} — click any row to expand details`}
          </div>
        </div>
        <button className="btn btn-ghost" onClick={() => queryClient.invalidateQueries()} disabled={isFetching}>
          <RefreshCw size={14} className={isFetching ? "animate-spin" : ""} /> Refresh
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
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}>
          {STATUS_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
            <AlertTriangle size={32} style={{ marginBottom: 8, opacity: 0.4 }} />
            <div>No alerts found.</div>
          </div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>Severity</th>
                <th>Host</th>
                <th>User</th>
                <th>MITRE Chain</th>
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
                      style={{ background: isExpanded ? '#f8fafc' : undefined }}
                    >
                      {/* Expand chevron */}
                      <td style={{ paddingLeft: 16, paddingRight: 4 }}>
                        {isExpanded
                          ? <ChevronDown size={15} color="var(--accent)" />
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
                              background: '#eef2ff', color: '#4f46e5',
                              border: '1px solid #c7d2fe', fontFamily: 'monospace'
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
                            width: 60, height: 4, borderRadius: 3,
                            background: '#f1f5f9', overflow: 'hidden'
                          }}>
                            <div style={{
                              height: '100%',
                              width: `${alert.confidence_score}%`,
                              background: severity === 'critical' ? '#dc2626'
                                : severity === 'high' ? '#ea580c'
                                : severity === 'medium' ? '#ca8a04'
                                : '#0891b2',
                              borderRadius: 3
                            }} />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>
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
                    {isExpanded && <AlertDetail key={`${alert.basket_id}-detail`} alert={alert} onClose={() => setExpandedId(null)} />}
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
            Prev
          </button>
          {Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1).map(p => (
            <button
              key={p}
              onClick={() => setPage(p)}
              style={{
                width: 36, height: 36, borderRadius: 8,
                border: p === page ? '1px solid #c7d2fe' : '1px solid #e2e8f0',
                background: p === page ? '#eef2ff' : '#fff',
                color: p === page ? '#4f46e5' : 'var(--text-secondary)',
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
            Next
          </button>
        </div>
      )}
    </div>
  )
}
