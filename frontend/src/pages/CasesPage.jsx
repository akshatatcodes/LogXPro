import React, { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchCases } from '../api'
import { relativeTime, formatTime } from '../utils'
import { FileText, CheckCircle, Clock, Plus, X, User, Calendar, AlertTriangle, Code, Tag, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
const SEV_STYLE = {
  critical: { bg: '#fff0f0', border: '#ffb3b3', text: '#c00000', dot: '#dc2626' },
  high:     { bg: '#fff4ec', border: '#fec89a', text: '#b84a00', dot: '#ea580c' },
  medium:   { bg: '#fffbeb', border: '#fde68a', text: '#92620a', dot: '#ca8a04' },
  low:      { bg: '#f0fbff', border: '#a5f3fc', text: '#0e7490', dot: '#0891b2' },
}

function SevBadge({ severity }) {
  const s = SEV_STYLE[severity?.toLowerCase()] || SEV_STYLE.low
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 11px', borderRadius: 999, fontSize: 11, fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '0.05em',
      background: s.bg, color: s.text, border: `1px solid ${s.border}`
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.dot, flexShrink: 0 }} />
      {severity?.toUpperCase() || '—'}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Case Detail Modal
// ---------------------------------------------------------------------------
function CaseDetailModal({ c, onClose }) {
  // Close on Escape key
  useEffect(() => {
    const fn = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', fn)
    return () => window.removeEventListener('keydown', fn)
  }, [onClose])

  const metaItems = [
    { label: 'Case ID',   value: <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#4f46e5' }}>CAS-{c.id}</span> },
    { label: 'Severity',  value: <SevBadge severity={c.severity} /> },
    { label: 'Status',    value: c.status?.toLowerCase() === 'open'
        ? <span style={{ display:'inline-flex', alignItems:'center', gap:5, color:'#b45309', fontWeight:600, fontSize:13 }}><Clock size={13}/>Open</span>
        : <span style={{ display:'inline-flex', alignItems:'center', gap:5, color:'#15803d', fontWeight:600, fontSize:13 }}><CheckCircle size={13}/>Closed</span>
    },
    { label: 'Assignee',  value: c.assignee
        ? <span style={{ display:'inline-flex', alignItems:'center', gap:5, fontSize:13, fontWeight:500, color:'#1e293b' }}><User size={13} color="#94a3b8"/>{c.assignee}</span>
        : <span style={{ color:'#94a3b8', fontStyle:'italic', fontSize:13 }}>Unassigned</span>
    },
    { label: 'Created',   value: <span style={{ fontSize:13, color:'#475569' }}>{formatTime(c.created_at)} <span style={{ color:'#94a3b8', fontSize:11 }}>({relativeTime(c.created_at)})</span></span> },
    ...(c.updated_at ? [{ label: 'Updated', value: <span style={{ fontSize:13, color:'#475569' }}>{formatTime(c.updated_at)}</span> }] : []),
  ]

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0,
          background: 'rgba(15,23,42,0.6)',
          backdropFilter: 'blur(4px)',
          WebkitBackdropFilter: 'blur(4px)',
          zIndex: 9000,
        }}
      />

      {/* Dialog */}
      <div style={{
        position: 'fixed',
        top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        width: 740, maxWidth: 'calc(100vw - 32px)',
        maxHeight: 'calc(100vh - 64px)',
        background: '#ffffff',
        borderRadius: 16,
        border: '1px solid #e2e8f0',
        boxShadow: '0 32px 80px rgba(0,0,0,0.22), 0 8px 20px rgba(0,0,0,0.12)',
        zIndex: 9001,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        fontFamily: "'Inter', system-ui, sans-serif",
      }}>

        {/* ── Header ── */}
        <div style={{
          padding: '18px 24px',
          borderBottom: '1px solid #e2e8f0',
          background: '#f8fafc',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 14,
          flexShrink: 0,
        }}>
          <div style={{
            width: 42, height: 42, borderRadius: 10,
            background: '#eef2ff',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <FileText size={21} color="#4f46e5" />
          </div>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 10.5, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
              Case Report · CAS-{c.id}
            </div>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: '#0f172a', lineHeight: 1.35, margin: 0, wordBreak: 'break-word' }}>
              {c.title}
            </h2>
          </div>

          <button
            onClick={onClose}
            style={{
              flexShrink: 0,
              marginLeft: 8,
              width: 32, height: 32,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'none',
              border: '1px solid #e2e8f0',
              borderRadius: 8,
              cursor: 'pointer',
              color: '#64748b',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => Object.assign(e.currentTarget.style, { background: '#f1f5f9', color: '#0f172a' })}
            onMouseLeave={e => Object.assign(e.currentTarget.style, { background: 'none', color: '#64748b' })}
            title="Close (Esc)"
          >
            <X size={15} />
          </button>
        </div>

        {/* ── Body (scrollable) ── */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '22px 24px' }}>

          {/* Meta grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '10px 16px',
            padding: '16px',
            background: '#f8fafc',
            border: '1px solid #e2e8f0',
            borderRadius: 10,
            marginBottom: 20,
          }}>
            {metaItems.map(({ label, value }) => (
              <div key={label}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 5 }}>
                  {label}
                </div>
                <div>{value}</div>
              </div>
            ))}
          </div>

          {/* Linked basket */}
          {c.basket_id && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '10px 14px', marginBottom: 18,
              background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 8,
            }}>
              <AlertTriangle size={14} color="#3b82f6" />
              <span style={{ fontSize: 12, fontWeight: 600, color: '#1d4ed8' }}>Linked Basket:</span>
              <code style={{ fontSize: 12, color: '#2563eb', background: '#dbeafe', padding: '1px 7px', borderRadius: 4 }}>{c.basket_id}</code>
            </div>
          )}

          {/* Executive Summary */}
          {c.summary && (
            <div style={{ marginBottom: 20 }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                fontSize: 11, fontWeight: 700, color: '#475569',
                textTransform: 'uppercase', letterSpacing: '0.07em',
                marginBottom: 10,
              }}>
                <Tag size={13} /> Executive Summary
              </div>
              <div style={{
                background: '#f8fafc', border: '1px solid #e2e8f0',
                borderRadius: 8, padding: '14px 16px',
                fontSize: 13.5, color: '#334155', lineHeight: 1.75,
                whiteSpace: 'pre-wrap',
              }}>
                {c.summary}
              </div>
            </div>
          )}

          {/* Technical Details */}
          {c.technical_details && (
            <div>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                fontSize: 11, fontWeight: 700, color: '#475569',
                textTransform: 'uppercase', letterSpacing: '0.07em',
                marginBottom: 10,
              }}>
                <Code size={13} /> Technical Details
              </div>
              <pre style={{
                background: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: 8,
                padding: '14px 16px',
                fontSize: 11.5,
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                color: '#e6edf3',
                overflowX: 'auto',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                lineHeight: 1.65,
                maxHeight: 300,
                margin: 0,
              }}>
                {c.technical_details}
              </pre>
            </div>
          )}
        </div>

        {/* ── Footer ── */}
        <div style={{
          padding: '14px 24px',
          borderTop: '1px solid #e2e8f0',
          background: '#f8fafc',
          display: 'flex',
          justifyContent: 'flex-end',
          flexShrink: 0,
        }}>
          <button
            onClick={onClose}
            style={{
              padding: '8px 22px',
              borderRadius: 8, fontSize: 13, fontWeight: 600,
              background: '#ffffff', color: '#475569',
              border: '1px solid #cbd5e1',
              cursor: 'pointer',
              transition: 'all 0.15s',
              fontFamily: "'Inter', system-ui, sans-serif",
            }}
            onMouseEnter={e => Object.assign(e.currentTarget.style, { background: '#f1f5f9', borderColor: '#94a3b8' })}
            onMouseLeave={e => Object.assign(e.currentTarget.style, { background: '#ffffff', borderColor: '#cbd5e1' })}
          >
            Close
          </button>
        </div>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Cases Page
// ---------------------------------------------------------------------------
export default function CasesPage() {
  const navigate = useNavigate()
  const [selectedCase, setSelectedCase] = useState(null)

  const { data: cases = [], isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: fetchCases,
    refetchInterval: 15000,
  })

  if (isLoading) return (
    <div style={{ padding: '28px 32px', color: 'var(--text-muted)' }}>Loading cases…</div>
  )

  return (
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
              <ShieldAlert size={22} color="#4f46e5" /> Case Reports
            </span>
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            Formal incident response escalations and tracking.
            {cases.length > 0 && (
              <span style={{ marginLeft: 8, fontWeight: 600, color: '#4f46e5' }}>
                {cases.length} {cases.length === 1 ? 'case' : 'cases'}
              </span>
            )}
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/cases/write')}>
          <Plus size={15} /> New Case Report
        </button>
      </div>

      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Case ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Assignee</th>
              <th>Created</th>
              <th style={{ width: 80, textAlign: 'center' }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {cases.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No cases found. Escalate an alert from the Alert Queue to create one.
                </td>
              </tr>
            ) : (
              cases.map(c => (
                <tr
                  key={c.id}
                  onClick={() => setSelectedCase(c)}
                  style={{ cursor: 'pointer' }}
                  title="Click to view full case details"
                >
                  <td>
                    <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#4f46e5', fontWeight: 700 }}>
                      CAS-{c.id}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <FileText size={14} color="var(--text-muted)" />
                      <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{c.title}</span>
                    </div>
                  </td>
                  <td><SevBadge severity={c.severity} /></td>
                  <td>
                    {c.status?.toLowerCase() === 'open' ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 13, color: '#ca8a04', fontWeight: 500 }}>
                        <Clock size={13} /> Open
                      </span>
                    ) : (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 13, color: '#16a34a', fontWeight: 500 }}>
                        <CheckCircle size={13} /> Closed
                      </span>
                    )}
                  </td>
                  <td style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                    {c.assignee || <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Unassigned</span>}
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {c.created_at ? relativeTime(c.created_at) : '-'}
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <span style={{
                      display: 'inline-block',
                      fontSize: 11, fontWeight: 600, color: '#4f46e5',
                      background: '#eef2ff', padding: '4px 12px', borderRadius: 6,
                      border: '1px solid #c7d2fe', cursor: 'pointer',
                    }}>
                      View →
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Modal */}
      {selectedCase && (
        <CaseDetailModal c={selectedCase} onClose={() => setSelectedCase(null)} />
      )}
    </div>
  )
}
