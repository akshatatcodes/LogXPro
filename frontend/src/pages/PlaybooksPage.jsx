import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchPlaybooks } from '../api'
import { Zap, Shield, AlertTriangle, Activity } from 'lucide-react'

const ACTION_COLORS = {
  notify:        { bg: '#fef2f2', border: '#fecaca', text: '#dc2626', label: 'NOTIFY' },
  recommend:     { bg: '#eff6ff', border: '#bfdbfe', text: '#2563eb', label: 'RECOMMEND' },
  auto_response: { bg: '#f0fdf4', border: '#bbf7d0', text: '#16a34a', label: 'AUTO-RESPONSE' },
}

function parseActions(raw) {
  if (Array.isArray(raw)) return raw
  if (typeof raw === 'string') {
    // Sometimes actions come as string from YAML when blank
    return []
  }
  return []
}

export default function PlaybooksPage() {
  const { data: playbooks = [], isLoading } = useQuery({
    queryKey: ['playbooks'],
    queryFn: fetchPlaybooks
  })

  return (
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Zap size={22} color="#4f46e5" />
          Active Playbooks
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Automated incident response workflows loaded in the correlation engine.
        </p>
      </div>

      {isLoading ? (
        <div style={{ color: 'var(--text-muted)', padding: 32 }}>Loading playbooks…</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {playbooks.map(pb => {
            const c = pb.content || {}
            const techniques = Array.isArray(c.matched_techniques) ? c.matched_techniques : []
            const tiers = Array.isArray(c.trigger_tier) ? c.trigger_tier : []
            const actions = parseActions(c.actions)

            return (
              <div key={pb.id} className="glass-card" style={{ padding: '24px 28px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                  <div>
                    <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>{c.name || pb.filename}</h2>
                    <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6 }}>{c.description || 'No description.'}</p>
                  </div>
                  <span style={{ fontSize: 11, padding: '3px 10px', background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe', borderRadius: 999, fontWeight: 700, whiteSpace: 'nowrap', marginLeft: 16 }}>
                    YAML PLAYBOOK
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                  {/* Triggers */}
                  <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 10, padding: '14px 16px' }}>
                    <h3 style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <Shield size={13} color="#ea580c" /> Triggers
                    </h3>
                    {tiers.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Tier:</div>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {tiers.map((t, i) => (
                            <span key={i} style={{
                              fontSize: 12, fontWeight: 700, padding: '2px 8px', borderRadius: 999,
                              background: '#fff7ed', color: '#ea580c', border: '1px solid #fed7aa'
                            }}>Tier {t}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {techniques.length > 0 && (
                      <div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Techniques:</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {techniques.map((t, i) => (
                            <span key={i} style={{
                              fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 4,
                              background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe', fontFamily: 'monospace'
                            }}>{t}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 10, padding: '14px 16px' }}>
                    <h3 style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <Activity size={13} color="#4f46e5" /> Actions
                    </h3>
                    {actions.length === 0 ? (
                      <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No actions defined.</div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {actions.map((action, idx) => {
                          const style = ACTION_COLORS[action.type] || { bg: '#f8fafc', border: '#e2e8f0', text: '#475569', label: (action.type || 'ACTION').toUpperCase() }
                          return (
                            <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                              <span style={{
                                fontSize: 9, fontWeight: 800, padding: '2px 6px', borderRadius: 4,
                                background: style.bg, color: style.text, border: `1px solid ${style.border}`,
                                whiteSpace: 'nowrap', marginTop: 1, letterSpacing: '0.05em'
                              }}>{style.label}</span>
                              <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                                {action.message || action.text?.trim() || (action.enabled ? 'Auto-containment enabled when GRC permits.' : 'Disabled')}
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
          {playbooks.length === 0 && (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 48 }}>
              No playbooks found in configuration.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
