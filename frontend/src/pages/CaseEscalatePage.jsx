import { useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, Gavel, FileText, Clock, Monitor, User, Shield } from 'lucide-react'
import { formatTime, severityFromScore } from '../utils'

export default function CaseEscalatePage() {
  const location = useLocation()
  const navigate = useNavigate()
  const alert = location.state?.alert

  return (
    <div style={{ padding: '28px 32px', maxWidth: 900 }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <button
          className="btn btn-ghost"
          onClick={() => navigate(-1)}
          style={{ marginBottom: 18 }}
        >
          <ArrowLeft size={15} /> Back to Alerts
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <Gavel size={20} color="var(--accent-bright)" />
          <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.03em' }}>Escalate to Case</h1>
        </div>
        <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
          Phase 9 — Case Writing. Pre-filled from the selected alert. Review and submit to create a formal incident case.
        </p>
      </div>

      {/* Pre-filled alert summary */}
      {alert ? (
        <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <Shield size={15} color="var(--accent-bright)" />
            <span style={{ fontWeight: 700, fontSize: 15 }}>Source Alert — {alert.basket_id?.slice(0, 12)}…</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14 }}>
            {[
              { icon: Monitor, label: 'Host', value: alert.host_name },
              { icon: User,    label: 'User', value: alert.user_name || '—' },
              { icon: Shield,  label: 'Severity', value: severityFromScore(alert.confidence_score).toUpperCase() },
              { icon: Clock,   label: 'Detected', value: formatTime(alert.created_at) },
            ].map(({ icon: Icon, label, value }) => (
              <div key={label}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
                  {label}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Icon size={13} color="var(--text-muted)" />
                  <span style={{ fontSize: 13.5, fontWeight: 600 }}>{value}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="glass-card" style={{ padding: '18px 24px', marginBottom: 20, color: 'var(--text-muted)', fontSize: 13 }}>
          No alert context supplied. Navigate here via "Escalate to Case" from an alert row.
        </div>
      )}

      {/* Case form */}
      <div className="glass-card" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 22 }}>
          <FileText size={15} color="var(--accent-bright)" />
          <span style={{ fontWeight: 700, fontSize: 15 }}>Case Form</span>
          <span style={{
            marginLeft: 8, fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 999,
            background: 'rgba(139,92,246,0.15)', color: 'var(--accent-bright)',
            border: '1px solid rgba(139,92,246,0.25)', letterSpacing: '0.08em'
          }}>PHASE 9</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>
              Case Title
            </label>
            <input
              type="text"
              defaultValue={alert ? `Incident — ${alert.host_name} (${severityFromScore(alert.confidence_score).toUpperCase()})` : ''}
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>
              Description / Summary
            </label>
            <textarea
              rows={6}
              defaultValue={alert?.ai_narrative?.slice(0, 500) || ''}
              style={{
                width: '100%', background: 'rgba(15,23,42,0.8)',
                border: '1px solid var(--border)', color: 'var(--text-primary)',
                borderRadius: 8, padding: '10px 14px', fontSize: 13.5,
                fontFamily: 'inherit', outline: 'none', resize: 'vertical',
                lineHeight: 1.65
              }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>
                Severity
              </label>
              <select style={{ width: '100%' }}
                defaultValue={severityFromScore(alert?.confidence_score || 0)}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>
                Assigned Analyst
              </label>
              <input type="text" defaultValue={alert?.assigned_to || ''} style={{ width: '100%' }} />
            </div>
          </div>

          {/* Coming soon note */}
          <div style={{
            padding: '14px 16px', borderRadius: 10, marginTop: 6,
            background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)',
            fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.65
          }}>
            <strong style={{ color: 'var(--accent-bright)' }}>Phase 9 Coming Soon</strong> — Full case management with TheHive integration, automated evidence packing, and forensic timeline export will be implemented in Phase 9.
          </div>

          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', paddingTop: 8 }}>
            <button className="btn btn-ghost" onClick={() => navigate(-1)}>Cancel</button>
            <button className="btn btn-primary" style={{ opacity: 0.5, cursor: 'not-allowed' }}>
              <Gavel size={14} />
              Create Case (Phase 9)
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
