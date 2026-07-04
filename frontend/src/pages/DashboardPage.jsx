import { useQuery } from '@tanstack/react-query'
import { fetchMetrics, fetchOpenBaskets } from '../api'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'
import {
  ShieldAlert, FolderOpen, CheckCircle2, TrendingDown,
  RefreshCw, Activity, Clock, ChevronRight, AlertTriangle
} from 'lucide-react'
import { severityFromScore, relativeTime } from '../utils'
import { useNavigate } from 'react-router-dom'

const CHART_COLORS = {
  critical: '#f43f5e',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#06b6d4',
}

// Custom tooltip for bar chart
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(10,17,32,0.95)', border: '1px solid rgba(139,92,246,0.3)',
      borderRadius: 10, padding: '10px 16px', fontSize: 13
    }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 3 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: p.fill }} />
          <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{p.name}:</span>
          <span style={{ color: p.fill, fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

// Metric card component
function MetricCard({ icon: Icon, label, value, sublabel, glowClass, iconBg, valueColor }) {
  return (
    <div className={`glass-card ${glowClass}`} style={{
      padding: '22px 24px', flex: 1, minWidth: 180,
      transition: 'all 0.25s ease'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 10 }}>
            {label}
          </div>
          <div style={{ fontSize: 34, fontWeight: 800, letterSpacing: '-0.03em', color: valueColor || 'var(--text-primary)', lineHeight: 1 }}>
            {value}
          </div>
          {sublabel && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>{sublabel}</div>
          )}
        </div>
        <div style={{
          width: 44, height: 44, borderRadius: 10,
          background: iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <Icon size={20} color="#fff" />
        </div>
      </div>
    </div>
  )
}

// Open basket card
function BasketCard({ basket }) {
  const navigate = useNavigate()
  const conf = basket.confidence_score || 0
  const stages = basket.matched_stages || []
  const severity = severityFromScore(conf)

  const ringColor = {
    critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#06b6d4'
  }[severity]

  const circumference = 2 * Math.PI * 24
  const dash = (conf / 100) * circumference

  return (
    <div
      className="glass-card"
      onClick={() => navigate('/alerts')}
      style={{ padding: '16px 18px', cursor: 'pointer', transition: 'all 0.2s ease' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {/* Circular confidence meter */}
        <div style={{ position: 'relative', width: 56, height: 56, flexShrink: 0 }}>
          <svg width="56" height="56" viewBox="0 0 56 56" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="28" cy="28" r="24" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="4" />
            <circle
              cx="28" cy="28" r="24" fill="none"
              stroke={ringColor} strokeWidth="4"
              strokeDasharray={`${dash} ${circumference}`}
              strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 4px ${ringColor})` }}
            />
          </svg>
          <div style={{
            position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, color: ringColor
          }}>
            {conf}%
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13.5, marginBottom: 3, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {basket.host_name}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
            {basket.user_name || '—'} · {basket.source_ip || '—'}
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {stages.slice(0, 3).map((s, i) => (
              <span key={i} style={{
                fontSize: 10, fontWeight: 600, padding: '2px 6px', borderRadius: 4,
                background: 'rgba(139,92,246,0.15)', color: 'var(--accent-bright)',
                border: '1px solid rgba(139,92,246,0.25)'
              }}>
                {s.mitre}
              </span>
            ))}
            {stages.length > 3 && (
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{stages.length - 3}</span>
            )}
          </div>
        </div>

        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{relativeTime(basket.updated_at)}</div>
          <ChevronRight size={14} color="var(--text-muted)" style={{ marginTop: 4 }} />
        </div>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const { data: metrics, isLoading: mLoading, refetch } = useQuery({
    queryKey: ['metrics'],
    queryFn: fetchMetrics,
    refetchInterval: 20000,
  })

  const { data: openBaskets, isLoading: bLoading } = useQuery({
    queryKey: ['open-baskets'],
    queryFn: fetchOpenBaskets,
    refetchInterval: 15000,
  })

  const now = new Date()

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1400 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 4 }}>
            SOC Dashboard
          </h1>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={13} />
            {now.toLocaleString('en-US', { weekday: 'long', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
          </div>
        </div>
        <button className="btn btn-ghost" onClick={() => refetch()} style={{ gap: 6 }}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* Metric cards */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 28, flexWrap: 'wrap' }}>
        <MetricCard
          icon={ShieldAlert}
          label="Alerts Today"
          value={mLoading ? '…' : (metrics?.alerts_today ?? '—')}
          sublabel="Across all severity levels"
          glowClass="glow-red"
          iconBg="linear-gradient(135deg, #f43f5e, #be123c)"
          valueColor="#f43f5e"
        />
        <MetricCard
          icon={FolderOpen}
          label="Open Baskets"
          value={mLoading ? '…' : (metrics?.open_baskets ?? '—')}
          sublabel="Currently forming"
          glowClass="glow-purple"
          iconBg="linear-gradient(135deg, #8b5cf6, #6d28d9)"
          valueColor="#a78bfa"
        />
        <MetricCard
          icon={CheckCircle2}
          label="Confirmed Incidents"
          value={mLoading ? '…' : (metrics?.confirmed_incidents ?? '—')}
          sublabel="Resolved this week"
          iconBg="linear-gradient(135deg, #10b981, #059669)"
          valueColor="#10b981"
        />
        <MetricCard
          icon={TrendingDown}
          label="FP Rate"
          value={mLoading ? '…' : (metrics?.fp_rate ?? '—')}
          sublabel="False positives suppressed"
          glowClass="glow-cyan"
          iconBg="linear-gradient(135deg, #06b6d4, #0891b2)"
          valueColor="#06b6d4"
        />
      </div>

      {/* Charts + Open Baskets */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 20, alignItems: 'start' }}>
        {/* Severity chart */}
        <div className="glass-card" style={{ padding: '22px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
            <Activity size={16} color="var(--accent-bright)" />
            <h2 style={{ fontSize: 15, fontWeight: 700 }}>Alert Severity — Last 12 Hours</h2>
          </div>
          {mLoading ? (
            <div style={{ height: 260, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
              Loading chart data…
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart
                data={metrics?.severity_by_hour || []}
                margin={{ top: 4, right: 8, left: -20, bottom: 0 }}
                barCategoryGap="35%"
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis
                  dataKey="hour_str"
                  tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                <Legend
                  wrapperStyle={{ fontSize: 12, color: 'var(--text-secondary)', paddingTop: 12, textTransform: 'capitalize' }}
                />
                <Bar dataKey="low"      name="low"      fill={CHART_COLORS.low}      radius={[3,3,0,0]} />
                <Bar dataKey="medium"   name="medium"   fill={CHART_COLORS.medium}   radius={[3,3,0,0]} />
                <Bar dataKey="high"     name="high"     fill={CHART_COLORS.high}     radius={[3,3,0,0]} />
                <Bar dataKey="critical" name="critical" fill={CHART_COLORS.critical} radius={[3,3,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Active basket feed */}
        <div className="glass-card" style={{ padding: '22px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={16} color="#f97316" />
              <h2 style={{ fontSize: 15, fontWeight: 700 }}>Active Baskets</h2>
            </div>
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 999,
              background: 'rgba(249,115,22,0.15)', color: '#f97316',
              border: '1px solid rgba(249,115,22,0.3)'
            }}>
              {bLoading ? '…' : (openBaskets?.length ?? 0)} LIVE
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {bLoading ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', padding: 24 }}>Loading…</div>
            ) : (openBaskets?.length > 0) ? (
              openBaskets.slice(0, 6).map(b => <BasketCard key={b.basket_id} basket={b} />)
            ) : (
              <div style={{
                textAlign: 'center', padding: '28px 16px', color: 'var(--text-muted)', fontSize: 13,
                border: '1px dashed var(--border)', borderRadius: 8
              }}>
                <CheckCircle2 size={28} color="var(--color-success)" style={{ marginBottom: 8, opacity: 0.6 }} />
                <div>No active open baskets</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
