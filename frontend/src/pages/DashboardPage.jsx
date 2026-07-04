import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fetchMetrics, fetchOpenBaskets } from '../api'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'
import {
  ShieldAlert, FolderOpen, CheckCircle2, TrendingDown,
  RefreshCw, Activity, Clock, ChevronRight, AlertTriangle
} from 'lucide-react'
import { severityFromScore, relativeTime } from '../utils'
import { useNavigate } from 'react-router-dom'

const CHART_COLORS = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#ca8a04',
  low:      '#0891b2',
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#fff', border: '1px solid #e2e8f0',
      borderRadius: 8, padding: '10px 14px', fontSize: 13,
      boxShadow: '0 4px 12px rgba(0,0,0,0.08)'
    }}>
      <div style={{ color: '#64748b', marginBottom: 6, fontWeight: 600 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 3 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: p.fill }} />
          <span style={{ color: '#475569', textTransform: 'capitalize' }}>{p.name}:</span>
          <span style={{ color: p.fill, fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

function MetricCard({ icon: Icon, label, value, sublabel, iconColor, bgColor, onClick }) {
  return (
    <div
      className="glass-card"
      onClick={onClick}
      style={{
        padding: '20px 24px', flex: 1, minWidth: 180,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.2s ease'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
            {label}
          </div>
          <div style={{ fontSize: 30, fontWeight: 700, letterSpacing: '-0.03em', color: iconColor, lineHeight: 1 }}>
            {value}
          </div>
          {sublabel && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>{sublabel}</div>
          )}
          {onClick && (
            <div style={{ fontSize: 12, color: 'var(--accent)', marginTop: 8, fontWeight: 500 }}>
              View all &#8594;
            </div>
          )}
        </div>
        <div style={{
          width: 44, height: 44, borderRadius: 10,
          background: bgColor, display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <Icon size={22} color={iconColor} />
        </div>
      </div>
    </div>
  )
}

function BasketCard({ basket }) {
  const navigate = useNavigate()
  const conf = basket.confidence_score || 0
  const stages = basket.matched_stages || []
  const severity = severityFromScore(conf)

  const severityColor = {
    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#0891b2'
  }[severity]

  return (
    <div
      className="glass-card"
      onClick={() => navigate('/alerts')}
      style={{ padding: '14px 16px', cursor: 'pointer', transition: 'all 0.2s ease' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 42, height: 42, borderRadius: 8,
          background: severityColor + '15', border: `1px solid ${severityColor}30`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <ShieldAlert size={18} color={severityColor} />
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--text-primary)' }}>
            {basket.host_name}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
            {basket.user_name || '—'} · {conf}% confidence
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {stages.slice(0, 2).map((s, i) => (
              <span key={i} style={{
                fontSize: 10, fontWeight: 600, padding: '1px 6px', borderRadius: 4,
                background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe'
              }}>
                {s.mitre}
              </span>
            ))}
            {stages.length > 2 && (
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{stages.length - 2}</span>
            )}
          </div>
        </div>

        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{relativeTime(basket.updated_at)}</div>
          <ChevronRight size={13} color="var(--text-muted)" style={{ marginTop: 4 }} />
        </div>
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data: metrics, isLoading: mLoading, isFetching: mFetching } = useQuery({
    queryKey: ['metrics'],
    queryFn: fetchMetrics,
    refetchInterval: 20000,
  })

  const { data: openBaskets, isLoading: bLoading, isFetching: bFetching } = useQuery({
    queryKey: ['open-baskets'],
    queryFn: fetchOpenBaskets,
    refetchInterval: 15000,
  })

  const isFetching = mFetching || bFetching
  const now = new Date()

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1400, background: 'var(--bg-main)', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            SOC Dashboard
          </h1>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={13} />
            {now.toLocaleString('en-US', { weekday: 'long', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
          </div>
        </div>
        <button 
          className="btn btn-ghost" 
          onClick={() => queryClient.invalidateQueries()} 
          disabled={isFetching}
          style={{ gap: 6 }}
        >
          <RefreshCw size={14} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Metric cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
        <MetricCard
          icon={ShieldAlert}
          label="Alerts Today"
          value={mLoading ? '…' : (metrics?.alerts_today ?? '—')}
          sublabel="Across all severity levels"
          iconColor="#dc2626"
          bgColor="#fef2f2"
          onClick={() => navigate('/alerts')}
        />
        <MetricCard
          icon={FolderOpen}
          label="Open Baskets"
          value={mLoading ? '…' : (metrics?.open_baskets ?? '—')}
          sublabel="Currently forming"
          iconColor="#4f46e5"
          bgColor="#eef2ff"
          onClick={() => navigate('/alerts')}
        />
        <MetricCard
          icon={CheckCircle2}
          label="Confirmed Incidents"
          value={mLoading ? '…' : (metrics?.confirmed_incidents ?? '—')}
          sublabel="Resolved this week"
          iconColor="#16a34a"
          bgColor="#f0fdf4"
          onClick={() => navigate('/cases')}
        />
        <MetricCard
          icon={TrendingDown}
          label="FP Rate"
          value={mLoading ? '…' : (metrics?.fp_rate ?? '—')}
          sublabel="False positives suppressed"
          iconColor="#0891b2"
          bgColor="#ecfeff"
        />
      </div>

      {/* Charts + Open Baskets */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 20, alignItems: 'start' }}>
        {/* Severity chart */}
        <div className="glass-card" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
            <Activity size={16} color="var(--accent)" />
            <h2 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Alert Severity — Last 12 Hours</h2>
          </div>
          {mLoading ? (
            <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
              Loading chart data…
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart
                data={metrics?.severity_by_hour || []}
                margin={{ top: 4, right: 8, left: -20, bottom: 0 }}
                barCategoryGap="35%"
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis
                  dataKey="hour_str"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(99,102,241,0.04)' }} />
                <Bar dataKey="low"      name="low"      fill={CHART_COLORS.low}      radius={[3,3,0,0]} />
                <Bar dataKey="medium"   name="medium"   fill={CHART_COLORS.medium}   radius={[3,3,0,0]} />
                <Bar dataKey="high"     name="high"     fill={CHART_COLORS.high}     radius={[3,3,0,0]} />
                <Bar dataKey="critical" name="critical" fill={CHART_COLORS.critical} radius={[3,3,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Active basket feed */}
        <div className="glass-card" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={16} color="#ea580c" />
              <h2 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Active Baskets</h2>
            </div>
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 999,
              background: '#fff7ed', color: '#ea580c',
              border: '1px solid #fed7aa'
            }}>
              {bLoading ? '…' : (openBaskets?.length ?? 0)} LIVE
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {bLoading ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', padding: 24 }}>Loading…</div>
            ) : (openBaskets?.length > 0) ? (
              openBaskets.slice(0, 6).map(b => <BasketCard key={b.basket_id} basket={b} />)
            ) : (
              <div style={{
                textAlign: 'center', padding: '28px 16px', color: 'var(--text-muted)', fontSize: 13,
                border: '1px dashed var(--border)', borderRadius: 8
              }}>
                <CheckCircle2 size={28} color="#16a34a" style={{ marginBottom: 8, opacity: 0.6 }} />
                <div>No active open baskets</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
