import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fetchMetrics, fetchOpenBaskets } from '../api'
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'
import {
  RefreshCw, AlertTriangle, Clock, Activity,
  Zap, Shield
} from 'lucide-react'
import { severityFromScore, relativeTime } from '../utils'
import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'

/* ─── colour tokens ─────────────────────────────────────────── */
const C = {
  cyan:   '#00e5ff',
  purple: '#a855f7',
  green:  '#10b981',
  orange: '#f97316',
  red:    '#ef4444',
  yellow: '#eab308',
}

/* ─── Sparkline mini-data generators ────────────────────────── */
function spark(n = 12, base = 40, variance = 30) {
  return Array.from({ length: n }, () => ({ v: base + Math.random() * variance }))
}

/* ─── Metric card with inline sparkline ────────────────────── */
function MetricCard({ label, value, delta, color, sparkColor, chartData, icon: Icon }) {
  return (
    <div style={{
      background: '#0e1622', border: '1px solid #1e2d40',
      borderRadius: 12, padding: '20px 22px', flex: 1,
      display: 'flex', flexDirection: 'column', gap: 8,
      position: 'relative', overflow: 'hidden',
      boxShadow: `0 0 30px ${color}12`
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#4b5563' }}>
          {label}
        </span>
        {Icon && <Icon size={14} color="#4b5563" />}
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 10 }}>
        <span style={{ fontSize: 36, fontWeight: 800, letterSpacing: '-0.04em', color, lineHeight: 1 }}>{value}</span>
        {delta && (
          <span style={{ fontSize: 12, fontWeight: 600, color: C.green, marginBottom: 4 }}>{delta}</span>
        )}
      </div>
      <div style={{ height: 48, marginTop: 4 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id={`g${label}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={sparkColor} stopOpacity={0.35} />
                <stop offset="100%" stopColor={sparkColor} stopOpacity={0} />
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="v" stroke={sparkColor} strokeWidth={2}
              fill={`url(#g${label})`} dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/* ─── Real-Time Alert Feed ──────────────────────────────────── */
const FEED_COLORS = { Critical: C.red, Higher: C.orange, High: C.orange, Medium: C.yellow }

function AlertFeed({ baskets }) {
  const items = baskets?.slice(0, 8).map(b => ({
    severity: severityFromScore(b.confidence_score),
    title: 'Ransomware Activity',
    host: b.host_name || 'server-hq-01',
    time: relativeTime(b.updated_at),
  })) || Array.from({ length: 5 }, (_, i) => ({
    severity: ['critical', 'high', 'critical', 'critical', 'critical'][i],
    title: 'Ransomware Activity',
    host: 'server-hq-01',
    time: '09:42:1' + (i + 5) + ' UTC',
  }))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {items.map((item, i) => {
        const cap = item.severity.charAt(0).toUpperCase() + item.severity.slice(1)
        const color = FEED_COLORS[cap] || C.cyan
        return (
          <div key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: 10,
            padding: '9px 12px', borderRadius: 8,
            background: 'rgba(255,255,255,0.02)', border: '1px solid #1e2d40',
            cursor: 'pointer', transition: 'border-color 0.2s',
          }}>
            <AlertTriangle size={14} color={color} style={{ marginTop: 2, flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  fontSize: 10, fontWeight: 700, color,
                  background: color + '18', padding: '1px 7px',
                  borderRadius: 999, border: `1px solid ${color}30`,
                }}>{cap}</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}>
                  {item.title}
                </span>
              </div>
              <div style={{ fontSize: 11, color: '#6b7280', marginTop: 2 }}>
                {item.host} | {item.time}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

/* ─── Section header ────────────────────────────────────────── */
function SectionTitle({ title, extra }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
      <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#9ca3af' }}>
        {title}
      </span>
      {extra}
    </div>
  )
}

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: '#0e1622', border: '1px solid #1e2d40',
      borderRadius: 12, padding: '20px 22px',
      ...style
    }}>
      {children}
    </div>
  )
}

/* ─── Donut chart for threat actors ────────────────────────── */
const ACTOR_DATA = [
  { name: 'APT29',    value: 38, color: C.purple },
  { name: 'BlackCat', value: 45, color: C.cyan },
  { name: 'Others',   value: 17, color: C.green },
]

/* ─── World map dots ────────────────────────────────────────── */
const HOTSPOTS = [
  { x: '20%', y: '38%' }, { x: '30%', y: '43%' }, { x: '52%', y: '30%' },
  { x: '60%', y: '25%' }, { x: '68%', y: '55%' }, { x: '72%', y: '32%' },
  { x: '80%', y: '45%' }, { x: '48%', y: '48%' }, { x: '38%', y: '60%' },
  { x: '85%', y: '60%' }, { x: '22%', y: '55%' }, { x: '65%', y: '42%' },
]

/* ─── Main component ────────────────────────────────────────── */
export default function DashboardPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const now = new Date()

  const { data: metrics, isFetching: mf } = useQuery({
    queryKey: ['metrics'],
    queryFn: fetchMetrics,
    refetchInterval: 20000,
  })
  const { data: openBaskets = [], isFetching: bf } = useQuery({
    queryKey: ['open-baskets'],
    queryFn: fetchOpenBaskets,
    refetchInterval: 15000,
  })

  /* sparkline static data (visual only) */
  const [sparks] = useState({
    threats:   spark(14, 120, 40),
    fp:        spark(14, 2.5, 1.5),
    triaged:   spark(14, 2500, 600),
    mttr:      spark(14, 15, 8),
  })

  /* 30-day incident trend (memoized so it doesn't re-randomize on every render) */
  const trendData = useMemo(() => Array.from({ length: 30 }, (_, i) => ({
    day: i + 1,
    critical: Math.floor(Math.random() * 180 + 60),
    high:     Math.floor(Math.random() * 140 + 40),
    medium:   Math.floor(Math.random() * 100 + 30),
  })), [])

  /* SOC performance */
  const socPerf = [
    { t: '1m',  detection: 40,  response: 65 },
    { t: '3m',  detection: 80,  response: 85 },
    { t: '5m',  detection: 120, response: 95 },
    { t: '17m', detection: 70,  response: 115 },
    { t: '26m', detection: 100, response: 140 },
  ]

  const activeThreats   = metrics?.alerts_today ?? 147
  const fpRate          = metrics?.fp_rate ?? '3.1%'
  const confirmed       = metrics?.confirmed_incidents ?? 2841
  const openCount       = metrics?.open_baskets ?? 18

  return (
    <div style={{ padding: '24px 28px', background: '#080e18', minHeight: '100vh', fontFamily: "'Inter', sans-serif" }}>

      {/* ── Page title ── */}
      <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 26, fontWeight: 900, letterSpacing: '-0.03em', color: '#f9fafb', marginBottom: 2 }}>
            <span style={{ color: '#f9fafb' }}>LOGXPRO</span>
            <span style={{ color: C.cyan, margin: '0 10px' }}>//</span>
            <span style={{ color: '#9ca3af', fontWeight: 600, fontSize: 20 }}>AUTONOMOUS SOC PLATFORM</span>
          </h1>
          <div style={{ fontSize: 12, color: '#4b5563' }}>
            {now.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })} · Real-time correlation active
          </div>
        </div>
        <button
          className="btn btn-ghost"
          onClick={() => queryClient.invalidateQueries()}
          style={{ gap: 6, fontSize: 12 }}
          disabled={mf || bf}
        >
          <RefreshCw size={13} className={mf || bf ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* ── Metric cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 16 }}>
        <MetricCard
          label="Active Threats"
          value={activeThreats}
          delta="+5.2%"
          color={C.cyan}
          sparkColor={C.cyan}
          chartData={sparks.threats}
          icon={Activity}
        />
        <MetricCard
          label="False Positive Rate"
          value={typeof fpRate === 'string' ? fpRate : fpRate + '%'}
          color={C.green}
          sparkColor={C.green}
          chartData={sparks.fp}
          icon={Shield}
        />
        <MetricCard
          label="Incidents Triaged"
          value={confirmed.toLocaleString()}
          color={C.purple}
          sparkColor={C.purple}
          chartData={sparks.triaged}
          icon={Zap}
        />
        <MetricCard
          label="Avg. MTTR"
          value="18 mins"
          color={C.cyan}
          sparkColor={C.cyan}
          chartData={sparks.mttr}
          icon={Clock}
        />
      </div>

      {/* ── Row 2: Trend chart + Alert Feed ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 14, marginBottom: 14 }}>

        {/* Security incident trends */}
        <Card>
          <SectionTitle
            title="Security Incident Trends"
            extra={
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 11 }}>
                <span style={{ color: '#6b7280' }}>Last 30 days</span>
                <div style={{ display: 'flex', gap: 12 }}>
                  {[['Critical', C.cyan], ['High', C.purple], ['Medium', '#60a5fa']].map(([l, c]) => (
                    <span key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#9ca3af' }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: c, display: 'inline-block' }} />
                      {l}
                    </span>
                  ))}
                </div>
              </div>
            }
          />
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={trendData} barCategoryGap="30%" margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d40" vertical={false} />
              <XAxis dataKey="day" tick={{ fill: '#4b5563', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#4b5563', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#0e1622', border: '1px solid #1e2d40', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#9ca3af' }}
                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
              />
              <Bar dataKey="critical" fill={C.cyan}   radius={[2,2,0,0]} />
              <Bar dataKey="high"     fill={C.purple} radius={[2,2,0,0]} />
              <Bar dataKey="medium"   fill="#60a5fa"  radius={[2,2,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Real-time alert feed */}
        <Card>
          <SectionTitle
            title="Real-Time Alert Feed"
            extra={<span style={{ fontSize: 18, color: '#374151', cursor: 'pointer' }}>···</span>}
          />
          <AlertFeed baskets={openBaskets} />
        </Card>
      </div>

      {/* ── Row 3: Threat Actor + World Map + SOC Perf ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>

        {/* Threat Actor Activity */}
        <Card>
          <SectionTitle title="Threat Actor Activity" extra={<span style={{ fontSize: 18, color: '#374151', cursor: 'pointer' }}>···</span>} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <ResponsiveContainer width={130} height={130}>
              <PieChart>
                <Pie
                  data={ACTOR_DATA}
                  cx="50%" cy="50%"
                  innerRadius={38} outerRadius={60}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {ACTOR_DATA.map((e, i) => (
                    <Cell key={i} fill={e.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {ACTOR_DATA.map(a => (
                <div key={a.name} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: a.color, flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: '#d1d5db' }}>{a.name}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Asset Vulnerability – stylized world map */}
        <Card style={{ position: 'relative', overflow: 'hidden' }}>
          <SectionTitle title="Asset Vulnerability" extra={<span style={{ fontSize: 18, color: '#374151', cursor: 'pointer' }}>···</span>} />
          <div style={{ position: 'relative', height: 130, borderRadius: 8, overflow: 'hidden', background: '#0a1220' }}>
            {/* SVG world outline (simplified continents) */}
            <svg viewBox="0 0 400 200" style={{ width: '100%', height: '100%', opacity: 0.3 }}>
              <path d="M60,60 Q80,50 100,60 Q110,70 105,80 Q90,90 70,85 Z" fill="#1e3a5f" />
              <path d="M120,55 Q160,45 200,50 Q220,55 215,75 Q205,90 185,92 Q160,95 140,85 Q120,75 120,55 Z" fill="#1e3a5f" />
              <path d="M215,60 Q240,55 260,60 Q270,70 265,85 Q250,90 235,88 Q218,80 215,60 Z" fill="#1e3a5f" />
              <path d="M270,55 Q300,50 330,58 Q345,68 340,85 Q325,95 305,92 Q280,88 270,70 Z" fill="#1e3a5f" />
              <path d="M65,100 Q90,95 115,105 Q120,120 110,140 Q90,150 70,140 Q55,125 65,100 Z" fill="#1e3a5f" />
              <path d="M210,95 Q235,90 255,100 Q260,115 250,130 Q232,140 215,132 Q205,118 210,95 Z" fill="#1e3a5f" />
              <path d="M290,80 Q320,78 345,90 Q355,105 345,125 Q325,138 300,130 Q280,120 280,100 Z" fill="#1e3a5f" />
            </svg>
            {/* Hotspot dots */}
            {HOTSPOTS.map((h, i) => (
              <div key={i} style={{
                position: 'absolute', left: h.x, top: h.y,
                width: 8, height: 8, borderRadius: '50%',
                background: i % 3 === 0 ? C.red : i % 3 === 1 ? C.orange : C.yellow,
                boxShadow: `0 0 8px ${i % 3 === 0 ? C.red : i % 3 === 1 ? C.orange : C.yellow}`,
                animation: 'pulse 2s infinite',
                transform: 'translate(-50%, -50%)',
              }} />
            ))}
          </div>
        </Card>

        {/* SOC Performance */}
        <Card>
          <SectionTitle title="SOC Performance" extra={<span style={{ fontSize: 18, color: '#374151', cursor: 'pointer' }}>···</span>} />
          <div style={{ display: 'flex', gap: 14, marginBottom: 10 }}>
            {[['Detection', C.cyan], ['Response', C.purple]].map(([l, c]) => (
              <span key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: '#9ca3af' }}>
                <span style={{ width: 20, height: 2, background: c, borderRadius: 1, display: 'inline-block' }} />
                {l}
              </span>
            ))}
          </div>
          <ResponsiveContainer width="100%" height={110}>
            <LineChart data={socPerf} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d40" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: '#4b5563', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#4b5563', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#0e1622', border: '1px solid #1e2d40', borderRadius: 8, fontSize: 11 }} cursor={false} />
              <Line type="monotone" dataKey="detection" stroke={C.cyan}   strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="response"  stroke={C.purple} strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Pulse animation for map dots */}
      <style>{`
        @keyframes pulse {
          0%, 100% { transform: translate(-50%,-50%) scale(1); opacity: 1; }
          50% { transform: translate(-50%,-50%) scale(1.6); opacity: 0.6; }
        }
      `}</style>
    </div>
  )
}
