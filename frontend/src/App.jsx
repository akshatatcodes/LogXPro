import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  LayoutDashboard, ShieldAlert, Settings, BookOpen,
  Zap, Activity, ChevronRight
} from 'lucide-react'
import DashboardPage from './pages/DashboardPage'
import AlertQueuePage from './pages/AlertQueuePage'
import SettingsPage from './pages/SettingsPage'
import CaseEscalatePage from './pages/CaseEscalatePage'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 30000,
      retry: 1,
      staleTime: 10000,
    }
  }
})

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/alerts',    icon: ShieldAlert,     label: 'Alert Queue' },
  { to: '/settings',  icon: Settings,        label: 'Settings' },
]

function Sidebar() {
  return (
    <aside
      style={{
        width: 220, minHeight: '100vh', flexShrink: 0,
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        padding: '20px 12px',
        backdropFilter: 'blur(20px)',
        position: 'sticky', top: 0, height: '100vh'
      }}
    >
      {/* Logo */}
      <div style={{ padding: '4px 4px 24px', borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: 'linear-gradient(135deg, #7c3aed, #4f46e5)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 16px rgba(139,92,246,0.5)'
          }}>
            <Zap size={18} color="#fff" />
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.02em' }}>LogXPro</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>SOC Platform</div>
          </div>
        </div>
      </div>

      {/* Live indicator */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '7px 10px', marginBottom: 16,
        background: 'rgba(16,185,129,0.08)', borderRadius: 7,
        border: '1px solid rgba(16,185,129,0.2)'
      }}>
        <div style={{
          width: 7, height: 7, borderRadius: '50%',
          background: '#10b981', position: 'relative',
          boxShadow: '0 0 6px #10b981'
        }} className="pulse-dot" />
        <span style={{ fontSize: 12, color: '#10b981', fontWeight: 600 }}>Engine Live</span>
      </div>

      {/* Nav links */}
      <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Version footer */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14, marginTop: 8 }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>LogXPro v3.0 · Phase 7</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
          <span style={{ color: 'var(--accent-bright)' }}>FastAPI</span> + React
        </div>
      </div>
    </aside>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div style={{ display: 'flex', minHeight: '100vh' }}>
          <Sidebar />
          <main style={{ flex: 1, overflow: 'auto', minHeight: '100vh' }}>
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/alerts" element={<AlertQueuePage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/cases/write" element={<CaseEscalatePage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
