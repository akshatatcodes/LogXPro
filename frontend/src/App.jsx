import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  LayoutDashboard, ShieldAlert, Settings, BookOpen,
  Zap, Activity, Terminal, FileText,
  LineChart, UploadCloud, ShieldCheck, Users
} from 'lucide-react'
import DashboardPage from './pages/DashboardPage'
import AlertQueuePage from './pages/AlertQueuePage'
import LogAnalysisPage from './pages/LogAnalysisPage'
import CasesPage from './pages/CasesPage'
import SettingsPage from './pages/SettingsPage'
import CaseEscalatePage from './pages/CaseEscalatePage'
import DocsPage from './pages/DocsPage'
import PlaybooksPage from './pages/PlaybooksPage'
import GuidePage from './pages/GuidePage'
import KibanaPage from './pages/KibanaPage'
import FileUploadPage from './pages/FileUploadPage'
import AdminPage from './pages/AdminPage'
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

const NAV_MAIN = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/alerts',    icon: ShieldAlert,     label: 'Alert Queue' },
  { to: '/logs',      icon: Terminal,        label: 'Log Analysis' },
  { to: '/kibana',    icon: LineChart,       label: 'Kibana' },
  { to: '/upload',    icon: UploadCloud,     label: 'File Upload' },
]

const NAV_SOC = [
  { to: '/cases',     icon: FileText,        label: 'Case Reports' },
  { to: '/playbooks', icon: Zap,             label: 'Playbooks' },
]

const NAV_KNOWLEDGE = [
  { to: '/docs',      icon: BookOpen,        label: 'Documentation' },
  { to: '/guide',     icon: Activity,        label: 'Analyst Guide' },
]

const NAV_ADMIN = [
  { to: '/admin',     icon: Users,           label: 'Admin Panel' },
  { to: '/settings',  icon: Settings,        label: 'Settings' },
]

function NavSection({ title, items }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        fontSize: 10, fontWeight: 700, letterSpacing: '0.1em',
        textTransform: 'uppercase', color: 'var(--text-muted)',
        padding: '0 12px', marginBottom: 6
      }}>
        {title}
      </div>
      {items.map(({ to, icon: Icon, label }) => (
        <NavLink
          key={to}
          to={to}
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <Icon size={15} />
          <span>{label}</span>
        </NavLink>
      ))}
    </div>
  )
}

function Sidebar() {
  return (
    <aside style={{
      width: 224, minHeight: '100vh', flexShrink: 0,
      background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      padding: '16px 12px',
      position: 'sticky', top: 0, height: '100vh',
      overflowY: 'auto'
    }}>
      {/* Logo */}
      <div style={{ padding: '4px 4px 20px', borderBottom: '1px solid var(--border)', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 8,
            background: '#4f46e5',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ShieldCheck size={18} color="#fff" />
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>LogXPro</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>SOC Platform</div>
          </div>
        </div>
      </div>

      {/* Live indicator */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '6px 10px', marginBottom: 20,
        background: '#f0fdf4', borderRadius: 8,
        border: '1px solid #bbf7d0'
      }}>
        <div style={{
          width: 7, height: 7, borderRadius: '50%',
          background: '#16a34a', position: 'relative',
          boxShadow: '0 0 6px #16a34a'
        }} className="pulse-dot" />
        <span style={{ fontSize: 12, color: '#16a34a', fontWeight: 600 }}>Engine Live</span>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1 }}>
        <NavSection title="Operations" items={NAV_MAIN} />
        <NavSection title="SOC Workflow" items={NAV_SOC} />
        <NavSection title="Knowledge Base" items={NAV_KNOWLEDGE} />
        <NavSection title="Management" items={NAV_ADMIN} />
      </nav>

      {/* Footer */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>LogXPro v3.0 · SOC Platform</div>
      </div>
    </aside>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-main)' }}>
          <Sidebar />
          <main style={{ flex: 1, overflow: 'auto', minHeight: '100vh', background: 'var(--bg-main)' }}>
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/alerts" element={<AlertQueuePage />} />
              <Route path="/logs" element={<LogAnalysisPage />} />
              <Route path="/kibana" element={<KibanaPage />} />
              <Route path="/cases" element={<CasesPage />} />
              <Route path="/cases/write" element={<CaseEscalatePage />} />
              <Route path="/playbooks" element={<PlaybooksPage />} />
              <Route path="/docs" element={<DocsPage />} />
              <Route path="/guide" element={<GuidePage />} />
              <Route path="/upload" element={<FileUploadPage />} />
              <Route path="/admin" element={<AdminPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
