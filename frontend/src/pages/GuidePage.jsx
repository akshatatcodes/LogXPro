import React from 'react'
import { BookOpen, ShieldAlert, Crosshair, Target } from 'lucide-react'

const SLA_ITEMS = [
  { range: 'Confidence 0–25%', label: 'Low Alert', color: '#16a34a', sla: 'Review when time allows' },
  { range: 'Confidence 26–50%', label: 'Medium Alert', color: '#ca8a04', sla: 'Investigate within 4h' },
  { range: 'Confidence 51–75%', label: 'High Alert', color: '#ea580c', sla: 'Investigate within 1h' },
  { range: 'Confidence 76–100%', label: 'Critical Alert', color: '#dc2626', sla: 'Immediate Response' },
]

const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command & Control' },
]

const RESPONSE_ACTIONS = [
  {
    title: 'Host Isolation',
    desc: 'Isolate the affected host from the network while maintaining a remote shell for investigation.',
    action: 'Action: Block via Firewall/EDR',
  },
  {
    title: 'Credential Reset',
    desc: "If Credential Access is suspected, immediately reset the user's password and kill active sessions.",
    action: 'Action: Force password change',
  },
  {
    title: 'Process Investigation',
    desc: 'Always check the parent process in Sysmon Event ID 1 to identify the execution chain.',
    action: 'Action: Search Sysmon EID 1',
  },
]

export default function GuidePage() {
  return (
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <BookOpen size={24} color="#4f46e5" />
          Analyst Quick Reference
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Essential cheat sheet for triage, categorization, and response actions.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Triage SLAs */}
        <div className="glass-card" style={{ padding: 24 }}>
          <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={18} color="#ca8a04" /> Alert Triage SLAs
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {SLA_ITEMS.map(item => (
              <div key={item.label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                background: 'var(--bg-main)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '10px 14px',
              }}>
                <div>
                  <div style={{ fontSize: 11, fontFamily: 'monospace', color: item.color, fontWeight: 700, marginBottom: 2 }}>{item.range}</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{item.label}</div>
                </div>
                <div style={{ fontSize: 12, color: item.color, fontWeight: 600 }}>{item.sla}</div>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE Map */}
        <div className="glass-card" style={{ padding: 24 }}>
          <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Target size={18} color="#7c3aed" /> MITRE Tactics Quick Map
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {MITRE_TACTICS.map(t => (
              <div key={t.id} style={{
                background: 'var(--bg-main)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '8px 12px',
              }}>
                <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#7c3aed', fontWeight: 700 }}>{t.id}</div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginTop: 2 }}>{t.name}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Response Actions */}
        <div className="glass-card" style={{ padding: 24, gridColumn: '1 / -1' }}>
          <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Crosshair size={18} color="#16a34a" /> Common Response Actions
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
            {RESPONSE_ACTIONS.map(a => (
              <div key={a.title} style={{
                background: 'var(--bg-main)', border: '1px solid var(--border)',
                borderRadius: 10, padding: '16px',
              }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>{a.title}</h3>
                <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.5 }}>{a.desc}</p>
                <div style={{
                  fontFamily: 'monospace', fontSize: 12,
                  background: '#f0fdf4', color: '#16a34a',
                  border: '1px solid #bbf7d0',
                  borderRadius: 6, padding: '6px 10px',
                }}>
                  {a.action}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
