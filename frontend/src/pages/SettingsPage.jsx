import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { fetchGRC, setGRCProfile } from '../api'
import {
  Shield, Building2, Heart, Globe, Check, ChevronRight,
  Settings as SettingsIcon, AlertCircle, RefreshCw
} from 'lucide-react'

const PROFILES = [
  {
    id: 'default',
    name: 'Default SOC',
    icon: Globe,
    description: 'General-purpose enterprise SOC profile with balanced rule coverage.',
    accentColor: '#8b5cf6',
    features: [
      'Active Directory monitoring',
      'Endpoint detection',
      'Network anomaly detection',
      'Standard alert sensitivity',
    ],
    frameworks: ['NIST CSF', 'CIS Controls'],
  },
  {
    id: 'finance',
    name: 'Finance / Banking',
    icon: Building2,
    description: 'Tuned for PCI-DSS compliance. Enhanced alerting on payment system access, privilege escalation, and data exfiltration.',
    accentColor: '#f97316',
    features: [
      'PCI-DSS coverage',
      'Cardholder data env monitoring',
      'High sensitivity on lateral movement',
      'Auto-response enabled',
    ],
    frameworks: ['PCI-DSS v4', 'SOX', 'NIST 800-53'],
  },
  {
    id: 'healthcare',
    name: 'Healthcare / HIPAA',
    icon: Heart,
    description: 'HIPAA-compliant profile with PII redaction and extended retention for medical systems.',
    accentColor: '#10b981',
    features: [
      'HIPAA PHI protection',
      'PII redaction in logs',
      'Extended 365-day retention',
      'ePHI access monitoring',
    ],
    frameworks: ['HIPAA', 'HITECH', 'NIST 800-66'],
  },
]

function ProfileCard({ profile, isActive, onSelect, isPending }) {
  const Icon = profile.icon

  return (
    <div
      onClick={() => !isActive && !isPending && onSelect(profile.id)}
      style={{
        padding: '22px 24px',
        borderRadius: 14,
        background: isActive ? `rgba(${hexToRgbStr(profile.accentColor)}, 0.1)` : 'var(--bg-card)',
        border: `1px solid ${isActive ? profile.accentColor + '50' : 'var(--border)'}`,
        backdropFilter: 'blur(16px)',
        cursor: isActive ? 'default' : 'pointer',
        transition: 'all 0.2s ease',
        boxShadow: isActive ? `0 0 28px ${profile.accentColor}20` : 'none',
        position: 'relative',
      }}
      className={isActive ? '' : 'glass-card'}
    >
      {/* Active check */}
      {isActive && (
        <div style={{
          position: 'absolute', top: 16, right: 16,
          width: 24, height: 24, borderRadius: '50%',
          background: profile.accentColor,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: `0 0 10px ${profile.accentColor}`
        }}>
          <Check size={13} color="#fff" strokeWidth={3} />
        </div>
      )}

      {/* Icon + name */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 10,
          background: `rgba(${hexToRgbStr(profile.accentColor)}, 0.18)`,
          border: `1px solid ${profile.accentColor}40`,
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <Icon size={20} color={profile.accentColor} />
        </div>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700 }}>{profile.name}</div>
          {isActive && (
            <div style={{ fontSize: 11, fontWeight: 600, color: profile.accentColor, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Active Profile
            </div>
          )}
        </div>
      </div>

      <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>
        {profile.description}
      </p>

      {/* Features */}
      <div style={{ marginBottom: 16 }}>
        {profile.features.map((f, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: profile.accentColor, flexShrink: 0 }} />
            <span style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>{f}</span>
          </div>
        ))}
      </div>

      {/* Frameworks */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {profile.frameworks.map(fw => (
          <span key={fw} style={{
            fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 999,
            background: `rgba(${hexToRgbStr(profile.accentColor)}, 0.15)`,
            color: profile.accentColor,
            border: `1px solid ${profile.accentColor}30`,
            letterSpacing: '0.05em'
          }}>{fw}</span>
        ))}
      </div>

      {/* Apply button (non-active) */}
      {!isActive && (
        <div style={{
          marginTop: 18, paddingTop: 16, borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between'
        }}>
          <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            {isPending ? 'Applying…' : 'Click to activate'}
          </span>
          <ChevronRight size={15} color="var(--text-muted)" />
        </div>
      )}
    </div>
  )
}

function hexToRgbStr(hex) {
  const res = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return res ? `${parseInt(res[1],16)},${parseInt(res[2],16)},${parseInt(res[3],16)}` : '255,255,255'
}

export default function SettingsPage() {
  const [activeProfile, setActiveProfile] = useState('default')
  const [successMsg, setSuccessMsg] = useState(null)

  const { data: grcData, isLoading } = useQuery({
    queryKey: ['grc'],
    queryFn: fetchGRC,
    onSuccess: (d) => {
      if (d?.industry) {
        const map = { finance: 'finance', healthcare: 'healthcare', generic: 'default', financial: 'finance' }
        setActiveProfile(map[d.industry] || 'default')
      }
    }
  })

  const mutation = useMutation({
    mutationFn: (profile) => setGRCProfile(profile),
    onSuccess: (_, profile) => {
      setActiveProfile(profile)
      setSuccessMsg(`Switched to ${PROFILES.find(p => p.id === profile)?.name} profile`)
      setTimeout(() => setSuccessMsg(null), 4000)
    }
  })

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <SettingsIcon size={20} color="var(--accent-bright)" />
          <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.03em' }}>Settings</h1>
        </div>
        <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
          Configure GRC compliance profile and engine behaviour.
        </p>
      </div>

      {/* GRC Section */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <Shield size={16} color="var(--accent-bright)" />
          <h2 style={{ fontSize: 17, fontWeight: 700 }}>GRC Compliance Profile</h2>
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
          Select the GRC profile matching your client's regulatory environment.
          This controls which rule groups are active, alert sensitivity, and PII handling.
        </p>

        {successMsg && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '12px 16px', marginBottom: 20, borderRadius: 10,
            background: 'rgba(16,185,129,0.12)', color: '#10b981',
            border: '1px solid rgba(16,185,129,0.3)', fontSize: 13, fontWeight: 600
          }}>
            <Check size={16} />
            {successMsg}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
          {PROFILES.map(profile => (
            <ProfileCard
              key={profile.id}
              profile={profile}
              isActive={activeProfile === profile.id}
              onSelect={(id) => mutation.mutate(id)}
              isPending={mutation.isPending}
            />
          ))}
        </div>
      </div>

      {/* Current GRC data read-back */}
      {grcData && (
        <div className="glass-card" style={{ padding: '18px 22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <AlertCircle size={15} color="var(--text-muted)" />
            <span style={{ fontWeight: 600, fontSize: 14 }}>Active Profile Details</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            {[
              { label: 'Client', value: grcData.client },
              { label: 'Industry', value: grcData.industry },
              { label: 'Alert Sensitivity', value: grcData.alert_sensitivity },
              { label: 'Auto Response', value: grcData.auto_response_allowed ? 'Enabled' : 'Disabled' },
              { label: 'PII Redaction', value: grcData.pii_redaction ? 'On' : 'Off' },
              { label: 'Retention Days', value: `${grcData.retention_days} days` },
            ].map(({ label, value }) => (
              <div key={label}>
                <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 4 }}>
                  {label}
                </div>
                <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                  {value ?? '—'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
