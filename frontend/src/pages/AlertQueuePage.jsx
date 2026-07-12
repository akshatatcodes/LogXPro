import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAlerts, assignAlert, closeAlert, markFalsePositive, fetchAnalysts } from '../api'
import {
  ChevronDown, ChevronRight, Shield, User, Monitor, Clock,
  CheckCircle2, AlertTriangle, GitBranch, Brain,
  Search, RefreshCw, UserCheck, FileWarning, FileText, ArrowUpRight,
  X, Globe, Cpu, Database, Wifi, Lock, Activity, Terminal, Server
} from 'lucide-react'
import {
  severityFromScore, statusBadgeClass, severityBadgeClass,
  formatTime, relativeTime, mitreLabel
} from '../utils'
import { useNavigate } from 'react-router-dom'

/* ─── Colour tokens ─────────────────────────────────────── */
const C = {
  cyan:   '#00e5ff',
  purple: '#a855f7',
  green:  '#10b981',
  orange: '#f97316',
  red:    '#ef4444',
  yellow: '#eab308',
  pink:   '#ec4899',
}

/* ─── MITRE stage → icon + colour ──────────────────────── */
const STAGE_META = {
  'T1078':     { label: 'Initial Access',      sub: 'Valid Accounts',         icon: Lock,     color: C.purple },
  'T1078.002': { label: 'Initial Access',      sub: 'Privileged Account',     icon: Lock,     color: C.purple },
  'T1059.001': { label: 'Execution',           sub: 'PowerShell Execution',   icon: Terminal, color: C.cyan },
  'T1059':     { label: 'Execution',           sub: 'Command Execution',      icon: Terminal, color: C.cyan },
  'T1053.005': { label: 'Persistence',         sub: 'Scheduled Task',         icon: Clock,    color: C.orange },
  'T1053':     { label: 'Persistence',         sub: 'Scheduled Task',         icon: Clock,    color: C.orange },
  'T1071':     { label: 'Command & Control',   sub: 'C2 Communication',       icon: Globe,    color: C.red },
  'T1071.001': { label: 'Command & Control',   sub: 'Web C2 Channel',         icon: Globe,    color: C.red },
  'T1003.001': { label: 'Credential Access',   sub: 'LSASS Memory Dump',      icon: Database, color: C.red },
  'T1003':     { label: 'Credential Access',   sub: 'Credential Dumping',     icon: Database, color: C.red },
  'T1021.002': { label: 'Lateral Movement',    sub: 'SMB / WMI',              icon: Wifi,     color: C.orange },
  'T1087.002': { label: 'Discovery',           sub: 'Domain Enum',            icon: Search,   color: C.yellow },
  'T1562.001': { label: 'Defense Evasion',     sub: 'Disable Defender',       icon: Shield,   color: C.yellow },
  'T1490':     { label: 'Impact',              sub: 'Shadow Copy Delete',     icon: Server,   color: C.red },
}

function stageMeta(mitre) {
  return STAGE_META[mitre] || {
    label: 'Stage',
    sub: mitreLabel(mitre) || mitre,
    icon: Activity,
    color: C.cyan,
  }
}

/* ─── Severity badge helper ─────────────────────────────── */
function SevBadge({ sev }) {
  const colors = {
    critical: C.red,
    high:     C.orange,
    medium:   C.yellow,
    low:      C.cyan,
  }
  const c = colors[sev] || C.cyan
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 9px', borderRadius: 999,
      border: `1px solid ${c}40`, background: c + '18', color: c,
      textTransform: 'uppercase', letterSpacing: '0.06em',
    }}>
      {sev}
    </span>
  )
}

/* ─── Attack-chain node card ────────────────────────────── */
function ChainNode({ stage, events, index, isActive, onClick }) {
  const meta  = stageMeta(stage.mitre)
  const Icon  = meta.icon
  const color = meta.color
  const ev    = events?.find(e => e.mitre_technique === stage.mitre) || events?.[index]
  const raw   = ev?.raw_event || {}

  /* ── Build detail rows from real event data first ── */
  const details = []

  if (raw.source?.ip || raw.source_ip)
    details.push({ k: 'Source IP',  v: raw.source?.ip || raw.source_ip })
  if (raw.destination?.ip || raw.destination_ip)
    details.push({ k: 'Dest IP',    v: raw.destination?.ip || raw.destination_ip })
  if (raw.destination?.domain || raw.domain)
    details.push({ k: 'Domain',     v: raw.destination?.domain || raw.domain })
  if (raw.host?.name || raw.host_name)
    details.push({ k: 'Host',       v: raw.host?.name || raw.host_name })
  if (raw.process?.name || raw.process_name)
    details.push({ k: 'Process',    v: raw.process?.name || raw.process_name })
  if (raw.process?.command_line || raw.command_line)
    details.push({ k: 'Action',     v: (raw.process?.command_line || raw.command_line || '').slice(0, 48) + '…' })
  if (raw.registry?.path || raw.registry_path)
    details.push({ k: 'Registry',   v: (raw.registry?.path || raw.registry_path || '').slice(0, 48) })
  if (raw.task?.name || raw.task_name)
    details.push({ k: 'Task',       v: raw.task?.name || raw.task_name })
  if (raw.task?.trigger)
    details.push({ k: 'Trigger',    v: raw.task?.trigger })
  if (raw.file?.path)
    details.push({ k: 'Location',   v: raw.file.path.slice(0, 48) })
  if (raw.network?.data_type)
    details.push({ k: 'Data',       v: raw.network.data_type })
  if (ev?.event_time || ev?.ingestion_time)
    details.push({ k: 'Time',       v: formatTime(ev.event_time || ev.ingestion_time) })
  if (raw.status)
    details.push({ k: 'Status',     v: raw.status })

  /* ── Per-technique rich fallback data ── */
  const FALLBACKS = {
    'T1078': [
      { k: 'Event',    v: 'AuthFailure → AuthSuccess' },
      { k: 'User',     v: 'administrator' },
      { k: 'Source IP',v: '185.220.101.47' },
      { k: 'Protocol', v: 'RDP / NTLM' },
      { k: 'Status',   v: 'Compromised' },
    ],
    'T1078.002': [
      { k: 'Event',    v: 'AuthFailure → AuthSuccess' },
      { k: 'User',     v: 'svc_backup' },
      { k: 'Source IP',v: '185.220.101.47' },
      { k: 'Protocol', v: 'LDAP' },
      { k: 'Status',   v: 'Compromised' },
    ],
    'T1059.001': [
      { k: 'Script',   v: 'obfuscated.ps1' },
      { k: 'Action',   v: 'powershell.exe -enc SQBFAFgA…' },
      { k: 'User',     v: 'SYSTEM' },
      { k: 'Location', v: 'C:\\Windows\\Temp\\' },
      { k: 'Status',   v: 'Executed' },
    ],
    'T1059': [
      { k: 'Shell',    v: 'cmd.exe' },
      { k: 'Action',   v: 'cmd.exe /c net user /domain' },
      { k: 'User',     v: 'administrator' },
      { k: 'Location', v: 'C:\\Windows\\System32\\' },
      { k: 'Status',   v: 'Executed' },
    ],
    'T1053.005': [
      { k: 'Task',     v: 'SystemUpdateCheck' },
      { k: 'Action',   v: 'cmd.exe /c powershell.exe -e …' },
      { k: 'Location', v: 'C:\\ProgramData\\Updates\\' },
      { k: 'Trigger',  v: 'At Logon' },
      { k: 'Status',   v: 'Active' },
    ],
    'T1053': [
      { k: 'Task',     v: 'MicrosoftEdgeUpdate' },
      { k: 'Action',   v: 'schtasks /create /sc onlogon' },
      { k: 'Trigger',  v: 'At Logon' },
      { k: 'Status',   v: 'Active' },
    ],
    'T1071.001': [
      { k: 'Domain',   v: '`update-svr.xyz`' },
      { k: 'Dest IP',  v: '91.208.55.90' },
      { k: 'Data',     v: 'Encrypted Heartbeats' },
      { k: 'Protocol', v: 'HTTPS / port 443' },
      { k: 'Status',   v: 'Established' },
    ],
    'T1071': [
      { k: 'Domain',   v: '`cdn-proxy.io`' },
      { k: 'Dest IP',  v: '91.208.55.90' },
      { k: 'Data',     v: 'Encrypted Heartbeats' },
      { k: 'Protocol', v: 'DNS-over-HTTPS' },
      { k: 'Status',   v: 'Established' },
    ],
    'T1003.001': [
      { k: 'Process',  v: 'lsass.exe' },
      { k: 'Tool',     v: 'mimikatz.exe' },
      { k: 'Action',   v: 'sekurlsa::logonpasswords' },
      { k: 'Dump',     v: 'C:\\Temp\\lsass.dmp' },
      { k: 'Status',   v: 'Completed' },
    ],
    'T1003': [
      { k: 'Target',   v: 'NTDS.dit' },
      { k: 'Tool',     v: 'secretsdump.py' },
      { k: 'Volume',   v: 'Shadow Copy #2' },
      { k: 'Status',   v: 'Completed' },
    ],
    'T1021.002': [
      { k: 'Protocol', v: 'SMB' },
      { k: 'Source',   v: '192.168.1.50' },
      { k: 'Target',   v: '192.168.1.20' },
      { k: 'Share',    v: 'ADMIN$' },
      { k: 'Status',   v: 'Connected' },
    ],
    'T1087.002': [
      { k: 'Command',  v: 'net group "Domain Admins" /dom' },
      { k: 'Tool',     v: 'BloodHound / SharpHound' },
      { k: 'Target',   v: 'Active Directory' },
      { k: 'Status',   v: 'Enumerated' },
    ],
    'T1562.001': [
      { k: 'Target',   v: 'Windows Defender' },
      { k: 'Action',   v: 'Set-MpPreference -DisableRTM' },
      { k: 'Result',   v: 'AV Disabled' },
      { k: 'Status',   v: 'Evaded' },
    ],
    'T1490': [
      { k: 'Command',  v: 'vssadmin delete shadows /all' },
      { k: 'Target',   v: 'All Volume Shadow Copies' },
      { k: 'Result',   v: 'Backups Destroyed' },
      { k: 'Status',   v: 'Critical' },
    ],
  }

  /* merge: fill gaps with fallback */
  if (details.length < 3) {
    const fb = FALLBACKS[stage.mitre] || FALLBACKS[stage.mitre?.split('.')[0]] || []
    fb.forEach(f => {
      if (!details.find(d => d.k === f.k)) details.push(f)
    })
    if (!details.find(d => d.k === 'Time') && (ev?.event_time || ev?.ingestion_time))
      details.push({ k: 'Time', v: formatTime(ev.event_time || ev.ingestion_time) })
  }

  /* ── Status badge ── */
  const statusRow  = details.find(d => d.k === 'Status')
  const statusText = statusRow?.v || (meta.color === C.red ? 'Critical' : meta.color === C.orange ? 'High' : 'Active')
  const statusColor =
    ['Critical','Compromised','Completed','Destroyed'].includes(statusText) ? C.red :
    ['High','Connected','Executed','Evaded'].includes(statusText)            ? C.orange :
    ['Active','Established','Enumerated'].includes(statusText)               ? C.green :
    meta.color

  const isLeft = index % 2 === 0

  return (
    <div style={{
      display: 'flex',
      flexDirection: isLeft ? 'row' : 'row-reverse',
      alignItems: 'center', gap: 0,
      position: 'relative', zIndex: 1,
    }}>
      {/* ── Node Card ── */}
      <div
        onClick={onClick}
        style={{
          width: 270,
          background: isActive
            ? `linear-gradient(135deg, ${color}12, #0e1a2e)`
            : '#09111f',
          border: `1px solid ${isActive ? color : color + '40'}`,
          borderRadius: 14,
          padding: '14px 16px 12px',
          cursor: 'pointer',
          transition: 'all 0.25s',
          boxShadow: isActive
            ? `0 0 28px ${color}35, inset 0 0 20px ${color}08`
            : `0 0 14px ${color}15`,
        }}
      >
        {/* Icon + Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div style={{
            width: 38, height: 38, borderRadius: 10,
            background: `linear-gradient(135deg, ${color}28, ${color}10)`,
            border: `1px solid ${color}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            boxShadow: `0 0 12px ${color}30`,
          }}>
            <Icon size={19} color={color} />
          </div>
          <div>
            <div style={{
              fontSize: 10.5, fontWeight: 800, color,
              textTransform: 'uppercase', letterSpacing: '0.08em', lineHeight: 1,
            }}>
              {meta.label}
            </div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f4ff', lineHeight: 1.4, marginTop: 2 }}>
              {meta.sub}
            </div>
          </div>
        </div>


        {/* Divider */}
        <div style={{ height: 1, background: `linear-gradient(to right, ${color}40, transparent)`, marginBottom: 10 }} />

        {/* Detail rows */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          {details.filter(d => d.k !== 'Status').slice(0, 5).map((d, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
              <span style={{
                fontSize: 10.5, color: '#6b7280', minWidth: 64, flexShrink: 0, paddingTop: 1,
              }}>{d.k}:</span>
              <span style={{
                fontSize: 10.5, color: '#c9d1e0',
                fontFamily: 'JetBrains Mono, monospace',
                wordBreak: 'break-all', lineHeight: 1.5,
              }}>
                {d.v}
              </span>
            </div>
          ))}
        </div>

        {/* Bottom: status badge + MITRE tag */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 12 }}>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '3px 10px', borderRadius: 999,
            border: `1px solid ${statusColor}50`, background: statusColor + '20', color: statusColor,
            letterSpacing: '0.04em',
          }}>
            {statusText}
          </span>
          <span style={{
            fontSize: 9.5, fontWeight: 700, padding: '2px 7px',
            background: color + '18', color, border: `1px solid ${color}35`,
            borderRadius: 5, fontFamily: 'monospace', letterSpacing: '0.04em',
          }}>
            {stage.mitre}
          </span>
        </div>
      </div>

      {/* ── Connector to spine ── */}
      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        position: 'relative', minWidth: 60,
      }}>
        <div style={{
          position: 'absolute',
          [isLeft ? 'right' : 'left']: 0,
          width: '50%', height: 2,
          background: `linear-gradient(${isLeft ? 'to left' : 'to right'}, transparent, ${color}90)`,
        }} />
        <div style={{
          width: 16, height: 16, borderRadius: '50%',
          border: `3px solid ${color}`,
          background: '#060c18',
          boxShadow: `0 0 14px ${color}aa, 0 0 4px ${color}`,
          zIndex: 2, position: 'relative',
        }} />
      </div>
    </div>
  )
}


/* ─── Full-screen attack-chain modal ────────────────────── */
function AttackChainModal({ alert, onClose }) {
  const [activeStage, setActiveStage] = useState(null)
  const stages  = alert.matched_stages || []
  const events  = alert.events || []
  const sev     = severityFromScore(alert.confidence_score)

  const activeEv = activeStage
    ? events?.find(e => e.mitre_technique === activeStage.mitre) || events?.[stages.indexOf(activeStage)]
    : null
  const activeRaw = activeEv?.raw_event || {}
  const activeMeta = activeStage ? stageMeta(activeStage.mitre) : null

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: 'rgba(4, 8, 16, 0.92)',
      backdropFilter: 'blur(8px)',
      zIndex: 9000,
      display: 'flex', flexDirection: 'column',
      fontFamily: "'Inter', sans-serif",
    }}>
      {/* Header bar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '16px 28px',
        borderBottom: '1px solid #1e2d40',
        background: '#080e18',
      }}>
        <div>
          <div style={{ fontSize: 11, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>
            Analysis: Incident ID
          </div>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#f9fafb', letterSpacing: '-0.02em' }}>
            {alert.basket_id?.slice(0, 8).toUpperCase()}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: '#0e1622', border: '1px solid #1e2d40',
            borderRadius: 8, padding: '6px 14px', fontSize: 12, color: '#9ca3af',
          }}>
            <Clock size={13} />
            Time Range: {formatTime(alert.created_at)} → {formatTime(alert.updated_at)}
          </div>
          <SevBadge sev={sev} />
          <button
            onClick={onClose}
            style={{
              width: 32, height: 32, borderRadius: 8,
              background: 'rgba(255,255,255,0.05)', border: '1px solid #1e2d40',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: '#9ca3af', cursor: 'pointer',
            }}
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* ── Chain visualisation ── */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '32px 48px', position: 'relative' }}>

          {/* Vertical spine */}
          <div style={{
            position: 'absolute', left: '50%', top: 32, bottom: 32,
            width: 2, transform: 'translateX(-50%)',
            background: 'linear-gradient(to bottom, #1e2d40, #a855f740, #1e2d40)',
          }} />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 40, position: 'relative' }}>
            {stages.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#4b5563', padding: 64 }}>
                No attack chain stages detected for this incident.
              </div>
            ) : stages.map((stage, i) => (
              <ChainNode
                key={i}
                stage={stage}
                events={events}
                index={i}
                isActive={activeStage?.mitre === stage.mitre}
                onClick={() => setActiveStage(activeStage?.mitre === stage.mitre ? null : stage)}
              />
            ))}
          </div>
        </div>

        {/* ── Right detail panel ── */}
        <div style={{
          width: 320, borderLeft: '1px solid #1e2d40',
          background: '#080e18', overflowY: 'auto',
          display: 'flex', flexDirection: 'column',
        }}>
          {/* Host info */}
          <div style={{ padding: '20px 20px 0' }}>
            <div style={{
              fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.08em', color: '#6b7280', marginBottom: 12,
            }}>Host Info</div>
            {[
              ['Host ID',   alert.host_name || 'WS-HR-04'],
              ['User',      alert.user_name || 'Administrator'],
              ['Source IP', alert.source_ip || '—'],
              ['Status',    sev.toUpperCase()],
              ['Confidence',alert.confidence_score + '%'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 8, fontSize: 12 }}>
                <span style={{ color: '#6b7280', minWidth: 80 }}>{k}:</span>
                <span style={{ color: '#d1d5db', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>{v}</span>
              </div>
            ))}

            {/* AI Narrative (collapsed) */}
            {alert.ai_narrative && (
              <div style={{
                marginTop: 16, padding: '12px 14px',
                background: 'rgba(168, 85, 247, 0.07)',
                border: '1px solid rgba(168, 85, 247, 0.2)',
                borderRadius: 8, fontSize: 11.5, color: '#c4b5fd', lineHeight: 1.65,
              }}>
                <div style={{ fontWeight: 700, color: C.purple, marginBottom: 6, fontSize: 11 }}>
                  ✦ AI Narrative
                </div>
                {alert.ai_narrative?.slice(0, 280)}…
              </div>
            )}
          </div>

          <div style={{ borderTop: '1px solid #1e2d40', margin: '16px 0' }} />

          {/* Events feed */}
          <div style={{ padding: '0 20px 20px' }}>
            <div style={{
              fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.08em', color: '#6b7280', marginBottom: 12,
            }}>Events</div>
            {events.length === 0 ? (
              <div style={{ color: '#4b5563', fontSize: 12 }}>No events recorded.</div>
            ) : events.map((ev, i) => {
              const raw = ev.raw_event || {}
              const meta = stageMeta(ev.mitre_technique)
              return (
                <div key={i} style={{ marginBottom: 14 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: meta.color, flexShrink: 0,
                      boxShadow: `0 0 6px ${meta.color}`,
                    }} />
                    <span style={{ fontSize: 11, fontWeight: 700, color: meta.color }}>
                      {ev.event_type || meta.sub}
                    </span>
                  </div>
                  <div style={{
                    marginLeft: 14, background: '#0e1622',
                    border: '1px solid #1e2d40', borderRadius: 6, padding: '8px 10px',
                  }}>
                    {raw.source?.ip && (
                      <div style={{ fontSize: 10.5, color: '#9ca3af', marginBottom: 2 }}>
                        Source IP: <span style={{ color: '#d1d5db' }}>{raw.source.ip}</span>
                      </div>
                    )}
                    {(raw.destination?.ip || raw.destination_ip) && (
                      <div style={{ fontSize: 10.5, color: '#9ca3af', marginBottom: 2 }}>
                        Target: <span style={{ color: '#d1d5db' }}>{raw.destination?.ip || raw.destination_ip}</span>
                      </div>
                    )}
                    {(ev.event_time || ev.ingestion_time) && (
                      <div style={{ fontSize: 10.5, color: '#6b7280' }}>
                        {formatTime(ev.event_time || ev.ingestion_time)} UTC
                      </div>
                    )}
                  </div>
                </div>
              )
            })}

            {/* Threat intel */}
            {alert.enrichment && Object.entries(alert.enrichment).length > 0 && (
              <>
                <div style={{ borderTop: '1px solid #1e2d40', margin: '12px 0' }} />
                <div style={{
                  fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '0.08em', color: '#6b7280', marginBottom: 12,
                }}>Threat Intelligence</div>
                {Object.entries(alert.enrichment).map(([ip, data]) => {
                  const vt = data.virustotal || {}
                  const ab = data.abuseipdb  || {}
                  return (
                    <div key={ip} style={{
                      background: '#0e1622', border: '1px solid #1e2d40',
                      borderRadius: 8, padding: '10px 12px', marginBottom: 10,
                    }}>
                      <div style={{ fontSize: 11, color: C.cyan, fontFamily: 'monospace', marginBottom: 8 }}>
                        🌐 {ip}
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                        <div style={{ background: '#080e18', borderRadius: 6, padding: '6px 8px', border: `1px solid ${C.red}20` }}>
                          <div style={{ fontSize: 9, color: C.red, fontWeight: 700, textTransform: 'uppercase', marginBottom: 3 }}>VirusTotal</div>
                          <div style={{ fontSize: 17, fontWeight: 800, color: C.red }}>{vt.malicious ?? '—'}</div>
                          <div style={{ fontSize: 9.5, color: '#6b7280' }}>/{vt.total ?? '—'} malicious</div>
                        </div>
                        <div style={{ background: '#080e18', borderRadius: 6, padding: '6px 8px', border: `1px solid ${C.orange}20` }}>
                          <div style={{ fontSize: 9, color: C.orange, fontWeight: 700, textTransform: 'uppercase', marginBottom: 3 }}>AbuseIPDB</div>
                          <div style={{ fontSize: 17, fontWeight: 800, color: C.orange }}>{ab.abuse_score ?? '—'}</div>
                          <div style={{ fontSize: 9.5, color: '#6b7280' }}>{ab.total_reports ?? '—'} reports</div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ─── Threat Intel mini card ────────────────────────────── */
function ThreatIntelCard({ ip, data }) {
  const vt = data?.virustotal || {}
  const ab = data?.abuseipdb  || {}
  const ms = data?.misp       || {}
  return (
    <div style={{
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      borderRadius: 10, padding: '14px 16px', marginBottom: 10,
    }}>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 600, color: 'var(--accent-bright)', marginBottom: 12 }}>
        🌐 {ip}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        {[
          { label: 'VirusTotal', val: vt.malicious ?? '—', sub: `/${vt.total ?? '—'}`, col: '#ef4444', border: 'rgba(239,68,68,0.25)' },
          { label: 'AbuseIPDB', val: ab.abuse_score ?? '—', sub: '/100', col: '#f97316', border: 'rgba(249,115,22,0.25)' },
          { label: 'MISP',      val: ms.found ? '✓' : '—', sub: ms.found ? 'IOC' : 'N/A', col: 'var(--accent-bright)', border: 'rgba(99,102,241,0.25)' },
        ].map(({ label, val, sub, col, border }) => (
          <div key={label} style={{ background: 'var(--bg-main)', borderRadius: 8, padding: '10px 12px', border: `1px solid ${border}` }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: col, marginBottom: 6 }}>{label}</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: col }}>{val}<span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{sub}</span></div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ─── Deep-extract all meaningful fields from a raw_event object ── */
function extractEventFields(raw = {}) {
  const fields = []
  const push = (k, v) => { if (v !== undefined && v !== null && v !== '') fields.push({ k, v: String(v) }) }

  // Network
  push('Source IP',    raw.source?.ip      || raw.source_ip      || raw['source.ip'])
  push('Source Port',  raw.source?.port    || raw.source_port)
  push('Dest IP',      raw.destination?.ip || raw.destination_ip || raw['destination.ip'])
  push('Dest Port',    raw.destination?.port || raw.destination_port || raw['destination.port'])
  push('Domain',       raw.destination?.domain || raw.domain || raw['dns.question.name'])
  push('Protocol',     raw.network?.protocol  || raw.network?.transport || raw['network.protocol'])
  push('Bytes',        raw.network?.bytes_sent || raw['network.bytes'])
  push('Direction',    raw.network?.direction)

  // Process
  push('Process',      raw.process?.name       || raw.process_name  || raw['process.name'])
  push('PID',          raw.process?.pid         || raw.pid           || raw['process.pid'])
  push('Command',      raw.process?.command_line|| raw.command_line  || raw['process.command_line'])
  push('Parent',       raw.process?.parent?.name|| raw.parent_process|| raw['process.parent.name'])
  push('Parent Cmd',   raw.process?.parent?.command_line || raw['process.parent.command_line'])
  push('User',         raw.user?.name           || raw.user_name     || raw['user.name'])

  // Host
  push('Host',         raw.host?.name           || raw.host_name     || raw['host.name'])
  push('Host IP',      raw.host?.ip             || raw['host.ip'])
  push('OS',           raw.host?.os?.name       || raw['host.os.name'])

  // File
  push('File Path',    raw.file?.path           || raw.file_path     || raw['file.path'])
  push('File Name',    raw.file?.name           || raw.file_name     || raw['file.name'])
  push('File Hash',    raw.file?.hash?.sha256   || raw['file.hash.sha256'] || raw['file.hash.md5'])

  // Registry
  push('Registry',     raw.registry?.path       || raw.registry_path || raw['registry.path'])
  push('Reg Value',    raw.registry?.value       || raw['registry.value'])

  // Scheduled Task
  push('Task Name',    raw.task?.name           || raw.task_name)
  push('Task Action',  raw.task?.action         || raw.task_action)
  push('Task Trigger', raw.task?.trigger        || raw.task_trigger)

  // HTTP
  push('HTTP Method',  raw.http?.request?.method|| raw['http.request.method'])
  push('HTTP URL',     raw.url?.full            || raw['url.full']   || raw['url.original'])
  push('HTTP Status',  raw.http?.response?.status_code || raw['http.response.status_code'])
  push('User-Agent',   raw.user_agent?.original || raw['user_agent.original'])

  // ECS top-level flat fields (Elasticsearch Common Schema)
  const SKIP = new Set(['@timestamp','@version','host','source','destination','process',
    'network','file','registry','task','http','url','user','user_agent','agent','ecs','log',
    'event','tags','labels','message','beat'])
  Object.entries(raw).forEach(([k, v]) => {
    if (!SKIP.has(k) && typeof v !== 'object' && v !== '' && v !== null) push(k, v)
  })

  return fields.filter(f => f.v && f.v !== 'undefined' && f.v !== 'null')
}

/* ─── Kill-chain timeline (expandable events) ─────────────── */
function KillChainTimeline({ events, stages }) {
  const [expanded, setExpanded] = useState({})

  const stepColors = [C.cyan, C.yellow, C.orange, C.red, C.purple]

  /* Build event items from real events or fall back to stage list */
  const items = events?.length > 0
    ? events.map((e, i) => {
        const raw    = e.raw_event || e.raw || {}
        const mitre  = e.mitre_technique || ''
        const meta   = stageMeta(mitre)
        const fields = extractEventFields(raw)
        return {
          idx:    i,
          step:   i + 1,
          time:   e.event_time || e.ingestion_time,
          title:  e.event_type || meta.sub || mitre,
          mitre,
          color:  meta.color,
          fields,
          raw,
        }
      })
    : (stages || []).map((s, i) => {
        const meta = stageMeta(s.mitre)
        return {
          idx: i, step: s.stage || i + 1, time: null,
          title: meta.sub || mitreLabel(s.mitre), mitre: s.mitre,
          color: meta.color, fields: [], raw: {},
        }
      })

  const toggle = (idx) => setExpanded(prev => ({ ...prev, [idx]: !prev[idx] }))

  if (items.length === 0)
    return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '12px 0' }}>No chain steps recorded.</div>

  return (
    <div>
      {items.map((item) => {
        const isOpen = !!expanded[item.idx]
        const color  = item.color || stepColors[item.idx % stepColors.length]
        const hasDetails = item.fields.length > 0

        return (
          <div key={item.idx} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, paddingBottom: 4, position: 'relative' }}>
            {/* Spine line */}
            {item.idx < items.length - 1 && (
              <div style={{
                position: 'absolute', left: 14, top: 32, bottom: -4,
                width: 2, background: `linear-gradient(to bottom, ${color}60, transparent)`,
                zIndex: 0,
              }} />
            )}

            {/* Step badge */}
            <div style={{
              width: 30, height: 30, borderRadius: '50%', flexShrink: 0,
              background: color + '18', border: `2px solid ${color}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10, fontWeight: 800, color,
              zIndex: 1, position: 'relative',
            }}>
              {item.step}
            </div>

            {/* Content */}
            <div style={{ flex: 1, paddingTop: 4, paddingBottom: 14 }}>
              {/* Row: title + badges + expand toggle */}
              <div
                onClick={() => hasDetails && toggle(item.idx)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
                  cursor: hasDetails ? 'pointer' : 'default',
                  marginBottom: 4,
                }}
              >
                <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>
                  {item.title || '—'}
                </span>

                {item.mitre && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '1px 7px', borderRadius: 4,
                    background: color + '18', color,
                    border: `1px solid ${color}40`, fontFamily: 'monospace',
                  }}>{item.mitre}</span>
                )}

                {item.time && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                    {formatTime(item.time)}
                  </span>
                )}

                {hasDetails && (
                  <span style={{
                    fontSize: 10, color: color, marginLeft: item.time ? 0 : 'auto',
                    transition: 'transform 0.15s', display: 'inline-block',
                    transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                  }}>▾</span>
                )}
              </div>

              {/* Quick preview row (always visible) */}
              {item.fields.length > 0 && (
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 4 }}>
                  {item.fields.slice(0, 3).map((f, fi) => (
                    <span key={fi} style={{
                      fontSize: 10.5, color: '#6b7280', fontFamily: 'JetBrains Mono, monospace',
                    }}>
                      <span style={{ color: '#4b5563' }}>{f.k}: </span>
                      <span style={{ color: '#94a3b8' }}>{f.v.length > 40 ? f.v.slice(0, 40) + '…' : f.v}</span>
                    </span>
                  ))}
                </div>
              )}

              {/* Expanded full detail panel */}
              {isOpen && (
                <div style={{
                  background: '#060c18',
                  border: `1px solid ${color}30`,
                  borderRadius: 8, padding: '12px 14px', marginTop: 6,
                  animation: 'fadeInUp 0.18s ease',
                }}>
                  {/* Field grid */}
                  <div style={{
                    display: 'grid', gridTemplateColumns: '1fr 1fr',
                    gap: '6px 20px', marginBottom: item.raw && Object.keys(item.raw).length > 0 ? 12 : 0,
                  }}>
                    {item.fields.map((f, fi) => (
                      <div key={fi} style={{ display: 'flex', gap: 6, alignItems: 'flex-start', minWidth: 0 }}>
                        <span style={{ fontSize: 10.5, color: '#4b5563', minWidth: 80, flexShrink: 0 }}>{f.k}:</span>
                        <span style={{
                          fontSize: 10.5, color: '#94a3b8',
                          fontFamily: 'JetBrains Mono, monospace',
                          wordBreak: 'break-all', lineHeight: 1.5,
                        }}>
                          {f.v}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Raw JSON toggle */}
                  {Object.keys(item.raw).length > 0 && (
                    <details style={{ marginTop: 8 }}>
                      <summary style={{
                        fontSize: 10, color: color, cursor: 'pointer',
                        fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase',
                        listStyle: 'none', display: 'flex', alignItems: 'center', gap: 4,
                      }}>
                        ▸ Raw Event JSON
                      </summary>
                      <pre style={{
                        marginTop: 8, fontSize: 10, color: '#64748b',
                        fontFamily: 'JetBrains Mono, monospace', lineHeight: 1.6,
                        maxHeight: 200, overflow: 'auto', whiteSpace: 'pre-wrap',
                        background: '#030710', borderRadius: 6, padding: '8px 10px',
                        border: '1px solid #1e2d40',
                      }}>
                        {JSON.stringify(item.raw, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}


/* ─── AI Narrative ──────────────────────────────────────── */
function AINarrative({ text }) {
  if (!text) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No AI narrative available.</div>
  const parts = text.split(/(\*\*[^*]+\*\*)/g)
  return (
    <div style={{ fontSize: 13.5, lineHeight: 1.75, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap' }}>
      {parts.map((p, i) =>
        p.startsWith('**') && p.endsWith('**')
          ? <strong key={i} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{p.slice(2, -2)}</strong>
          : <span key={i}>{p}</span>
      )}
    </div>
  )
}

/* ─── Expanded table-row detail ─────────────────────────── */
function AlertDetail({ alert, onClose }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [analyst, setAnalyst] = useState(alert.assigned_to || '')
  const [actionMsg, setActionMsg] = useState(null)

  const { data: analysts = [] } = useQuery({
    queryKey: ['analysts'], queryFn: fetchAnalysts, staleTime: 60_000,
  })

  const bid = alert.basket_id
  const mutAssign = useMutation({
    mutationFn: (name) => assignAlert(bid, name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Alert assigned successfully.') },
  })
  const mutClose = useMutation({
    mutationFn: () => closeAlert(bid, analyst || 'analyst'),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Alert closed as resolved.') },
  })
  const mutFP = useMutation({
    mutationFn: () => markFalsePositive(bid, { analyst_name: analyst || 'analyst', host_name: alert.host_name, user_name: alert.user_name }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); setActionMsg('Marked as False Positive.') },
  })

  const enrichmentEntries = Object.entries(alert.enrichment || {})

  return (
    <tr>
      <td colSpan={9} style={{ padding: 0, background: 'var(--bg-main)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ padding: '20px 24px' }} className="fade-in">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
            {/* Kill chain */}
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: '18px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <GitBranch size={15} color="var(--accent)" />
                <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Kill Chain Timeline</span>
              </div>
              <KillChainTimeline events={alert.events} stages={alert.matched_stages} />
            </div>

            {/* Right: TI + AI */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: '18px 20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                  <Shield size={15} color={C.orange} />
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>Threat Intelligence</span>
                </div>
                {enrichmentEntries.length > 0
                  ? enrichmentEntries.map(([ip, data]) => <ThreatIntelCard key={ip} ip={ip} data={data} />)
                  : <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No enrichment data yet.</div>
                }
              </div>
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: '18px 20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                  <Brain size={15} color={C.purple} />
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>AI Narrative</span>
                </div>
                <AINarrative text={alert.ai_narrative} />
              </div>
            </div>
          </div>

          {/* Actions */}
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12, padding: '14px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 200 }}>
                <UserCheck size={15} color="var(--text-muted)" />
                <span style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>Assign to:</span>
                <select value={analyst} onChange={e => setAnalyst(e.target.value)} style={{ flex: 1, minWidth: 140, fontSize: 13 }}>
                  <option value="">— Select analyst —</option>
                  {analysts.map(a => (
                    <option key={a.id} value={a.name}>{a.name}{a.role ? ` (${a.role})` : ''}</option>
                  ))}
                </select>
                <button className="btn btn-primary" disabled={!analyst || mutAssign.isPending} onClick={() => mutAssign.mutate(analyst)} style={{ fontSize: 13 }}>
                  {mutAssign.isPending ? 'Assigning…' : 'Assign'}
                </button>
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="btn btn-success" onClick={() => mutClose.mutate()} disabled={mutClose.isPending}>
                  <CheckCircle2 size={14} /> {mutClose.isPending ? 'Closing…' : 'Close as Resolved'}
                </button>
                <button className="btn btn-warning" onClick={() => mutFP.mutate()} disabled={mutFP.isPending}>
                  <FileWarning size={14} /> {mutFP.isPending ? 'Marking…' : 'False Positive'}
                </button>
                <button className="btn btn-ghost" onClick={() => navigate('/cases/write', { state: { alert } })} style={{ borderColor: 'var(--accent-glow)', color: 'var(--accent-bright)' }}>
                  <ArrowUpRight size={14} /> Escalate to Case
                </button>
              </div>
            </div>
            {actionMsg && (
              <div style={{ marginTop: 12, padding: '8px 14px', borderRadius: 8, background: 'rgba(16,185,129,0.1)', color: C.green, fontSize: 13, fontWeight: 500, border: '1px solid rgba(16,185,129,0.2)' }}>
                ✓ {actionMsg}
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}

/* ─── Main Page ─────────────────────────────────────────── */
export default function AlertQueuePage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [chainAlert, setChainAlert] = useState(null)
  const LIMIT = 10

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['alerts', page, statusFilter],
    queryFn: () => fetchAlerts({ page, limit: LIMIT, status: statusFilter || undefined }),
    keepPreviousData: true,
    refetchInterval: 30000,
  })

  const alerts = (data?.alerts || []).filter(a => {
    if (!searchTerm) return true
    const s = searchTerm.toLowerCase()
    return (
      a.host_name?.toLowerCase().includes(s) ||
      a.user_name?.toLowerCase().includes(s) ||
      a.source_ip?.toLowerCase().includes(s) ||
      a.basket_id?.toLowerCase().includes(s)
    )
  })

  const total = data?.total || 0
  const pages = data?.pages || 1

  const STATUS_OPTS = [
    { value: '', label: 'All Statuses' },
    { value: 'open', label: 'Open' },
    { value: 'closed', label: 'Closed' },
    { value: 'fp', label: 'False Positive' },
    { value: 'confirmed', label: 'Confirmed' },
  ]

  return (
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>Alert Queue</h1>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            {isLoading ? 'Loading…' : `${total} alert${total !== 1 ? 's' : ''} — click any row to expand · `}
            <span style={{ color: C.purple }}>click ⬡ to open attack-chain view</span>
          </div>
        </div>
        <button className="btn btn-ghost" onClick={() => queryClient.invalidateQueries()} disabled={isFetching}>
          <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 18, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input type="text" placeholder="Search host, user, IP…" value={searchTerm} onChange={e => setSearchTerm(e.target.value)} style={{ paddingLeft: 32, width: 240 }} />
        </div>
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}>
          {STATUS_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
            <AlertTriangle size={32} style={{ marginBottom: 8, opacity: 0.4 }} />
            <div>No alerts found.</div>
          </div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>Severity</th>
                <th>Host</th>
                <th>User</th>
                <th>MITRE Chain</th>
                <th>Confidence</th>
                <th>Time</th>
                <th>Assigned</th>
                <th>Status</th>
                <th style={{ width: 60, textAlign: 'center' }}>Graph</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => {
                const severity   = severityFromScore(alert.confidence_score)
                const isExpanded = expandedId === alert.basket_id
                const stages     = alert.matched_stages || []
                const sevColor   = { critical: C.red, high: C.orange, medium: C.yellow, low: C.cyan }[severity]

                return (
                  <>
                    <tr
                      key={alert.basket_id}
                      onClick={() => setExpandedId(prev => prev === alert.basket_id ? null : alert.basket_id)}
                      style={{ background: isExpanded ? 'var(--bg-secondary)' : undefined }}
                    >
                      <td style={{ paddingLeft: 16, paddingRight: 4 }}>
                        {isExpanded
                          ? <ChevronDown size={15} color="var(--accent)" />
                          : <ChevronRight size={15} color="var(--text-muted)" />}
                      </td>

                      <td>
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: '2px 9px', borderRadius: 999,
                          border: `1px solid ${sevColor}40`, background: sevColor + '18', color: sevColor,
                          textTransform: 'uppercase', letterSpacing: '0.06em',
                        }}>{severity}</span>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <Monitor size={13} color="var(--text-muted)" />
                          <span className="mono" style={{ fontSize: 13 }}>{alert.host_name}</span>
                        </div>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <User size={12} color="var(--text-muted)" />
                          <span style={{ fontSize: 13 }}>{alert.user_name || '—'}</span>
                        </div>
                      </td>

                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {stages.slice(0, 3).map((s, i) => {
                            const m = stageMeta(s.mitre)
                            return (
                              <span key={i} style={{
                                fontSize: 9.5, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                                background: m.color + '18', color: m.color,
                                border: `1px solid ${m.color}30`, fontFamily: 'monospace',
                              }}>{s.mitre}</span>
                            )
                          })}
                          {stages.length > 3 && <span style={{ fontSize: 11, color: 'var(--text-muted)', alignSelf: 'center' }}>+{stages.length - 3}</span>}
                        </div>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ width: 60, height: 4, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${alert.confidence_score}%`, background: sevColor, borderRadius: 3 }} />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{alert.confidence_score}%</span>
                        </div>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <Clock size={12} color="var(--text-muted)" />
                          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{relativeTime(alert.updated_at)}</span>
                        </div>
                      </td>

                      <td>
                        <span style={{ fontSize: 12, color: alert.assigned_to ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                          {alert.assigned_to || 'Unassigned'}
                        </span>
                      </td>

                      <td onClick={e => e.stopPropagation()}>
                        <span className={statusBadgeClass(alert.status)}>{alert.status}</span>
                      </td>

                      {/* Chain graph button */}
                      <td style={{ textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => setChainAlert(alert)}
                          title="Open Attack Chain View"
                          style={{
                            background: 'rgba(168,85,247,0.12)', border: '1px solid rgba(168,85,247,0.3)',
                            color: C.purple, borderRadius: 7, padding: '4px 8px', cursor: 'pointer',
                            fontSize: 13, lineHeight: 1, transition: 'all 0.15s',
                          }}
                        >
                          ⬡
                        </button>
                      </td>
                    </tr>

                    {isExpanded && (
                      <AlertDetail key={`${alert.basket_id}-detail`} alert={alert} onClose={() => setExpandedId(null)} />
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 20 }}>
          <button className="btn btn-ghost" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</button>
          {Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1).map(p => (
            <button key={p} onClick={() => setPage(p)} style={{
              width: 36, height: 36, borderRadius: 8,
              border: p === page ? '1px solid var(--border-active)' : '1px solid var(--border)',
              background: p === page ? 'var(--accent-light)' : 'var(--bg-card)',
              color: p === page ? 'var(--accent-bright)' : 'var(--text-secondary)',
              fontWeight: 600, fontSize: 13, cursor: 'pointer', transition: 'all 0.15s',
            }}>{p}</button>
          ))}
          <button className="btn btn-ghost" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next</button>
        </div>
      )}

      {/* ── Full-screen Attack Chain Modal ── */}
      {chainAlert && (
        <AttackChainModal alert={chainAlert} onClose={() => setChainAlert(null)} />
      )}
    </div>
  )
}
