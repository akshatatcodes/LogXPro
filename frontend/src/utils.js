export const ANALYSTS = [
  'Alice Chen', 'Bob Martinez', 'Carol Singh',
  'David Park', 'Eve Okafor', 'Frank Weber'
]

export function severityFromScore(score) {
  if (score >= 80) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

export function statusBadgeClass(status) {
  const map = {
    open: 'badge-open', closed: 'badge-closed', resolved: 'badge-closed',
    fp: 'badge-fp', confirmed: 'badge-high', expired: 'badge-fp'
  }
  return `badge ${map[status] || 'badge-low'}`
}

export function severityBadgeClass(severity) {
  return `badge badge-${severity}`
}

export function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
    + ' ' + d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

export function relativeTime(iso) {
  if (!iso) return '—'
  const diff = (Date.now() - new Date(iso)) / 1000
  if (diff < 60)   return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export const MITRE_LABELS = {
  'T1078':     'Valid Accounts',
  'T1059.001': 'PowerShell',
  'T1053.005': 'Scheduled Task',
  'T1071':     'App Layer C2',
  'T1003.001': 'LSASS Memory Dump',
  'T1021.002': 'SMB / WMI Lateral',
  'T1087.002': 'Domain Account Enum',
  'T1562.001': 'Disable AV',
  'T1490':     'Shadow Copy Delete',
}

export function mitreLabel(id) {
  return MITRE_LABELS[id] || id
}
