import React from 'react'
import { LineChart } from 'lucide-react'

export default function KibanaPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-main)' }}>
      <div style={{ padding: '28px 32px' }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <LineChart size={24} style={{ color: 'var(--color-success)' }} />
          Kibana Analytics
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>Direct integration with the underlying Elasticsearch/Kibana cluster.</p>
      </div>
      
      <div style={{ flex: 1, padding: '0 32px 32px' }}>
        <div className="glass-card" style={{ overflow: 'hidden', width: '100%', height: '100%' }}>
          <iframe
            src="http://localhost:5601"
            style={{ width: '100%', height: '100%', border: '0', background: '#fff' }}
            title="Kibana"
            sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
          />
        </div>
      </div>
    </div>
  )
}

