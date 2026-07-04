import React, { useState, useRef } from 'react'
import { UploadCloud, CheckCircle, XCircle, File, Loader, ExternalLink } from 'lucide-react'

export default function FileUploadPage() {
  const [file, setFile] = useState(null)
  const [status, setStatus] = useState('idle') // idle, uploading, success, error
  const [result, setResult] = useState(null)
  const fileInputRef = useRef(null)

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setStatus('idle')
      setResult(null)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    const dropped = e.dataTransfer.files[0]
    if (dropped) {
      setFile(dropped)
      setStatus('idle')
      setResult(null)
    }
  }

  const handleUpload = async () => {
    if (!file) return

    setStatus('uploading')

    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch('http://localhost:8000/api/upload', {
        method: 'POST',
        body: formData,
      })

      const data = await res.json()
      setResult(data)

      if (res.ok && data.status === 'success') {
        setStatus('success')
      } else {
        setStatus('error')
      }
    } catch (err) {
      setStatus('error')
      setResult({ status: 'error', message: err.message || 'Network error. Is the API server running on port 8000?' })
    }
  }

  return (
    <div style={{ padding: '28px 32px', maxWidth: 900, background: 'var(--bg-main)', minHeight: '100vh' }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
          Log File Upload
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Upload historical log files or PCAPs for ingestion and analysis. Events are sent directly to the correlation engine running on port 8000.
        </p>
      </div>

      {/* Info Banner */}
      <div style={{
        background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 10,
        padding: '12px 16px', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10
      }}>
        <ExternalLink size={16} color="#2563eb" />
        <div style={{ fontSize: 13, color: '#1e40af' }}>
          <strong>Supported formats:</strong> JSON, JSONL, CSV, Syslog (.log, .txt), Zeek logs, PCAP/PCAPNG
        </div>
      </div>

      <div className="glass-card" style={{ padding: 32 }}>
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          style={{ display: 'none' }}
          accept=".json,.jsonl,.csv,.log,.txt,.pcap,.pcapng"
        />

        {!file ? (
          <div
            onDrop={handleDrop}
            onDragOver={e => e.preventDefault()}
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: '2px dashed #e2e8f0', borderRadius: 12,
              padding: '64px 32px', display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center', textAlign: 'center',
              cursor: 'pointer', transition: 'all 0.2s',
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#6366f1'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#e2e8f0'}
          >
            <div style={{
              width: 64, height: 64, borderRadius: 16, background: '#eef2ff',
              display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16
            }}>
              <UploadCloud size={32} color="#4f46e5" />
            </div>
            <h3 style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>
              Drop files here or click to browse
            </h3>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
              JSON, CSV, Syslog, PCAP supported
            </p>
            <button className="btn btn-ghost" style={{ pointerEvents: 'none' }}>
              Browse Files
            </button>
          </div>
        ) : (
          <div style={{ maxWidth: 600, margin: '0 auto' }}>
            {/* File info card */}
            <div style={{
              background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 10,
              padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24
            }}>
              <div style={{
                width: 48, height: 48, borderRadius: 10, background: '#eef2ff',
                display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
              }}>
                <File size={24} color="#4f46e5" />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {file.name}
                </p>
                <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {(file.size / 1024).toFixed(1)} KB · {file.type || 'Unknown type'}
                </p>
              </div>
              {status === 'idle' && (
                <button
                  onClick={() => setFile(null)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8' }}
                >
                  <XCircle size={20} />
                </button>
              )}
            </div>

            {/* Upload button */}
            {status === 'idle' && (
              <button
                onClick={handleUpload}
                className="btn btn-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '10px', fontSize: 14 }}
              >
                <UploadCloud size={16} /> Start Upload & Ingestion
              </button>
            )}

            {status === 'uploading' && (
              <button disabled className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center', padding: '10px', fontSize: 14 }}>
                <Loader className="animate-spin" size={16} /> Processing file…
              </button>
            )}

            {/* Result */}
            {result && (
              <div style={{
                marginTop: 16, padding: '14px 18px', borderRadius: 10,
                background: status === 'success' ? '#f0fdf4' : '#fef2f2',
                border: `1px solid ${status === 'success' ? '#bbf7d0' : '#fecaca'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: status === 'success' ? 10 : 0 }}>
                  {status === 'success'
                    ? <CheckCircle size={18} color="#16a34a" />
                    : <XCircle size={18} color="#dc2626" />}
                  <span style={{ fontWeight: 600, color: status === 'success' ? '#16a34a' : '#dc2626', fontSize: 14 }}>
                    {status === 'success' ? 'Upload successful!' : 'Upload failed'}
                  </span>
                </div>
                {status === 'success' && (
                  <div style={{ fontSize: 13, color: '#15803d', lineHeight: 1.7 }}>
                    <div>✓ <strong>{result.events_parsed}</strong> events parsed from <strong>{result.file_type?.toUpperCase()}</strong> file</div>
                    <div>✓ Events routed to correlation engine for analysis</div>
                    <div>✓ Check the <strong>Alert Queue</strong> in a few seconds for generated alerts</div>
                  </div>
                )}
                {status === 'error' && (
                  <div style={{ fontSize: 13, color: '#b91c1c', marginTop: 4 }}>
                    {result.message || 'Unknown error occurred.'}
                  </div>
                )}
              </div>
            )}

            {(status === 'success' || status === 'error') && (
              <button
                onClick={() => { setFile(null); setStatus('idle'); setResult(null) }}
                className="btn btn-ghost"
                style={{ width: '100%', justifyContent: 'center', marginTop: 12, fontSize: 13 }}
              >
                Upload another file
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
