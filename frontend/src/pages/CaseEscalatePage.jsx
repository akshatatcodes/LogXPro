import React, { useState, useRef } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query'
import { createCase, fetchAnalysts } from '../api'
import { FileText, Save, X, AlertTriangle, Download } from 'lucide-react'
import { formatTime, severityFromScore } from '../utils'
import html2canvas from 'html2canvas'
import jsPDF from 'jspdf'

const inputStyle = {
  width: '100%',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: '10px 14px',
  fontSize: 14,
  background: 'var(--bg-main)',
  color: 'var(--text-primary)',
  outline: 'none',
  boxSizing: 'border-box',
}

const labelStyle = {
  display: 'block',
  fontSize: 13,
  fontWeight: 600,
  color: 'var(--text-secondary)',
  marginBottom: 6,
}

export default function CaseEscalatePage() {
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const pdfRef = useRef(null)

  const alert = location.state?.alert

  // Fetch live analyst list from Admin panel data source
  const { data: analysts = [], isLoading: analystsLoading } = useQuery({
    queryKey: ['analysts'],
    queryFn: fetchAnalysts,
    staleTime: 60_000,
  })

  const [formData, setFormData] = useState({
    title: alert ? `Incident — ${alert.host_name} (${severityFromScore(alert.confidence_score).toUpperCase()})` : '',
    severity: severityFromScore(alert?.confidence_score || 0),
    assignee: alert?.assigned_to || '',
    summary: alert?.ai_narrative || '',
    technical_details: JSON.stringify(alert || {}, null, 2),
    basket_id: alert?.basket_id || null,
    close_basket: true
  })

  const mutation = useMutation({
    mutationFn: createCase,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      navigate('/cases')
    }
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    mutation.mutate(formData)
  }

  const handleExportPDF = async () => {
    if (!pdfRef.current) return
    try {
      const canvas = await html2canvas(pdfRef.current, { scale: 2, useCORS: true })
      const imgData = canvas.toDataURL('image/png')
      const pdf = new jsPDF('p', 'mm', 'a4')
      const pdfWidth = pdf.internal.pageSize.getWidth()
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight)
      pdf.save(`Case_Report_${formData.title.replace(/[^a-z0-9]/gi, '_')}.pdf`)
    } catch (err) {
      console.error('Failed to export PDF:', err)
    }
  }

  return (
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <FileText size={24} color="#4f46e5" />
          Escalate to Case Report
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>Formalize an incident report for tracking and remediation.</p>
      </div>

      <div ref={pdfRef} className="glass-card" style={{ padding: 28 }}>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Linked Alert Banner */}
          {alert && (
            <div style={{
              background: '#eff6ff',
              border: '1px solid #bfdbfe',
              borderRadius: 10,
              padding: '14px 18px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <AlertTriangle size={16} color="#3b82f6" />
                <span style={{ fontSize: 13, fontWeight: 600, color: '#1d4ed8' }}>Linked to Alert Basket</span>
              </div>
              <p style={{ fontSize: 12, fontFamily: 'monospace', color: '#3b82f6', marginBottom: 10 }}>{alert.basket_id}</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                {[
                  { label: 'Host', value: alert.host_name },
                  { label: 'User', value: alert.user_name || '—' },
                  { label: 'Created', value: formatTime(alert.created_at) },
                  { label: 'Score', value: `${alert.confidence_score}%` },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: '#93c5fd', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
                    <div style={{ fontSize: 13, fontWeight: 500, color: '#1e40af', marginTop: 2 }}>{value}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Case Title */}
          <div>
            <label style={labelStyle}>Case Title</label>
            <input
              required
              type="text"
              value={formData.title}
              onChange={e => setFormData({ ...formData, title: e.target.value })}
              style={inputStyle}
              placeholder="e.g. Unauthorized RDP Access to DESKTOP-01"
            />
          </div>

          {/* Severity + Assignee */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div>
              <label style={labelStyle}>Severity</label>
              <select
                value={formData.severity}
                onChange={e => setFormData({ ...formData, severity: e.target.value })}
                style={inputStyle}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>Assignee</label>
              <select
                value={formData.assignee}
                onChange={e => setFormData({ ...formData, assignee: e.target.value })}
                style={inputStyle}
                disabled={analystsLoading}
              >
                <option value="">{analystsLoading ? 'Loading analysts…' : '-- Select Analyst --'}</option>
                {analysts.map(a => (
                  <option key={a.id} value={a.name}>
                    {a.name}{a.role ? ` (${a.role})` : ''}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Summary */}
          <div>
            <label style={labelStyle}>Executive Summary</label>
            <textarea
              required
              rows={4}
              value={formData.summary}
              onChange={e => setFormData({ ...formData, summary: e.target.value })}
              style={{ ...inputStyle, resize: 'vertical', fontFamily: 'inherit' }}
              placeholder="Brief summary of the incident..."
            />
          </div>

          {/* Technical Details */}
          <div>
            <label style={labelStyle}>Technical Details</label>
            <textarea
              rows={10}
              value={formData.technical_details}
              onChange={e => setFormData({ ...formData, technical_details: e.target.value })}
              style={{ ...inputStyle, resize: 'vertical', fontFamily: 'monospace', fontSize: 12 }}
              placeholder="IOCs, attack chain timeline, relevant logs..."
            />
          </div>

          {/* Close basket checkbox */}
          {alert && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <input
                type="checkbox"
                id="close_basket"
                checked={formData.close_basket}
                onChange={e => setFormData({ ...formData, close_basket: e.target.checked })}
                style={{ width: 16, height: 16, accentColor: '#4f46e5' }}
              />
              <label htmlFor="close_basket" style={{ fontSize: 13, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                Automatically resolve the associated alert basket upon case creation.
              </label>
            </div>
          )}

          {/* Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <button
              type="button"
              onClick={handleExportPDF}
              style={{
                padding: '9px 18px', borderRadius: 8, fontSize: 13, fontWeight: 600,
                background: '#f3f0ff', color: '#7c3aed', border: '1px solid #e9d5ff',
                cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                transition: 'background 0.15s',
              }}
            >
              <Download size={15} /> Export PDF
            </button>
            <button
              type="button"
              onClick={() => navigate(-1)}
              className="btn btn-ghost"
            >
              <X size={15} /> Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="btn btn-primary"
            >
              <Save size={15} />
              {mutation.isPending ? 'Saving...' : 'Submit Case Report'}
            </button>
          </div>

        </form>
      </div>
    </div>
  )
}
