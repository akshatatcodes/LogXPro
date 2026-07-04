import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users, BookOpen, FileText, Zap, Plus, Trash2,
  Edit3, Save, X, Clock, ShieldCheck, Activity, LogIn, LogOut
} from 'lucide-react'
import {
  fetchCases, fetchPlaybooks, fetchDocs, deleteCase, updateCase,
  fetchAnalysts, saveAnalyst, deleteAnalyst, fetchSessions, loginAnalyst, logoutAnalyst,
  savePlaybook, deletePlaybook, saveDoc, deleteDoc, fetchPlaybookContent, fetchDocContent
} from '../api'
import { relativeTime } from '../utils'

/* ── Analysts Tab ─────────────────────────────────────────── */
function AnalystsTab() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ name: '', email: '', role: 'analyst' })
  const [editId, setEditId] = useState(null)

  const { data: analysts = [], isLoading: analystsLoading } = useQuery({
    queryKey: ['analysts'],
    queryFn: fetchAnalysts
  })

  const { data: sessions = [], isLoading: sessionsLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: fetchSessions,
    refetchInterval: 5000
  })

  const mutSave = useMutation({
    mutationFn: saveAnalyst,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analysts'] })
      setForm({ name: '', email: '', role: 'analyst' })
      setEditId(null)
    }
  })

  const mutDelete = useMutation({
    mutationFn: deleteAnalyst,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analysts'] })
    }
  })

  const mutLogin = useMutation({
    mutationFn: loginAnalyst,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analysts'] })
      qc.invalidateQueries({ queryKey: ['sessions'] })
    }
  })

  const mutLogout = useMutation({
    mutationFn: logoutAnalyst,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analysts'] })
      qc.invalidateQueries({ queryKey: ['sessions'] })
    }
  })

  const handleAdd = () => {
    if (!form.name.trim()) return
    mutSave.mutate({ id: editId, ...form })
  }

  const handleDelete = (id) => {
    if (window.confirm("Are you sure you want to delete this analyst?")) {
      mutDelete.mutate(id)
    }
  }

  const handleEdit = (a) => {
    setEditId(a.id)
    setForm({ name: a.name, email: a.email, role: a.role })
  }

  return (
    <div>
      {/* Add / Edit Form */}
      <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: 'var(--text-primary)' }}>
          {editId !== null ? 'Edit Analyst Profile' : 'Register New Analyst'}
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto auto', gap: 12, alignItems: 'end' }}>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Name</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="John Doe" style={{ width: '100%' }} />
          </div>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Email</label>
            <input value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} placeholder="john@soc.com" style={{ width: '100%' }} />
          </div>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Role</label>
            <select value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))} style={{ width: '100%' }}>
              <option value="analyst">Analyst</option>
              <option value="senior_analyst">Senior Analyst</option>
              <option value="manager">Manager</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" onClick={handleAdd} style={{ whiteSpace: 'nowrap' }} disabled={mutSave.isPending}>
              <Save size={14} /> {editId !== null ? 'Update' : 'Add'}
            </button>
            {editId !== null && (
              <button className="btn btn-ghost" onClick={() => { setEditId(null); setForm({ name: '', email: '', role: 'analyst' }) }}>
                <X size={14} />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Analyst List */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Analyst</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Session Controls</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {analystsLoading ? (
              <tr><td colSpan={6} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading analysts…</td></tr>
            ) : analysts.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>No analysts added yet.</td></tr>
            ) : analysts.map(a => (
              <tr key={a.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: '50%', background: '#eef2ff',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 13, fontWeight: 700, color: '#4f46e5'
                    }}>
                      {a.name.charAt(0).toUpperCase()}
                    </div>
                    <span style={{ fontWeight: 500 }}>{a.name}</span>
                  </div>
                </td>
                <td style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{a.email || '—'}</td>
                <td>
                  <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 999, background: '#eef2ff', color: '#4f46e5', border: '1px solid #c7d2fe' }}>
                    {a.role}
                  </span>
                </td>
                <td>
                  {a.status === 'active' ? (
                    <span style={{ fontSize: 12, color: '#16a34a', fontWeight: 600 }}>● Active Session</span>
                  ) : (
                    <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 500 }}>○ Offline</span>
                  )}
                </td>
                <td>
                  <button
                    className={a.status === 'active' ? 'btn btn-danger' : 'btn btn-success'}
                    style={{ padding: '4px 10px', fontSize: 11.5 }}
                    disabled={mutLogin.isPending || mutLogout.isPending}
                    onClick={() => {
                      if (a.status === 'active') {
                        mutLogout.mutate(a.name)
                      } else {
                        mutLogin.mutate(a.name)
                      }
                    }}
                  >
                    {a.status === 'active' ? <LogOut size={12} /> : <LogIn size={12} />}
                    {a.status === 'active' ? 'Force Exit' : 'Start Session'}
                  </button>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="btn btn-ghost" onClick={() => handleEdit(a)} style={{ padding: '4px 10px' }}>
                      <Edit3 size={13} />
                    </button>
                    <button className="btn btn-danger" onClick={() => handleDelete(a.id)} style={{ padding: '4px 10px' }}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Sessions / Activity Log */}
      <div className="glass-card" style={{ marginTop: 24, overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={15} color="var(--accent)" />
          <h3 style={{ fontSize: 14, fontWeight: 600 }}>Session Logs (PostgreSQL Storage)</h3>
        </div>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Analyst</th>
              <th>Login Time</th>
              <th>Logout Time</th>
              <th>Session Duration</th>
            </tr>
          </thead>
          <tbody>
            {sessionsLoading ? (
              <tr><td colSpan={4} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading sessions…</td></tr>
            ) : sessions.length === 0 ? (
              <tr><td colSpan={4} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>No logs recorded. Login above to create a session entry.</td></tr>
            ) : sessions.map((s, i) => (
              <tr key={i}>
                <td style={{ fontWeight: 500 }}>{s.name}</td>
                <td style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>{s.login_time ? new Date(s.login_time).toLocaleString() : '—'}</td>
                <td style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>{s.logout_time ? new Date(s.logout_time).toLocaleString() : <span style={{ color: '#16a34a', fontWeight: 600 }}>Active Now</span>}</td>
                <td style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--accent-bright)' }}>{s.duration || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ── Cases Tab ────────────────────────────────────────────── */
function CasesTab() {
  const qc = useQueryClient()
  const { data: cases = [], isLoading } = useQuery({ queryKey: ['cases'], queryFn: fetchCases })
  const { data: analysts = [] } = useQuery({ queryKey: ['analysts'], queryFn: fetchAnalysts })
  const [editingCase, setEditingCase] = useState(null)

  const mutDelete = useMutation({
    mutationFn: deleteCase,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases'] })
  })

  const mutUpdate = useMutation({
    mutationFn: ({ id, data }) => updateCase(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      setEditingCase(null)
    }
  })

  const handleDelete = (id) => {
    if (window.confirm("Are you sure you want to delete this case report?")) {
      mutDelete.mutate(id)
    }
  }

  const handleSaveUpdate = (e) => {
    e.preventDefault()
    mutUpdate.mutate({
      id: editingCase.id,
      data: {
        title: editingCase.title,
        severity: editingCase.severity,
        assignee: editingCase.assignee,
        summary: editingCase.summary,
        technical_details: editingCase.technical_details,
        status: editingCase.status
      }
    })
  }

  return (
    <div>
      {/* Edit Form */}
      {editingCase && (
        <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: 'var(--text-primary)' }}>
            Edit Case Details: CAS-{editingCase.id}
          </h3>
          <form onSubmit={handleSaveUpdate} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Case Title</label>
                <input
                  required
                  value={editingCase.title}
                  onChange={e => setEditingCase({ ...editingCase, title: e.target.value })}
                  style={{ width: '100%' }}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Assignee</label>
                <select
                  value={editingCase.assignee || ''}
                  onChange={e => setEditingCase({ ...editingCase, assignee: e.target.value })}
                  style={{ width: '100%' }}
                >
                  <option value="">-- Select Analyst --</option>
                  {analysts.map(a => (
                    <option key={a.id} value={a.name}>{a.name} ({a.role})</option>
                  ))}
                </select>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Severity</label>
                <select
                  value={editingCase.severity}
                  onChange={e => setEditingCase({ ...editingCase, severity: e.target.value })}
                  style={{ width: '100%' }}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Status</label>
                <select
                  value={editingCase.status}
                  onChange={e => setEditingCase({ ...editingCase, status: e.target.value })}
                  style={{ width: '100%' }}
                >
                  <option value="open">Open</option>
                  <option value="closed">Closed</option>
                </select>
              </div>
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Summary</label>
              <textarea
                value={editingCase.summary || ''}
                rows={3}
                onChange={e => setEditingCase({ ...editingCase, summary: e.target.value })}
                style={{ width: '100%', fontFamily: 'inherit' }}
              />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Technical Details</label>
              <textarea
                value={editingCase.technical_details || ''}
                rows={5}
                onChange={e => setEditingCase({ ...editingCase, technical_details: e.target.value })}
                style={{ width: '100%', fontFamily: 'monospace', fontSize: 11 }}
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button type="submit" className="btn btn-primary" disabled={mutUpdate.isPending}>
                <Save size={14} /> Save Changes
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => setEditingCase(null)}>
                <X size={14} /> Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Cases List */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>Loading cases…</div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Assignee</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {cases.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>No cases found.</td></tr>
              ) : cases.map(c => (
                <tr key={c.id}>
                  <td><span style={{ fontFamily: 'monospace', fontSize: 12, color: '#4f46e5', fontWeight: 600 }}>CAS-{c.id}</span></td>
                  <td style={{ fontWeight: 500 }}>{c.title}</td>
                  <td><span className={`badge badge-${c.severity?.toLowerCase()}`}>{c.severity}</span></td>
                  <td style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{c.assignee || '—'}</td>
                  <td><span className={`badge badge-${c.status === 'open' ? 'open' : 'closed'}`}>{c.status}</span></td>
                  <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{relativeTime(c.created_at)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn-ghost" onClick={() => setEditingCase(c)} style={{ padding: '4px 10px' }}>
                        <Edit3 size={13} />
                      </button>
                      <button className="btn btn-danger" onClick={() => handleDelete(c.id)} style={{ padding: '4px 10px' }}>
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

/* ── Playbooks Tab ────────────────────────────────────────── */
function PlaybooksTab() {
  const qc = useQueryClient()
  const { data: playbooks = [], isLoading } = useQuery({ queryKey: ['playbooks'], queryFn: fetchPlaybooks })
  
  // Editor state holds { filename: '', content: '', isNew: boolean }
  const [editor, setEditor] = useState(null)

  const mutSave = useMutation({
    mutationFn: savePlaybook,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['playbooks'] })
      setEditor(null)
    },
    onError: (err) => {
      alert(err.response?.data?.detail || "Failed to save playbook. Check YAML syntax.")
    }
  })

  const mutDelete = useMutation({
    mutationFn: deletePlaybook,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['playbooks'] })
    }
  })

  const handleNew = () => {
    setEditor({
      filename: 'new_playbook.yaml',
      content: `id: new_playbook
name: "My Custom Playbook"
description: "SOC action guidelines"
trigger_tier: [2, 3, 4]
matched_techniques:
  - T1059.001
actions:
  - type: notify
    message: "Alert triggered for technique"
    severity: high
`,
      isNew: true
    })
  }

  const handleEdit = async (pb) => {
    try {
      const rawContent = await fetchPlaybookContent(pb.filename)
      setEditor({
        filename: pb.filename,
        content: rawContent,
        isNew: false
      })
    } catch(err) {
      alert("Failed to load raw playbook content.")
    }
  }

  const handleDelete = (filename) => {
    if (window.confirm(`Are you sure you want to delete playbook ${filename}?`)) {
      mutDelete.mutate(filename)
    }
  }

  const handleSave = () => {
    if (!editor.filename.trim() || !editor.content.trim()) return
    mutSave.mutate({
      filename: editor.filename,
      yaml_content: editor.content
    })
  }

  return (
    <div>
      {/* Editor overlay/form */}
      {editor && (
        <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: 'var(--text-primary)' }}>
            {editor.isNew ? 'Create New Playbook File' : `Edit Playbook: ${editor.filename}`}
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Filename</label>
              <input
                value={editor.filename}
                onChange={e => setEditor({ ...editor, filename: e.target.value })}
                disabled={!editor.isNew}
                style={{ width: '100%' }}
                placeholder="playbook_name.yaml"
              />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Playbook Content (YAML Format)</label>
              <textarea
                value={editor.content}
                rows={14}
                onChange={e => setEditor({ ...editor, content: e.target.value })}
                style={{ width: '100%', fontFamily: 'monospace', fontSize: 12, lineHeight: 1.5 }}
                placeholder="yaml definition here..."
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={handleSave} disabled={mutSave.isPending}>
                <Save size={14} /> Save File
              </button>
              <button className="btn btn-ghost" onClick={() => setEditor(null)}>
                <X size={14} /> Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Active Response Playbooks stored as YAML config files.
        </div>
        <button className="btn btn-primary" onClick={handleNew}>
          <Plus size={14} /> New Playbook
        </button>
      </div>

      {isLoading ? (
        <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>Loading playbooks…</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {playbooks.map(pb => (
            <div key={pb.id} style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 12, padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{pb.content?.name || pb.filename}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{pb.filename}</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn btn-ghost" style={{ padding: '6px 12px' }} onClick={() => handleEdit(pb)}>
                    <Edit3 size={13} /> Edit YAML
                  </button>
                  <button className="btn btn-danger" style={{ padding: '6px 12px' }} onClick={() => handleDelete(pb.filename)}>
                    <Trash2 size={13} /> Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
          {playbooks.length === 0 && (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
              No playbooks found in config directory.
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ── Docs Tab ─────────────────────────────────────────────── */
function DocsTab() {
  const qc = useQueryClient()
  const { data: docs = [], isLoading } = useQuery({ queryKey: ['docs'], queryFn: fetchDocs })
  
  // Editor state holds { filename: '', content: '', isNew: boolean }
  const [editor, setEditor] = useState(null)

  const mutSave = useMutation({
    mutationFn: saveDoc,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['docs'] })
      setEditor(null)
    }
  })

  const mutDelete = useMutation({
    mutationFn: deleteDoc,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['docs'] })
    }
  })

  const handleNew = () => {
    setEditor({
      filename: 'new_document.md',
      content: `# My New Document\n\nWrite documentation or guides for the SOC team here...`,
      isNew: true
    })
  }

  const handleEdit = async (doc) => {
    try {
      const rawContent = await fetchDocContent(doc.filename)
      setEditor({
        filename: doc.filename,
        content: rawContent,
        isNew: false
      })
    } catch(err) {
      alert("Failed to load document content.")
    }
  }

  const handleDelete = (filename) => {
    if (window.confirm(`Are you sure you want to delete document ${filename}?`)) {
      mutDelete.mutate(filename)
    }
  }

  const handleSave = () => {
    if (!editor.filename.trim() || !editor.content.trim()) return
    mutSave.mutate({
      filename: editor.filename,
      content: editor.content
    })
  }

  return (
    <div>
      {/* Editor overlay/form */}
      {editor && (
        <div className="glass-card" style={{ padding: '20px 24px', marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16, color: 'var(--text-primary)' }}>
            {editor.isNew ? 'Create New Markdown Document' : `Edit Document: ${editor.filename}`}
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Filename</label>
              <input
                value={editor.filename}
                onChange={e => setEditor({ ...editor, filename: e.target.value })}
                disabled={!editor.isNew}
                style={{ width: '100%' }}
                placeholder="document_name.md"
              />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Markdown Content</label>
              <textarea
                value={editor.content}
                rows={14}
                onChange={e => setEditor({ ...editor, content: e.target.value })}
                style={{ width: '100%', fontFamily: 'monospace', fontSize: 12.5, lineHeight: 1.6 }}
                placeholder="# Document title..."
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={handleSave} disabled={mutSave.isPending}>
                <Save size={14} /> Save File
              </button>
              <button className="btn btn-ghost" onClick={() => setEditor(null)}>
                <X size={14} /> Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Knowledge base and analyst reference guides in Markdown.
        </div>
        <button className="btn btn-primary" onClick={handleNew}>
          <Plus size={14} /> New Document
        </button>
      </div>

      <div className="glass-card" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)' }}>Loading docs…</div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Filename</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {docs.length === 0 ? (
                <tr><td colSpan={3} style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>No documentation files found in /docs folder.</td></tr>
              ) : docs.map(d => (
                <tr key={d.id}>
                  <td style={{ fontWeight: 500 }}>{d.title}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 12, color: '#4f46e5' }}>{d.filename}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn-ghost" onClick={() => handleEdit(d)} style={{ padding: '4px 10px' }}>
                        <Edit3 size={13} /> Edit
                      </button>
                      <button className="btn btn-danger" onClick={() => handleDelete(d.filename)} style={{ padding: '4px 10px' }}>
                        <Trash2 size={13} /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

/* ── Main Admin Page ──────────────────────────────────────── */
const TABS = [
  { id: 'analysts',  icon: Users,      label: 'Analysts' },
  { id: 'cases',     icon: FileText,   label: 'Case Reports' },
  { id: 'playbooks', icon: Zap,        label: 'Playbooks' },
  { id: 'docs',      icon: BookOpen,   label: 'Documentation' },
]

export default function AdminPage() {
  const [tab, setTab] = useState('analysts')

  return (
    <div style={{ padding: '28px 32px', background: 'var(--bg-main)', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldCheck size={24} color="#4f46e5" />
          Admin Panel
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Manage analyst registry, active sessions, case reports, playbooks, and knowledge documents.
        </p>
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex', gap: 4, borderBottom: '1px solid var(--border)',
        marginBottom: 24, paddingBottom: 0
      }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 16px', fontSize: 13, fontWeight: 500,
              border: 'none', cursor: 'pointer', background: 'none',
              borderBottom: tab === t.id ? '2px solid #4f46e5' : '2px solid transparent',
              color: tab === t.id ? '#4f46e5' : 'var(--text-secondary)',
              marginBottom: -1,
              transition: 'all 0.15s'
            }}
          >
            <t.icon size={15} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {tab === 'analysts'  && <AnalystsTab />}
      {tab === 'cases'     && <CasesTab />}
      {tab === 'playbooks' && <PlaybooksTab />}
      {tab === 'docs'      && <DocsTab />}
    </div>
  )
}
