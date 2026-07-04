import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchDocs, fetchDocContent } from '../api'
import ReactMarkdown from 'react-markdown'
import { BookOpen, FileText } from 'lucide-react'

export default function DocsPage() {
  const { data: docsList = [], isLoading: listLoading } = useQuery({
    queryKey: ['docs'],
    queryFn: fetchDocs
  })

  const [activeDoc, setActiveDoc] = useState(null)

  const selectedFile = activeDoc || (docsList.length > 0 ? docsList[0].filename : null)

  const { data: content = '', isLoading: contentLoading } = useQuery({
    queryKey: ['docsContent', selectedFile],
    queryFn: () => fetchDocContent(selectedFile),
    enabled: !!selectedFile
  })

  return (
    <div style={{ display: 'flex', height: '100%', background: 'var(--bg-main)' }}>
      {/* Sidebar */}
      <div style={{
        width: 240,
        minWidth: 240,
        borderRight: '1px solid var(--border)',
        background: 'var(--bg-card)',
        padding: '20px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
      }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
          <BookOpen size={13} /> Knowledge Base
        </div>

        {listLoading ? (
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Loading docs...</div>
        ) : docsList.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No documentation found.</div>
        ) : (
          docsList.map(doc => (
            <button
              key={doc.id}
              onClick={() => setActiveDoc(doc.filename)}
              style={{
                textAlign: 'left',
                padding: '8px 12px',
                borderRadius: 8,
                fontSize: 13,
                fontWeight: selectedFile === doc.filename ? 600 : 400,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                border: selectedFile === doc.filename ? '1px solid #c7d2fe' : '1px solid transparent',
                background: selectedFile === doc.filename ? '#eef2ff' : 'transparent',
                color: selectedFile === doc.filename ? '#4f46e5' : 'var(--text-secondary)',
                transition: 'all 0.15s',
              }}
            >
              <FileText size={13} /> {doc.title}
            </button>
          ))
        )}
      </div>

      {/* Content Area */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '32px 48px' }}>
        <div style={{ maxWidth: 800, margin: '0 auto' }}>
          {contentLoading ? (
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Loading content...</div>
          ) : content ? (
            <div style={{
              fontSize: 14,
              lineHeight: 1.7,
              color: 'var(--text-primary)',
            }}>
              <ReactMarkdown
                components={{
                  h1: ({ children }) => <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>{children}</h1>,
                  h2: ({ children }) => <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginTop: 28, marginBottom: 12 }}>{children}</h2>,
                  h3: ({ children }) => <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-secondary)', marginTop: 20, marginBottom: 8 }}>{children}</h3>,
                  p: ({ children }) => <p style={{ color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.7 }}>{children}</p>,
                  code: ({ inline, children }) => inline
                    ? <code style={{ fontFamily: 'monospace', fontSize: 12, background: '#f1f5f9', color: '#4f46e5', padding: '2px 6px', borderRadius: 4 }}>{children}</code>
                    : <pre style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: 8, padding: 16, overflowX: 'auto', fontSize: 12, fontFamily: 'monospace', marginBottom: 16 }}><code>{children}</code></pre>,
                  ul: ({ children }) => <ul style={{ paddingLeft: 20, marginBottom: 12, color: 'var(--text-secondary)' }}>{children}</ul>,
                  li: ({ children }) => <li style={{ marginBottom: 4 }}>{children}</li>,
                  strong: ({ children }) => <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{children}</strong>,
                  a: ({ href, children }) => <a href={href} style={{ color: '#4f46e5', textDecoration: 'underline' }}>{children}</a>,
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          ) : (
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Select a document from the sidebar.</div>
          )}
        </div>
      </div>
    </div>
  )
}
