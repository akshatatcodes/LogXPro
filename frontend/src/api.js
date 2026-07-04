import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

// Dashboard
export const fetchMetrics = () => api.get('/dashboard/metrics').then(r => r.data)

// Alerts
export const fetchAlerts = (params) => api.get('/alerts', { params }).then(r => r.data)
export const fetchAlertDetail = (id) => api.get(`/alerts/${id}`).then(r => r.data)
export const assignAlert = (id, analyst_name) => api.post(`/alerts/${id}/assign`, { analyst_name }).then(r => r.data)
export const closeAlert = (id, analyst_name) => api.post(`/alerts/${id}/close`, { analyst_name }).then(r => r.data)
export const markFalsePositive = (id, payload) => api.post(`/alerts/${id}/false-positive`, payload).then(r => r.data)

// Open baskets
export const fetchOpenBaskets = () => api.get('/baskets/open').then(r => r.data)

// GRC
export const fetchGRC = () => api.get('/grc').then(r => r.data)
export const setGRCProfile = (profile) => api.post('/grc', { profile }).then(r => r.data)

// Phase 8: Logs & Enrichment
export const searchLogs = (params) => api.get('/logs/search', { params }).then(r => r.data)
export const fetchSavedSearches = () => api.get('/logs/saved_searches').then(r => r.data)
export const saveSearch = (data) => api.post('/logs/saved_searches', data).then(r => r.data)
export const deleteSavedSearch = (id) => api.delete(`/logs/saved_searches/${id}`).then(r => r.data)
export const enrichIndicator = (indicator, type) => api.get(`/enrichment/${indicator}`, { params: { type } }).then(r => r.data)

// Phase 9: Cases
export const fetchCases = () => api.get('/cases').then(r => r.data)
export const createCase = (data) => api.post('/cases', data).then(r => r.data)
export const deleteCase = (id) => api.delete(`/cases/${id}`).then(r => r.data)
export const updateCase = (id, data) => api.put(`/cases/${id}`, data).then(r => r.data)

// Phase 10: Docs & Playbooks
export const fetchDocs = () => api.get('/docs').then(r => r.data)
export const fetchDocContent = (filename) => api.get(`/docs/${filename}`).then(r => r.data.content)
export const saveDoc = (data) => api.post('/docs', data).then(r => r.data)
export const deleteDoc = (filename) => api.delete(`/docs/${filename}`).then(r => r.data)

export const fetchPlaybooks = () => api.get('/playbooks').then(r => r.data)
export const fetchPlaybookContent = (filename) => api.get(`/playbooks/${filename}`).then(r => r.data.content)
export const savePlaybook = (data) => api.post('/playbooks', data).then(r => r.data)
export const deletePlaybook = (filename) => api.delete(`/playbooks/${filename}`).then(r => r.data)

// Analyst Management & Sessions
export const fetchAnalysts = () => api.get('/analysts').then(r => r.data)
export const saveAnalyst = (data) => api.post('/analysts', data).then(r => r.data)
export const deleteAnalyst = (id) => api.delete(`/analysts/${id}`).then(r => r.data)
export const fetchSessions = () => api.get('/analysts/sessions').then(r => r.data)
export const loginAnalyst = (name) => api.post('/analysts/login', { name }).then(r => r.data)
export const logoutAnalyst = (name) => api.post('/analysts/logout', { name }).then(r => r.data)


