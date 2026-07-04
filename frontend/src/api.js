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
