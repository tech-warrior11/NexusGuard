/**
 * NexusGuard Frontend API Client
 */

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

async function request(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  const token = localStorage.getItem('token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      localStorage.removeItem('token');
      window.location.reload();
      return null;
    }
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP Error ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    console.error(`API Error on ${url}:`, err);
    throw err;
  }
}

export const api = {
  // Auth
  login: async (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);
    
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData
    });
    if (!res.ok) throw new Error('Invalid credentials');
    return await res.json();
  },
  updateCredentials: (newPassword) => request('/auth/update', {
    method: 'POST',
    body: JSON.stringify({ new_password: newPassword })
  }),

  // Metrics & Stats
  getMetrics: () => request('/metrics'),

  // Logs
  getLogs: (params = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') query.append(k, v);
    });
    return request(`/logs?${query.toString()}`);
  },
  ingestLog: (logData) => request('/logs', { method: 'POST', body: JSON.stringify(logData) }),
  ingestRawLog: (rawData) => request('/logs/raw', { method: 'POST', body: JSON.stringify(rawData) }),

  // Alerts
  getAlerts: (params = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') query.append(k, v);
    });
    return request(`/alerts?${query.toString()}`);
  },
  updateAlertStatus: (alertId, status, description) => 
    request(`/alerts/${alertId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, description })
    }),
  escalateAlert: (alertId, payload) => 
    request(`/alerts/${alertId}/escalate`, {
      method: 'POST',
      body: JSON.stringify(payload)
    }),

  // Incidents
  getIncidents: (params = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') query.append(k, v);
    });
    return request(`/incidents?${query.toString()}`);
  },
  createIncident: (data) => request('/incidents', { method: 'POST', body: JSON.stringify(data) }),
  updateIncident: (id, data) => request(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  getIncidentReport: (id) => request(`/incidents/${id}/report`),

  // Rules
  getRules: () => request('/rules'),
  toggleRule: (ruleId) => request(`/rules/${ruleId}/toggle`, { method: 'POST' }),
  updateRule: (ruleId, data) => request(`/rules/${ruleId}`, { method: 'PATCH', body: JSON.stringify(data) }),

  // Threat Intel
  lookupThreatIntel: (indicator) => request(`/threat-intel/lookup?indicator=${encodeURIComponent(indicator)}`),
  getKnownIOCs: (type) => request(`/threat-intel/iocs${type ? `?ioc_type=${type}` : ''}`),
  getMitreMatrix: () => request('/threat-intel/mitre-matrix'),

  // Tools & CyberChef
  executeCyberChef: (operation, inputText, param) => 
    request('/tools/cyberchef', {
      method: 'POST',
      body: JSON.stringify({ operation, input_text: inputText, param })
    }),
  extractIOCs: (rawText) => 
    request('/tools/extract-iocs', {
      method: 'POST',
      body: JSON.stringify({ raw_text: rawText })
    }),
  inspectPCAP: (pcapText) => 
    request('/tools/pcap-inspector', {
      method: 'POST',
      body: JSON.stringify({ raw_pcap_text: pcapText })
    })
};
