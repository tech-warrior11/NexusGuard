import React, { useState, useEffect } from 'react';
import { 
  Briefcase, 
  Flame, 
  FileText, 
  CheckCircle2, 
  Clock, 
  User, 
  ShieldCheck, 
  Download, 
  Save, 
  Plus, 
  Crosshair 
} from 'lucide-react';
import { api } from '../services/api';

export function IncidentsTab({ onOpenReportModal }) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [saving, setSaving] = useState(false);

  // Form state for selected incident
  const [editStatus, setEditStatus] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [editContainment, setEditContainment] = useState('');
  const [editRemediation, setEditRemediation] = useState('');

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await api.getIncidents();
      setIncidents(res.incidents || []);
      if (res.incidents && res.incidents.length > 0 && !selectedIncident) {
        selectIncident(res.incidents[0]);
      }
    } catch (err) {
      console.error('Failed to fetch incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const selectIncident = (inc) => {
    setSelectedIncident(inc);
    setEditStatus(inc.status);
    setEditNotes(inc.investigation_notes || '');
    setEditContainment(inc.containment_steps || '');
    setEditRemediation(inc.remediation_notes || '');
  };

  const handleSaveChanges = async () => {
    if (!selectedIncident) return;
    setSaving(true);
    try {
      const updated = await api.updateIncident(selectedIncident.id, {
        status: editStatus,
        investigation_notes: editNotes,
        containment_steps: editContainment,
        remediation_notes: editRemediation
      });
      setSelectedIncident(updated);
      fetchIncidents();
      alert(`Incident ${updated.incident_number} updated successfully!`);
    } catch (err) {
      alert('Failed to update incident: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Briefcase size={20} color="var(--color-cyan)" />
            SOC INCIDENT RESPONSE & CASE MANAGEMENT
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Track active security investigations, record forensic analyst notes, implement containment, and export executive reports.
          </div>
        </div>

        <button 
          className="btn btn-secondary"
          onClick={fetchIncidents}
          disabled={loading}
        >
          Refresh Cases
        </button>
      </div>

      {/* Main Grid: Cases List & Active Case Investigation Workbench */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '20px' }}>
        
        {/* Left Column: Incidents List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: '700', letterSpacing: '0.05em' }}>
            ACTIVE CASE REGISTER ({incidents.length})
          </div>

          {incidents.length === 0 ? (
            <div className="cyber-card" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No incidents registered yet. Escalate an open alert to create a case.
            </div>
          ) : (
            incidents.map((inc) => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <div 
                  key={inc.id}
                  className="cyber-card"
                  style={{
                    padding: '16px',
                    borderLeft: `4px solid ${inc.severity === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-high)'}`,
                    background: isSelected ? 'rgba(19, 29, 51, 0.95)' : 'var(--bg-card)',
                    borderColor: isSelected ? 'var(--color-cyan)' : undefined,
                    cursor: 'pointer'
                  }}
                  onClick={() => selectIncident(inc)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="mono" style={{ fontWeight: '700', color: 'var(--color-cyan)', fontSize: '13px' }}>
                        {inc.incident_number}
                      </span>
                      <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
                      <span className={`badge badge-${inc.status}`}>{inc.status}</span>
                    </div>
                  </div>

                  <div style={{ fontWeight: '600', fontSize: '13.5px', color: '#fff', marginBottom: '6px' }}>
                    {inc.title}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    <span>Lead: <strong style={{ color: '#fff' }}>{inc.assigned_to || 'soc_analyst'}</strong></span>
                    <span className="mono">{new Date(inc.created_at).toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' })}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Active Incident Details & Investigation Notes Editor */}
        {selectedIncident ? (
          <div className="cyber-card">
            <div className="card-header">
              <div className="card-title">
                <Flame size={18} color="var(--color-critical)" />
                <span>CASE WORKBENCH: {selectedIncident.incident_number}</span>
              </div>
              <button 
                className="btn btn-primary btn-sm"
                onClick={() => onOpenReportModal(selectedIncident.id)}
              >
                <Download size={13} /> Export Report
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Title & Metadata row */}
              <div>
                <h3 style={{ fontSize: '16px', color: '#fff', marginBottom: '4px' }}>{selectedIncident.title}</h3>
                <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                  {selectedIncident.summary}
                </div>
              </div>

              {/* Status & Priority Row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', background: 'rgba(19, 29, 51, 0.4)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>CASE STATUS</label>
                  <select 
                    className="form-select" 
                    value={editStatus} 
                    onChange={(e) => setEditStatus(e.target.value)}
                    style={{ fontSize: '12px', padding: '6px' }}
                  >
                    <option value="OPEN">🚨 OPEN</option>
                    <option value="INVESTIGATING">🔍 INVESTIGATING</option>
                    <option value="CONTAINED">🛡️ CONTAINED</option>
                    <option value="RESOLVED">✅ RESOLVED</option>
                    <option value="FALSE_POSITIVE">⚪ FALSE POSITIVE</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>LEAD ANALYST</label>
                  <div className="mono" style={{ fontSize: '13px', paddingTop: '6px', color: '#fff' }}>
                    {selectedIncident.assigned_to || 'soc_analyst'}
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>MITRE ATT&CK</label>
                  <div className="mono" style={{ fontSize: '12px', paddingTop: '6px', color: 'var(--color-high)' }}>
                    {selectedIncident.mitre_techniques || 'T1110'}
                  </div>
                </div>
              </div>

              {/* Associated Alert Info */}
              {selectedIncident.alert && (
                <div style={{ background: '#0a0e17', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px', fontSize: '12.5px' }}>
                  <div style={{ color: 'var(--color-cyan)', fontWeight: '600', marginBottom: '4px' }}>
                    Linked Detection Alert #{selectedIncident.alert.id} ({selectedIncident.alert.rule_id})
                  </div>
                  <div>Source IP: <span className="mono" style={{ color: '#fff' }}>{selectedIncident.alert.source_ip || 'N/A'}</span> | Threat Confidence: <span style={{ color: 'var(--color-critical)' }}>{selectedIncident.alert.threat_score || 85}%</span></div>
                </div>
              )}

              {/* Analyst Investigation Notes */}
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: '600', display: 'block', marginBottom: '6px' }}>
                  Analyst Investigation Log & Evidence
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={4}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  placeholder="Record timeline of actions, IP checks, compromised accounts, malware hash hashes..."
                />
              </div>

              {/* Containment Steps */}
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: '600', display: 'block', marginBottom: '6px' }}>
                  Containment & Eradication Actions
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={3}
                  value={editContainment}
                  onChange={(e) => setEditContainment(e.target.value)}
                  placeholder="e.g. Ingress firewall block applied, active user tokens revoked, host isolated..."
                />
              </div>

              {/* Post-Incident Remediation */}
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: '600', display: 'block', marginBottom: '6px' }}>
                  Post-Incident Hardening & Remediation
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={2}
                  value={editRemediation}
                  onChange={(e) => setEditRemediation(e.target.value)}
                  placeholder="e.g. Enforce MFA, review firewall ACLs, configure fail2ban..."
                />
              </div>

              {/* Save Button */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                <button 
                  className="btn btn-primary"
                  onClick={handleSaveChanges}
                  disabled={saving}
                >
                  <Save size={14} /> {saving ? 'Saving...' : 'Save Case Updates'}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="cyber-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Select a case on the left to start investigation workbench.
          </div>
        )}
      </div>
    </div>
  );
}
