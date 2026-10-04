import React, { useState } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  Search, 
  Flame, 
  CheckCircle, 
  XCircle, 
  ExternalLink, 
  ArrowRight, 
  Clock, 
  User, 
  Crosshair 
} from 'lucide-react';
import { api } from '../services/api';

export function AlertsTab({ 
  alerts, 
  onRefresh, 
  onNavigateTab, 
  onSelectThreatIntel 
}) {
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [escalateModalAlert, setEscalateModalAlert] = useState(null);
  const [analystNotes, setAnalystNotes] = useState('');
  const [loadingAction, setLoadingAction] = useState(false);

  const filteredAlerts = alerts.filter(a => {
    if (severityFilter && a.severity !== severityFilter) return false;
    if (statusFilter && a.status !== statusFilter) return false;
    return true;
  });

  const handleUpdateStatus = async (alertId, newStatus) => {
    setLoadingAction(true);
    try {
      await api.updateAlertStatus(alertId, newStatus);
      onRefresh();
      if (selectedAlert?.id === alertId) {
        setSelectedAlert(prev => ({ ...prev, status: newStatus }));
      }
    } catch (err) {
      alert('Failed to update alert: ' + err.message);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleEscalate = async (e) => {
    e.preventDefault();
    if (!escalateModalAlert) return;
    setLoadingAction(true);
    try {
      const incident = await api.escalateAlert(escalateModalAlert.id, {
        assigned_to: 'soc_analyst',
        initial_notes: analystNotes || `Escalated alert ${escalateModalAlert.rule_id} for investigation.`
      });
      alert(`Successfully escalated Alert #${escalateModalAlert.id} to Incident ${incident.incident_number}!`);
      setEscalateModalAlert(null);
      setAnalystNotes('');
      onRefresh();
      onNavigateTab('incidents');
    } catch (err) {
      alert('Failed to escalate alert: ' + err.message);
    } finally {
      setLoadingAction(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={20} color="var(--color-critical)" />
            SECURITY ALERTS & TRIAGE CENTER
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Real-time automated threat detections mapped against MITRE ATT&CK techniques with 1-click SOC case escalation.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <select 
            className="form-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{ width: '150px' }}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">🔴 Critical</option>
            <option value="HIGH">🟠 High</option>
            <option value="MEDIUM">🟡 Medium</option>
            <option value="LOW">🔵 Low</option>
          </select>

          <select 
            className="form-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ width: '160px' }}
          >
            <option value="">All Statuses</option>
            <option value="OPEN">🚨 Open</option>
            <option value="INVESTIGATING">🔍 Investigating</option>
            <option value="RESOLVED">✅ Resolved</option>
            <option value="FALSE_POSITIVE">⚪ False Positive</option>
          </select>
        </div>
      </div>

      {/* Alerts Grid / List */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedAlert ? '1fr 1fr' : '1fr', gap: '20px' }}>
        
        {/* Alerts List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredAlerts.length === 0 ? (
            <div className="cyber-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <CheckCircle size={36} color="var(--color-success)" style={{ margin: '0 auto 12px' }} />
              <div>No alerts matching the selected filters.</div>
            </div>
          ) : (
            filteredAlerts.map(alert => {
              const isSelected = selectedAlert?.id === alert.id;
              return (
                <div 
                  key={alert.id}
                  className="cyber-card"
                  style={{
                    padding: '16px 18px',
                    borderLeft: `4px solid ${alert.severity === 'CRITICAL' ? 'var(--color-critical)' : (alert.severity === 'HIGH' ? 'var(--color-high)' : 'var(--color-medium)')}`,
                    background: isSelected ? 'rgba(19, 29, 51, 0.95)' : 'var(--bg-card)',
                    borderColor: isSelected ? 'var(--color-cyan)' : undefined,
                    cursor: 'pointer'
                  }}
                  onClick={() => setSelectedAlert(alert)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                      <span className={`badge badge-${alert.status}`}>{alert.status}</span>
                      <span className="mono" style={{ fontSize: '11px', color: 'var(--color-cyan)' }}>{alert.rule_id}</span>
                      <span style={{ fontWeight: '700', fontSize: '14px', color: '#fff' }}>{alert.alert_type}</span>
                    </div>
                    <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {new Date(alert.timestamp).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' })}
                    </span>
                  </div>

                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                    {alert.description}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', fontSize: '12px', color: 'var(--text-muted)', paddingTop: '8px', borderTop: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <div style={{ display: 'flex', gap: '14px' }}>
                      {alert.source_ip && <span>Origin IP: <strong className="mono" style={{ color: '#fff' }}>{alert.source_ip}</strong></span>}
                      {alert.username && <span>Target: <strong style={{ color: '#fff' }}>{alert.username}</strong></span>}
                      {alert.mitre_technique_id && <span>MITRE: <strong className="mono" style={{ color: 'var(--color-high)' }}>{alert.mitre_technique_id}</strong></span>}
                    </div>

                    <div style={{ display: 'flex', gap: '6px' }} onClick={(e) => e.stopPropagation()}>
                      {alert.status === 'OPEN' && (
                        <button 
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleUpdateStatus(alert.id, 'INVESTIGATING')}
                        >
                          Triage
                        </button>
                      )}
                      <button 
                        className="btn btn-danger btn-sm"
                        onClick={() => setEscalateModalAlert(alert)}
                        title="Promote Alert to Official Incident Case"
                      >
                        <Flame size={12} /> Escalate Case
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Alert Details Panel */}
        {selectedAlert && (
          <div className="cyber-card" style={{ position: 'sticky', top: '20px', height: 'fit-content' }}>
            <div className="card-header">
              <div className="card-title">
                <ShieldAlert size={18} color="var(--color-cyan)" />
                <span>ALERT INVESTIGATION WORKBENCH</span>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedAlert(null)}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className={`badge badge-${selectedAlert.severity}`} style={{ fontSize: '12px', padding: '4px 10px' }}>
                  {selectedAlert.severity} PRIORITY
                </span>
                <span className={`badge badge-${selectedAlert.status}`}>{selectedAlert.status}</span>
              </div>

              <div style={{ fontSize: '15px', fontWeight: '700', color: '#fff' }}>
                {selectedAlert.alert_type}
              </div>

              <div style={{ background: '#0a0e17', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '13px' }}>
                {selectedAlert.description}
              </div>

              {/* MITRE ATT&CK Mapping Card */}
              <div style={{ background: 'rgba(255, 123, 0, 0.08)', border: '1px solid rgba(255, 123, 0, 0.3)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-high)', fontWeight: '700', fontSize: '12px', marginBottom: '6px' }}>
                  <Crosshair size={14} /> MITRE ATT&CK FRAMEWORK MAPPING
                </div>
                <div style={{ fontSize: '13px', color: '#fff' }}>
                  <strong>Technique:</strong> {selectedAlert.mitre_technique_id} - {selectedAlert.mitre_technique_name || 'Brute Force'}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  <strong>Tactic:</strong> {selectedAlert.mitre_tactic || 'Credential Access'}
                </div>
              </div>

              {/* Key Indicators Table */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                <div style={{ background: 'rgba(19, 29, 51, 0.5)', padding: '10px', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text-muted)' }}>Source / Attacker IP</div>
                  <div className="mono" style={{ fontWeight: '600', color: '#fff', marginTop: '2px' }}>{selectedAlert.source_ip || 'N/A'}</div>
                  {selectedAlert.source_ip && (
                    <button 
                      className="btn btn-secondary btn-sm" 
                      style={{ marginTop: '6px', width: '100%', fontSize: '11px', padding: '2px 6px' }}
                      onClick={() => onSelectThreatIntel(selectedAlert.source_ip)}
                    >
                      <ExternalLink size={10} /> Threat Intel Check
                    </button>
                  )}
                </div>

                <div style={{ background: 'rgba(19, 29, 51, 0.5)', padding: '10px', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text-muted)' }}>Target Host / Account</div>
                  <div className="mono" style={{ fontWeight: '600', color: '#fff', marginTop: '2px' }}>
                    {selectedAlert.username || selectedAlert.destination_ip || 'N/A'}
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '6px' }}>
                    Threat Score: <strong style={{ color: 'var(--color-critical)' }}>{selectedAlert.threat_score || 85}%</strong>
                  </div>
                </div>
              </div>

              {/* Raw Evidence Payload */}
              {selectedAlert.raw_event_data && (
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>Event Log Context:</div>
                  <pre style={{ background: '#0a0e17', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', color: '#38bdf8', fontSize: '11.5px', overflowX: 'auto' }}>
                    {selectedAlert.raw_event_data}
                  </pre>
                </div>
              )}

              {/* Triage Actions */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>ANALYST DISPOSITION</div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button 
                    className="btn btn-secondary btn-sm" 
                    style={{ flex: 1 }}
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'RESOLVED')}
                  >
                    <CheckCircle size={12} color="var(--color-success)" /> Resolve
                  </button>
                  <button 
                    className="btn btn-secondary btn-sm" 
                    style={{ flex: 1 }}
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'FALSE_POSITIVE')}
                  >
                    <XCircle size={12} color="var(--text-muted)" /> False Positive
                  </button>
                </div>
                <button 
                  className="btn btn-danger"
                  style={{ width: '100%', marginTop: '4px' }}
                  onClick={() => setEscalateModalAlert(selectedAlert)}
                >
                  <Flame size={15} /> Escalate to Incident Case
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Escalate to Incident Modal */}
      {escalateModalAlert && (
        <div className="modal-overlay" onClick={() => setEscalateModalAlert(null)}>
          <div className="modal-content" style={{ maxWidth: '540px' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Flame size={20} color="var(--color-critical)" />
                <h3 style={{ fontSize: '16px', color: '#fff' }}>Escalate Alert #{escalateModalAlert.id} to Incident</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setEscalateModalAlert(null)}>✕</button>
            </div>

            <form onSubmit={handleEscalate}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ background: 'rgba(19, 29, 51, 0.5)', padding: '12px', borderRadius: '6px', fontSize: '13px' }}>
                  <div><strong>Alert:</strong> {escalateModalAlert.alert_type} ({escalateModalAlert.rule_id})</div>
                  <div style={{ color: 'var(--text-muted)', marginTop: '4px' }}>{escalateModalAlert.description}</div>
                </div>

                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                    Assigned Lead Analyst:
                  </label>
                  <input type="text" className="form-input" defaultValue="soc_analyst" readOnly />
                </div>

                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                    Initial Triage & Investigation Notes:
                  </label>
                  <textarea 
                    className="form-textarea" 
                    rows={4}
                    placeholder="Enter initial findings, attacker IP assessment, infected host status..."
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setEscalateModalAlert(null)}>Cancel</button>
                <button type="submit" className="btn btn-danger" disabled={loadingAction}>
                  {loadingAction ? 'Escalating...' : 'Confirm Escalation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
