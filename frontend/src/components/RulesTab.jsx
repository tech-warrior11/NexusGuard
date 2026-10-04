import React, { useState, useEffect } from 'react';
import { 
  Sliders, 
  ShieldCheck, 
  Check, 
  X, 
  ToggleLeft, 
  ToggleRight, 
  RefreshCw, 
  Flame, 
  Crosshair 
} from 'lucide-react';
import { api } from '../services/api';

export function RulesTab() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [togglingId, setTogglingId] = useState(null);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await api.getRules();
      setRules(res.rules || []);
    } catch (err) {
      console.error('Failed to fetch rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (ruleId) => {
    setTogglingId(ruleId);
    try {
      const updated = await api.toggleRule(ruleId);
      setRules(prev => prev.map(r => r.rule_id === ruleId ? updated : r));
    } catch (err) {
      alert('Failed to toggle rule: ' + err.message);
    } finally {
      setTogglingId(null);
    }
  };

  const activeCount = rules.filter(r => r.enabled).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sliders size={20} color="var(--color-cyan)" />
            DETECTION ENGINE & RULE MANAGEMENT
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Real-time correlation rules mapped to MITRE ATT&CK techniques with configurable thresholds and time windows.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="mono" style={{ fontSize: '13px', background: 'rgba(19, 29, 51, 0.6)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            Active Rules: <strong style={{ color: 'var(--color-success)' }}>{activeCount}</strong> / {rules.length}
          </div>
          <button className="btn btn-secondary" onClick={fetchRules} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="cyber-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="cyber-table-container">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Name & Description</th>
                <th>Type</th>
                <th>Severity</th>
                <th>MITRE ATT&CK</th>
                <th>Threshold</th>
                <th>Triggers</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.rule_id} style={{ opacity: rule.enabled ? 1 : 0.55 }}>
                  <td className="mono" style={{ fontSize: '12px', fontWeight: '700', color: 'var(--color-cyan)' }}>
                    {rule.rule_id}
                  </td>
                  <td style={{ maxWidth: '300px' }}>
                    <div style={{ fontWeight: '600', color: '#fff', fontSize: '13px', marginBottom: '2px' }}>
                      {rule.name}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {rule.description}
                    </div>
                  </td>
                  <td>
                    <span className="badge" style={{ background: '#1e293b', color: 'var(--text-secondary)' }}>
                      {rule.rule_type}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${rule.severity}`}>{rule.severity}</span>
                  </td>
                  <td>
                    {rule.mitre_technique_id ? (
                      <div>
                        <span className="mono" style={{ fontSize: '11.5px', color: 'var(--color-high)', fontWeight: '600' }}>
                          {rule.mitre_technique_id}
                        </span>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{rule.mitre_tactic}</div>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>-</span>
                    )}
                  </td>
                  <td className="mono" style={{ fontSize: '12px' }}>
                    {rule.threshold} hits / {rule.time_window}s
                  </td>
                  <td>
                    <span className="mono" style={{ fontWeight: '700', color: rule.trigger_count > 0 ? 'var(--color-critical)' : 'var(--text-muted)' }}>
                      {rule.trigger_count || 0}
                    </span>
                  </td>
                  <td>
                    <button 
                      className={`btn btn-sm ${rule.enabled ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ padding: '4px 10px', fontSize: '11px' }}
                      onClick={() => handleToggle(rule.rule_id)}
                      disabled={togglingId === rule.rule_id}
                    >
                      {rule.enabled ? <><ToggleRight size={14} /> ACTIVE</> : <><ToggleLeft size={14} /> DISABLED</>}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
