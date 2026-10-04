import React, { useState, useEffect } from 'react';
import { Network, Crosshair, ShieldAlert, CheckCircle, Info } from 'lucide-react';
import { api } from '../services/api';

export function MitreMatrixTab() {
  const [matrixData, setMatrixData] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchMatrix = async () => {
      setLoading(true);
      try {
        const res = await api.getMitreMatrix();
        setMatrixData(res);
      } catch (err) {
        console.error('Failed to load MITRE matrix:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchMatrix();
  }, []);

  const tacticsList = matrixData?.tactics ? Object.entries(matrixData.tactics) : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Network size={20} color="var(--color-cyan)" />
          MITRE ATT&CK® ENTERPRISE MATRIX NAVIGATOR
        </h2>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Enterprise adversary tactics and techniques actively covered by NexusGuard detection engineering rules.
        </div>
      </div>

      {/* MITRE Matrix Horizontal Board */}
      <div className="cyber-card" style={{ padding: '16px', overflowX: 'auto' }}>
        <div style={{ display: 'flex', gap: '14px', minWidth: '950px' }}>
          {tacticsList.map(([tacticName, techniques], idx) => (
            <div 
              key={idx} 
              style={{
                flex: '1 0 200px',
                background: 'rgba(19, 29, 51, 0.4)',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
                overflow: 'hidden'
              }}
            >
              {/* Tactic Column Header */}
              <div style={{
                background: 'rgba(13, 20, 36, 0.9)',
                padding: '10px 12px',
                borderBottom: '2px solid var(--color-cyan)',
                fontSize: '12px',
                fontWeight: '700',
                color: '#fff',
                textTransform: 'uppercase',
                letterSpacing: '0.04em'
              }}>
                {tacticName}
                <div style={{ fontSize: '10px', color: 'var(--color-cyan)', marginTop: '2px' }}>
                  {techniques.length} Active Rules
                </div>
              </div>

              {/* Techniques List */}
              <div style={{ padding: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {techniques.map((tech, tIdx) => {
                  const isSelected = selectedTechnique?.id === tech.id;
                  return (
                    <div
                      key={tIdx}
                      style={{
                        background: isSelected ? 'rgba(0, 243, 255, 0.15)' : 'rgba(7, 11, 20, 0.7)',
                        border: `1px solid ${isSelected ? 'var(--color-cyan)' : 'var(--border-subtle)'}`,
                        borderRadius: '6px',
                        padding: '8px 10px',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease'
                      }}
                      onClick={() => {
                        const kbInfo = matrixData?.knowledge_base?.[tech.id] || {};
                        setSelectedTechnique({ ...tech, ...kbInfo });
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span className="mono" style={{ fontSize: '11px', fontWeight: '700', color: 'var(--color-high)' }}>
                          {tech.id}
                        </span>
                        <span className={`badge badge-${tech.severity}`} style={{ fontSize: '9px', padding: '1px 5px' }}>
                          {tech.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: '11.5px', color: '#fff', fontWeight: '600', lineHeight: '1.3' }}>
                        {tech.name}
                      </div>
                      <div style={{ fontSize: '10px', color: 'var(--color-cyan)', marginTop: '4px' }}>
                        🛡️ {tech.detected_by}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Technique Detail Drawer */}
      {selectedTechnique && (
        <div className="cyber-card" style={{ borderLeft: '4px solid var(--color-high)' }}>
          <div className="card-header">
            <div className="card-title">
              <Crosshair size={18} color="var(--color-high)" />
              <span>TECHNIQUE DETAILS: {selectedTechnique.id} - {selectedTechnique.name}</span>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={() => setSelectedTechnique(null)}>✕</button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
            <div>
              <strong style={{ color: 'var(--text-muted)' }}>Description:</strong>
              <p style={{ marginTop: '4px', color: 'var(--text-secondary)' }}>
                {selectedTechnique.description || 'Adversary technique monitored by NexusGuard.'}
              </p>
            </div>

            <div>
              <strong style={{ color: 'var(--color-success)' }}>Detection & Mitigation Strategies:</strong>
              <p style={{ marginTop: '4px', color: 'var(--text-secondary)' }}>
                {selectedTechnique.mitigation || 'Implement host-based logging, network segmentation, and credential hardening.'}
              </p>
            </div>

            <div style={{ display: 'flex', gap: '20px', paddingTop: '8px', borderTop: '1px solid rgba(45, 65, 105, 0.2)' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Covered By Rule:</span> <span className="mono" style={{ color: 'var(--color-cyan)', fontWeight: '700' }}>{selectedTechnique.detected_by}</span></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Severity Level:</span> <span className={`badge badge-${selectedTechnique.severity}`}>{selectedTechnique.severity}</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
