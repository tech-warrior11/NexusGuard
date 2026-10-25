import React, { useState } from 'react';
import { X, Shield, CheckCircle, RefreshCcw, Sparkles } from 'lucide-react';

export function UserProfileModal({ onClose, onResetData }) {
  const [resetDone, setResetDone] = useState(false);

  const handleReset = () => {
    if (onResetData) onResetData();
    setResetDone(true);
    setTimeout(() => {
      setResetDone(false);
      onClose();
    }, 1200);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ width: '450px', background: 'var(--bg-card)' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0, fontSize: '18px' }}>
            <Shield size={20} color="var(--color-cyan)" />
            Active Operator Profile
          </h2>
          <button className="btn-close" onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>
        
        <div className="modal-body" style={{ padding: '20px 0 0 0' }}>
          <div className="profile-view">
            <div style={{ textAlign: 'center', padding: '20px 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div style={{ 
                width: '80px', height: '80px', borderRadius: '50%', background: 'rgba(0, 240, 255, 0.1)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 15px auto',
                border: '2px solid var(--color-cyan)',
                boxShadow: '0 0 20px rgba(0, 240, 255, 0.25)'
              }}>
                <Shield size={40} color="var(--color-cyan)" />
              </div>
              <h3 style={{ margin: '0 0 5px 0', fontSize: '22px', color: '#fff' }}>soc_commander</h3>
              <span className="badge" style={{ background: 'var(--color-primary)', color: '#fff', fontSize: '12px' }}>
                Lead SOC Incident Commander
              </span>
              <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--color-success)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                <CheckCircle size={14} /> Unrestricted Full Platform Access
              </div>
            </div>
            
            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ background: 'rgba(19, 29, 51, 0.4)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span>Security Clearance:</span>
                  <strong style={{ color: 'var(--color-cyan)' }}>LEVEL-4 (TOP SECRET)</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span>Interactive Mode:</span>
                  <strong style={{ color: 'var(--color-success)' }}>Live Preview (Open Access)</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Authentication Barrier:</span>
                  <strong style={{ color: '#fff' }}>Disabled / Public Access</strong>
                </div>
              </div>

              {resetDone ? (
                <div style={{ textAlign: 'center', color: 'var(--color-success)', padding: '10px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                  <CheckCircle size={16} /> Telemetry & Alerts Reset!
                </div>
              ) : (
                <button 
                  className="btn btn-secondary" 
                  style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                  onClick={handleReset}
                >
                  <RefreshCcw size={15} /> Reset Demo Session Data
                </button>
              )}

              <button 
                className="btn btn-primary" 
                style={{ width: '100%' }}
                onClick={onClose}
              >
                Return to SOC Dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
