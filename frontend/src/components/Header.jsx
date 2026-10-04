import React, { useState, useEffect } from 'react';
import { Shield, Radio, Terminal, Bell, Activity, RefreshCw, User } from 'lucide-react';

export function Header({ metrics, onRefresh, isRefreshing, onQuickSimulate, isLiveStreaming, onOpenProfile }) {
  const [time, setTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const threatLevel = metrics?.threat_level || 'DEFCON-3 (ELEVATED GUARD)';
  let defconClass = 'ELEVATED';
  if (threatLevel.includes('CRITICAL') || threatLevel.includes('DEFCON-1')) defconClass = 'CRITICAL';
  else if (threatLevel.includes('HIGH') || threatLevel.includes('DEFCON-2')) defconClass = 'HIGH';
  else if (threatLevel.includes('NORMAL') || threatLevel.includes('DEFCON-4')) defconClass = 'NORMAL';

  return (
    <header className="top-header">
      <div className="header-brand">
        <div className="logo-glow">
          <Shield size={22} />
        </div>
        <div>
          <div className="brand-title">NEXUS<span style={{ color: 'var(--color-cyan)' }}>GUARD</span></div>
          <div className="brand-subtitle">THREAT DETECTION & SIEM PLATFORM</div>
        </div>
      </div>

      <div className="header-actions">
        {/* DEFCON Level Badge */}
        <div className={`defcon-badge ${defconClass}`}>
          <Activity size={14} />
          <span>{threatLevel}</span>
        </div>

        {/* Live Streaming Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)' }}>
          <div className={`status-dot ${isLiveStreaming ? '' : 'red'}`} />
          <span className="mono" style={{ fontSize: '11px' }}>{isLiveStreaming ? 'LIVE SIEM BUS' : 'OFFLINE'}</span>
        </div>

        {/* Clock */}
        <div className="mono" style={{ fontSize: '12px', color: 'var(--text-muted)', background: 'rgba(19, 29, 51, 0.6)', padding: '5px 10px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          {time}
        </div>

        {/* Live Streaming Indicator */}

        <button 
          onClick={onRefresh} 
          className="btn btn-secondary btn-sm"
          title="Refresh SOC Data"
          disabled={isRefreshing}
        >
          <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} />
        </button>

        {/* User Profile */}
        <button 
          onClick={onOpenProfile} 
          className="btn btn-secondary btn-sm"
          title="User Profile"
        >
          <User size={14} />
        </button>
      </div>
    </header>
  );
}
