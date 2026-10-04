import React from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  AlertOctagon, 
  Flame, 
  Globe, 
  CheckCircle2, 
  ArrowRight, 
  Clock, 
  Crosshair, 
  ExternalLink 
} from 'lucide-react';

export function DashboardTab({ 
  metrics, 
  alerts, 
  onSelectAlert, 
  onNavigateTab, 
  onEscalateAlert, 
  onQuickSimulate 
}) {
  const critAlerts = alerts.filter(a => a.severity === 'CRITICAL' && a.status === 'OPEN');
  const openAlerts = alerts.filter(a => a.status === 'OPEN').slice(0, 8);

  return (
    <div>
      {/* Top Banner / Defcon Warning if critical alerts exist */}
      {critAlerts.length > 0 && (
        <div style={{
          background: 'linear-gradient(90deg, rgba(255, 0, 85, 0.2), rgba(13, 20, 36, 0.9))',
          border: '1px solid var(--color-critical)',
          borderRadius: 'var(--radius-md)',
          padding: '12px 18px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          boxShadow: '0 0 20px rgba(255, 0, 85, 0.25)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <AlertOctagon color="var(--color-critical)" size={24} />
            <div>
              <div style={{ fontWeight: '700', color: '#fff', fontSize: '14px' }}>
                DEFCON-1 ALERT: {critAlerts.length} Active Critical Security Threat{critAlerts.length > 1 ? 's' : ''} Detected!
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                Immediate analyst triage required. Triggered rules: {critAlerts.map(a => a.rule_id).join(', ')}
              </div>
            </div>
          </div>
          <button 
            className="btn btn-danger btn-sm"
            onClick={() => onNavigateTab('alerts')}
          >
            Triage Alerts <ArrowRight size={14} />
          </button>
        </div>
      )}

      {/* Metrics Row */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-header">
            <span>Total Logs Ingested</span>
            <Terminal size={18} color="var(--color-cyan)" />
          </div>
          <div className="metric-value">{metrics?.total_logs_ingested?.toLocaleString() || '0'}</div>
          <div className="metric-sub">
            <span style={{ color: 'var(--color-success)' }}>● Real-Time</span> across Linux/Win/Net
          </div>
        </div>

        <div className="metric-card critical">
          <div className="metric-header">
            <span>Open Security Alerts</span>
            <ShieldAlert size={18} color="var(--color-critical)" />
          </div>
          <div className="metric-value" style={{ color: 'var(--color-critical)' }}>
            {metrics?.active_open_alerts || '0'}
          </div>
          <div className="metric-sub">
            <span style={{ color: 'var(--color-critical)' }}>{metrics?.critical_alerts || 0} Critical</span> | {metrics?.severity_breakdown?.high || 0} High
          </div>
        </div>

        <div className="metric-card high">
          <div className="metric-header">
            <span>Active Incidents</span>
            <Flame size={18} color="var(--color-high)" />
          </div>
          <div className="metric-value" style={{ color: 'var(--color-high)' }}>
            {metrics?.open_incidents || '0'}
          </div>
          <div className="metric-sub">
            <span>Under Analyst Investigation</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span>Threat Index Score</span>
            <Crosshair size={18} color="var(--color-cyan)" />
          </div>
          <div className="metric-value">
            {metrics?.threat_index_score || '12.0'}<span style={{ fontSize: '16px', color: 'var(--text-muted)' }}>/100</span>
          </div>
          <div className="metric-sub">
            <span>Aggregated Risk Gauge</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Live Alert Stream & Analytics Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '20px', marginBottom: '24px' }}>
        
        {/* Live Security Alerts Feed */}
        <div className="cyber-card">
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={18} color="var(--color-cyan)" />
              <span>LIVE SECURITY ALERT STREAM</span>
            </div>
            <button 
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab('alerts')}
            >
              View All ({alerts.length})
            </button>
          </div>

          {openAlerts.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <CheckCircle2 size={32} color="var(--color-success)" style={{ margin: '0 auto 10px' }} />
              <div>All threat alerts triaged and cleared. System baseline normal.</div>
              <button 
                className="btn btn-primary btn-sm" 
                style={{ marginTop: '12px' }}
                onClick={() => onQuickSimulate('brute_force')}
              >
                Launch Attack Simulation Lab
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {openAlerts.map(alert => (
                <div 
                  key={alert.id}
                  style={{
                    background: 'rgba(19, 29, 51, 0.5)',
                    border: `1px solid ${alert.severity === 'CRITICAL' ? 'rgba(255, 0, 85, 0.4)' : 'var(--border-subtle)'}`,
                    borderRadius: 'var(--radius-md)',
                    padding: '12px 14px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                    transition: 'all 0.2s ease',
                    cursor: 'pointer'
                  }}
                  onClick={() => onSelectAlert(alert)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                      <span className="mono" style={{ fontSize: '11px', color: 'var(--color-cyan)' }}>{alert.rule_id}</span>
                      <span style={{ fontWeight: '600', fontSize: '13px', color: '#fff' }}>{alert.alert_type}</span>
                    </div>
                    <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {new Date(alert.timestamp).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' })}
                    </span>
                  </div>

                  <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    {alert.description}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11.5px', color: 'var(--text-muted)', paddingTop: '4px', borderTop: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <div style={{ display: 'flex', gap: '14px' }}>
                      {alert.source_ip && <span>IP: <strong className="mono" style={{ color: '#fff' }}>{alert.source_ip}</strong></span>}
                      {alert.username && <span>User: <strong style={{ color: '#fff' }}>{alert.username}</strong></span>}
                      {alert.mitre_technique_id && <span>MITRE: <strong className="mono" style={{ color: 'var(--color-high)' }}>{alert.mitre_technique_id}</strong></span>}
                    </div>
                    <span style={{ color: 'var(--color-cyan)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                      Investigate <ArrowRight size={12} />
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Top Threat Actors & MITRE ATT&CK Breakdown */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Top Threat Source IPs */}
          <div className="cyber-card">
            <div className="card-header">
              <div className="card-title">
                <Globe size={18} color="var(--color-cyan)" />
                <span>TOP THREAT SOURCE IPs</span>
              </div>
              <button 
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('threat-intel')}
              >
                Threat Intel
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {(metrics?.top_attacking_ips || []).map((ipStat, idx) => (
                <div 
                  key={idx}
                  style={{
                    background: 'rgba(19, 29, 51, 0.4)',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    border: '1px solid var(--border-subtle)'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className="mono" style={{ fontWeight: '600', color: '#fff', fontSize: '13px' }}>{ipStat.ip}</span>
                      <span className="badge" style={{ fontSize: '10px', background: '#1e293b', color: 'var(--text-secondary)' }}>{ipStat.country}</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{ipStat.isp}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span className={`badge badge-${ipStat.reputation === 'MALICIOUS' ? 'CRITICAL' : 'HIGH'}`} style={{ fontSize: '10px' }}>
                      {ipStat.threat_score}% Threat
                    </span>
                    <div className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      {ipStat.count} hits
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE ATT&CK Tactic Distribution */}
          <div className="cyber-card">
            <div className="card-header">
              <div className="card-title">
                <Crosshair size={18} color="var(--color-high)" />
                <span>MITRE ATT&CK TACTICS COVERAGE</span>
              </div>
              <button 
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab('mitre')}
              >
                Matrix View
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {(metrics?.mitre_tactics_breakdown || []).map((tactic, idx) => (
                <div key={idx}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                    <span>{tactic.tactic}</span>
                    <span className="mono" style={{ color: 'var(--color-cyan)' }}>{tactic.count} detections</span>
                  </div>
                  <div style={{ display: 'flex', gap: '1px', width: '100%', height: '8px' }}>
                    {[...Array(100)].map((_, i) => {
                      const percentage = Math.min(100, Math.max(15, tactic.count * 20));
                      const isFilled = i < percentage;
                      const barColor = idx === 0 ? 'var(--color-critical)' : (idx === 1 ? 'var(--color-high)' : 'var(--color-cyan)');
                      return (
                        <div 
                          key={i} 
                          style={{ 
                            flex: 1, 
                            height: '100%', 
                            background: isFilled ? barColor : 'rgba(255, 255, 255, 0.05)'
                          }} 
                        />
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>

      {/* Activity Timeline Bar Chart */}
      <div className="cyber-card">
        <div className="card-header">
          <div className="card-title">
            <Clock size={18} color="var(--color-cyan)" />
            <span>EVENT INGESTION & THREAT ACTIVITY TIMELINE</span>
          </div>
          <span className="mono" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Last 24 Hours Interval</span>
        </div>

        <div style={{ position: 'relative', height: '140px', padding: '10px 10px 0' }}>
          {/* SVG Mountain Wave */}
          {(metrics?.activity_timeline || []).length > 0 && (
            <svg 
              viewBox="0 0 1000 120" 
              preserveAspectRatio="none" 
              style={{ position: 'absolute', bottom: '25px', left: 0, width: '100%', height: '100px', zIndex: 1 }}
            >
              <defs>
                <linearGradient id="waveGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-cyan)" stopOpacity="0.7"/>
                  <stop offset="100%" stopColor="var(--bg-secondary)" stopOpacity="0.1"/>
                </linearGradient>
              </defs>
              <path d={(() => {
                const data = metrics.activity_timeline;
                const maxVal = Math.max(1, ...data.map(p => p.logs_count));
                let pathD = "M 0 120";
                if (data.length > 1) {
                  pathD += ` L 0 ${120 - (data[0].logs_count / maxVal) * 100}`;
                  for (let i = 1; i < data.length; i++) {
                     const prevX = ((i - 1) / (data.length - 1)) * 1000;
                     const prevY = 120 - (data[i - 1].logs_count / maxVal) * 100;
                     const currX = (i / (data.length - 1)) * 1000;
                     const currY = 120 - (data[i].logs_count / maxVal) * 100;
                     const cp1X = prevX + (currX - prevX) / 3;
                     const cp2X = currX - (currX - prevX) / 3;
                     pathD += ` C ${cp1X} ${prevY}, ${cp2X} ${currY}, ${currX} ${currY}`;
                  }
                  pathD += ` L 1000 120 Z`;
                } else if (data.length === 1) {
                  const y = 120 - (data[0].logs_count / maxVal) * 100;
                  pathD += ` L 0 ${y} L 1000 ${y} L 1000 120 Z`;
                }
                return pathD;
              })()} fill="url(#waveGradient)" stroke="var(--color-cyan)" strokeWidth="3" style={{ filter: 'drop-shadow(0px 0px 8px var(--color-cyan))' }} />
            </svg>
          )}

          {/* Labels Overlay */}
          <div style={{ position: 'relative', zIndex: 2, display: 'flex', alignItems: 'flex-end', height: '100%', justifyContent: 'space-between', padding: '0 10px' }}>
            {(metrics?.activity_timeline || []).map((pt, idx) => {
              const maxVal = Math.max(1, ...(metrics?.activity_timeline || []).map(p => p.logs_count));
              const pointHeight = 120 - (pt.logs_count / maxVal) * 100;
              return (
                <div key={idx} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%', justifyContent: 'flex-end' }}>
                  <div className="mono" style={{ 
                    fontSize: '11px', 
                    color: '#fff', 
                    fontWeight: '700',
                    marginBottom: 'auto',
                    marginTop: `${pointHeight - 20}px`,
                    textShadow: '0 2px 4px rgba(0,0,0,0.8), 0 0 5px var(--color-cyan)'
                  }}>
                    {pt.logs_count}
                  </div>
                  <div className="mono" style={{ fontSize: '11px', color: 'var(--color-cyan)', marginTop: '8px' }}>
                    {pt.time_label}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
