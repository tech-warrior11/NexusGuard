import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Globe, 
  ShieldAlert, 
  CheckCircle2, 
  AlertOctagon, 
  Server, 
  Crosshair, 
  FileWarning, 
  ExternalLink 
} from 'lucide-react';
import { api } from '../services/api';

export function ThreatIntelTab({ initialIndicator }) {
  const [indicator, setIndicator] = useState(initialIndicator || '185.220.101.5');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const sampleIOCs = [
    { label: 'Tor Exit C2 IP', value: '185.220.101.5' },
    { label: 'Hydra Brute Force IP', value: '194.26.29.112' },
    { label: 'Nmap Scanner IP', value: '45.33.32.156' },
    { label: 'WannaCry SHA256', value: '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c' },
    { label: 'Mimikatz SHA256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { label: 'Clean Internal IP', value: '10.0.0.15' },
  ];

  const handleLookup = async (target) => {
    const query = (target || indicator).trim();
    if (!query) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.lookupThreatIntel(query);
      setResult(res);
    } catch (err) {
      setError(err.message || 'Threat intelligence query failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialIndicator) {
      setIndicator(initialIndicator);
      handleLookup(initialIndicator);
    } else {
      handleLookup('185.220.101.5');
    }
  }, [initialIndicator]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Search size={20} color="var(--color-cyan)" />
          THREAT INTELLIGENCE & IOC REPUTATION HUB
        </h2>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Real-time threat enrichment integrating AbuseIPDB confidence scores, VirusTotal multi-engine verdicts, and MITRE correlations.
        </div>
      </div>

      {/* Query Bar */}
      <div className="cyber-card" style={{ padding: '16px 20px' }}>
        <form 
          onSubmit={(e) => { e.preventDefault(); handleLookup(); }} 
          style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}
        >
          <div style={{ flex: '1 1 350px', position: 'relative' }}>
            <input 
              type="text"
              className="form-input"
              placeholder="Enter IP address, Domain, MD5, or SHA256 hash..."
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              style={{ paddingLeft: '36px', fontFamily: 'var(--font-mono)' }}
            />
            <Search size={16} color="var(--color-cyan)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Querying Feeds...' : 'Investigate IOC'}
          </button>
        </form>

        {/* Quick Sample Chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginTop: '14px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>DEMO IOCs:</span>
          {sampleIOCs.map((ioc, idx) => (
            <button
              key={idx}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: '11px', padding: '3px 8px' }}
              onClick={() => { setIndicator(ioc.value); handleLookup(ioc.value); }}
            >
              {ioc.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ background: 'rgba(255, 0, 85, 0.15)', border: '1px solid var(--color-critical)', padding: '14px', borderRadius: '8px', color: '#ff4d79', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {/* Intel Result Card */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Main Verdict Summary Card */}
          <div className="cyber-card" style={{ borderLeft: `5px solid ${result.threat_level === 'CRITICAL' ? 'var(--color-critical)' : (result.threat_level === 'HIGH' ? 'var(--color-high)' : 'var(--color-success)')}` }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                  <span className={`badge badge-${result.threat_level}`} style={{ fontSize: '13px', padding: '4px 12px' }}>
                    {result.threat_level} RISK
                  </span>
                  <span className="mono" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Type: {result.indicator_type.toUpperCase()}
                  </span>
                </div>
                <h3 className="mono" style={{ fontSize: '20px', color: '#fff', wordBreak: 'break-all' }}>
                  {result.indicator}
                </h3>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px', maxWidth: '700px' }}>
                  {result.description}
                </p>
              </div>

              <div style={{ textAlign: 'right', background: 'rgba(19, 29, 51, 0.6)', padding: '14px 20px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Confidence</div>
                <div className="mono" style={{ fontSize: '30px', fontWeight: '800', color: result.overall_confidence > 70 ? 'var(--color-critical)' : (result.overall_confidence > 30 ? 'var(--color-high)' : 'var(--color-success)') }}>
                  {result.overall_confidence}%
                </div>
              </div>
            </div>
          </div>

          {/* Dual Feed Comparison: AbuseIPDB & VirusTotal */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            
            {/* AbuseIPDB Card */}
            <div className="cyber-card">
              <div className="card-header">
                <div className="card-title">
                  <Globe size={18} color="var(--color-high)" />
                  <span>AbuseIPDB REPUTATION FEED</span>
                </div>
                {result.abuseipdb?.is_tor && (
                  <span className="badge badge-CRITICAL">TOR EXIT NODE</span>
                )}
              </div>

              {result.abuseipdb ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Abuse Confidence Score:</span>
                    <strong className="mono" style={{ color: result.abuseipdb.abuse_confidence_score > 50 ? 'var(--color-critical)' : 'var(--color-success)' }}>
                      {result.abuseipdb.abuse_confidence_score}%
                    </strong>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Country / Location:</span>
                    <span>{result.abuseipdb.country_name || result.abuseipdb.country_code || 'N/A'} ({result.abuseipdb.country_code})</span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>ISP / Hosting Provider:</span>
                    <span>{result.abuseipdb.isp || 'N/A'}</span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Total Abuse Reports:</span>
                    <strong className="mono">{result.abuseipdb.total_reports} reports</strong>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Usage Classification:</span>
                    <span>{result.abuseipdb.usage_type || 'Datacenter / Hosting'}</span>
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                  AbuseIPDB reputation query not applicable for file hashes.
                </div>
              )}
            </div>

            {/* VirusTotal Card */}
            <div className="cyber-card">
              <div className="card-header">
                <div className="card-title">
                  <ShieldAlert size={18} color="var(--color-critical)" />
                  <span>VirusTotal MULTI-ENGINE VERDICT</span>
                </div>
                <span className="mono" style={{ fontSize: '12px', color: 'var(--color-critical)' }}>
                  {result.virustotal?.detection_ratio || '0/70'}
                </span>
              </div>

              {result.virustotal ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Detection Score:</span>
                    <strong className="mono" style={{ color: result.virustotal.malicious_votes > 0 ? 'var(--color-critical)' : 'var(--color-success)' }}>
                      {result.virustotal.malicious_votes} / {result.virustotal.total_engines} Engines Flagged Malicious
                    </strong>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(45, 65, 105, 0.2)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Threat Classification:</span>
                    <span className="mono" style={{ color: 'var(--color-cyan)' }}>{result.virustotal.threat_classification || 'N/A'}</span>
                  </div>

                  <div>
                    <div style={{ color: 'var(--text-muted)', marginBottom: '6px', fontSize: '12px' }}>Leading Engine Verdicts:</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', background: '#0a0e17', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-subtle)', maxHeight: '110px', overflowY: 'auto' }}>
                      {Object.entries(result.virustotal.engine_verdicts || {}).map(([engine, verdict], idx) => (
                        <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11.5px' }}>
                          <span style={{ color: '#fff' }}>{engine}:</span>
                          <span className="mono" style={{ color: 'var(--color-critical)' }}>{verdict}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                  No VirusTotal scan record found.
                </div>
              )}
            </div>

          </div>

          {/* MITRE ATT&CK Mapping */}
          {result.mitre_technique_id && (
            <div className="cyber-card" style={{ background: 'rgba(255, 123, 0, 0.05)', borderColor: 'rgba(255, 123, 0, 0.3)' }}>
              <div className="card-title" style={{ color: 'var(--color-high)', marginBottom: '8px' }}>
                <Crosshair size={18} />
                <span>CORRELATED MITRE ATT&CK TECHNIQUE</span>
              </div>
              <div style={{ fontSize: '14px', color: '#fff' }}>
                <strong>{result.mitre_technique_id}:</strong> {result.mitre_technique_name}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
