import React, { useState } from 'react';
import { Cpu, Terminal, ShieldAlert, Sparkles, Network } from 'lucide-react';
import { api } from '../services/api';

export function PcapInspectorTab() {
  const [pcapText, setPcapText] = useState(`14:32:01.123456 IP 45.33.32.156.54122 > 10.0.0.15.80: Flags [S], seq 0, win 65535, length 0
14:32:01.124500 IP 45.33.32.156.54123 > 10.0.0.15.443: Flags [S], seq 0, win 65535, length 0
14:32:01.125600 IP 45.33.32.156.54124 > 10.0.0.15.22: Flags [S], seq 0, win 65535, length 0
14:32:01.126700 IP 45.33.32.156.54125 > 10.0.0.15.3389: Flags [S], seq 0, win 65535, length 0
14:32:05.987654 IP 185.220.101.5.443 > 10.0.0.20.51222: Flags [P.], length 256 (C2_BEACON_HEARTBEAT)
14:32:08.112233 IP 10.0.0.45.49811 > 198.51.100.23.4444: Flags [P.], length 1024 (SUSPICIOUS_REVERSE_SHELL)`);

  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleInspect = async () => {
    if (!pcapText) return;
    setLoading(true);
    try {
      const res = await api.inspectPCAP(pcapText);
      setAnalysis(res);
    } catch (err) {
      alert('PCAP analysis failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Cpu size={20} color="var(--color-cyan)" />
          WIRESHARK / PCAP NETWORK TRAFFIC INSPECTOR
        </h2>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Analyze raw Wireshark text packet logs, identify TCP SYN stealth port scans, reverse shell ports, and C2 beacons.
        </div>
      </div>

      {/* Input Box */}
      <div className="cyber-card">
        <div className="card-header">
          <div className="card-title">
            <Terminal size={16} color="var(--color-cyan)" />
            <span>RAW PACKET STREAM / WIRESHARK TEXT DUMP</span>
          </div>
          <button 
            className="btn btn-primary btn-sm"
            onClick={handleInspect}
            disabled={loading}
          >
            <Sparkles size={14} /> {loading ? 'Analyzing...' : 'Inspect Packet Stream'}
          </button>
        </div>

        <textarea 
          className="form-textarea" 
          rows={6}
          value={pcapText}
          onChange={(e) => setPcapText(e.target.value)}
          placeholder="Paste Wireshark text packet dump..."
        />
      </div>

      {/* Analysis Results */}
      {analysis && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
            <div className="metric-card">
              <div className="metric-header"><span>Packets Parsed</span></div>
              <div className="metric-value">{analysis.total_packets}</div>
            </div>
            <div className="metric-card critical">
              <div className="metric-header"><span>Suspicious Anomalies</span></div>
              <div className="metric-value" style={{ color: 'var(--color-critical)' }}>
                {analysis.suspicious_alerts_found}
              </div>
            </div>
          </div>

          {/* Packet Stream Table */}
          <div className="cyber-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="cyber-table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Destination IP:Port</th>
                    <th>Protocol</th>
                    <th>Anomalies / Flags</th>
                    <th>Packet Info</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.packets.map((pkt) => (
                    <tr key={pkt.packet_num}>
                      <td className="mono">{pkt.packet_num}</td>
                      <td className="mono" style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>{pkt.timestamp}</td>
                      <td className="mono" style={{ fontWeight: '600' }}>{pkt.src_ip}</td>
                      <td className="mono">{pkt.dst_ip}:{pkt.dst_port || '-'}</td>
                      <td>
                        <span className="badge" style={{ background: '#1e293b', color: 'var(--color-cyan)' }}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td>
                        {pkt.suspicious_flags.length > 0 ? (
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {pkt.suspicious_flags.map((flg, idx) => (
                              <span key={idx} className="badge badge-CRITICAL" style={{ fontSize: '9px' }}>
                                {flg}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Clean</span>
                        )}
                      </td>
                      <td style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>{pkt.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
