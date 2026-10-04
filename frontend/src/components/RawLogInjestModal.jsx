import React, { useState } from 'react';
import { PlusCircle, Terminal, Sparkles } from 'lucide-react';
import { api } from '../services/api';

export function RawLogInjestModal({ onClose, onSuccess }) {
  const [format, setFormat] = useState('linux_auth');
  const [content, setContent] = useState('Sep 29 14:22:01 server sshd[1234]: Failed password for root from 194.26.29.112 port 49212 ssh2');
  const [loading, setLoading] = useState(false);

  const formatSamples = {
    linux_auth: 'Sep 29 14:22:01 server sshd[1234]: Failed password for root from 194.26.29.112 port 49212 ssh2',
    windows_event: `Event ID: 4625
Logon Type: 10
Account Name: Administrator
Source Network Address: 194.26.29.112
Status: 0xC000006D (An account failed to log on)`,
    pcap_stream: '14:32:01.123456 IP 45.33.32.156.54122 > 10.0.0.15.80: Flags [S], seq 0, win 65535, length 0'
  };

  const handleFormatChange = (newFormat) => {
    setFormat(newFormat);
    setContent(formatSamples[newFormat] || '');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!content.trim()) return;
    setLoading(true);
    try {
      await api.ingestRawLog({
        format,
        content
      });
      alert('Security event log normalized and ingested successfully! Detection engine triggered.');
      onSuccess();
      onClose();
    } catch (err) {
      alert('Ingestion error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '650px' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <PlusCircle size={20} color="var(--color-cyan)" />
            <h3 style={{ fontSize: '16px', color: '#fff' }}>Inject Raw Security Event Log</h3>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onClose}>✕</button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                Log Platform Format:
              </label>
              <select 
                className="form-select"
                value={format}
                onChange={(e) => handleFormatChange(e.target.value)}
              >
                <option value="linux_auth">🐧 Linux auth.log / secure / sshd</option>
                <option value="windows_event">🪟 Windows Security Event (4624 / 4625 / 4688)</option>
                <option value="pcap_stream">🌐 Wireshark / Network Packet Text</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                Raw Unstructured Log Content:
              </label>
              <textarea 
                className="form-textarea"
                rows={7}
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Paste raw log string or XML snippet here..."
                required
              />
            </div>

            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', background: 'rgba(19, 29, 51, 0.4)', padding: '10px', borderRadius: '6px' }}>
              💡 NexusGuard log parser will automatically extract Timestamp, Source IP, Destination Port, Username, and trigger correlation detection rules in real-time.
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <Sparkles size={14} /> {loading ? 'Ingesting...' : 'Normalize & Ingest Log'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
