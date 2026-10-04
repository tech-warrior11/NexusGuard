import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Terminal, 
  Filter, 
  PlusCircle, 
  RefreshCw, 
  ChevronLeft, 
  ChevronRight, 
  Eye, 
  FileText 
} from 'lucide-react';
import { api } from '../services/api';

export function LogExplorerTab({ onOpenRawInjector }) {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);

  // Filters
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [page, setPage] = useState(0);
  const limit = 25;

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await api.getLogs({
        source: sourceFilter || undefined,
        status: statusFilter || undefined,
        source_ip: ipFilter || undefined,
        search: searchQuery || undefined,
        limit,
        offset: page * limit
      });
      setLogs(res.logs || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error('Failed to fetch logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [sourceFilter, statusFilter, ipFilter, page]);

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(0);
    fetchLogs();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header & Actions */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={20} color="var(--color-cyan)" />
            SIEM LOG EXPLORER & STREAM
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Centralized security event ingestion across Linux servers, Windows Event Viewer, and Network sniffers.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button 
            className="btn btn-primary"
            onClick={onOpenRawInjector}
          >
            <PlusCircle size={15} /> Inject Security Log
          </button>
          <button 
            className="btn btn-secondary"
            onClick={fetchLogs}
            disabled={loading}
          >
            <RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="cyber-card" style={{ padding: '14px 18px' }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Keyword Search */}
          <div style={{ flex: '1 1 240px', position: 'relative' }}>
            <input 
              type="text"
              className="form-input"
              placeholder="Full-text search (e.g. root, 4625, mimikatz, powershell)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ paddingLeft: '34px' }}
            />
            <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '11px' }} />
          </div>

          {/* Source Select */}
          <div style={{ width: '150px' }}>
            <select 
              className="form-select"
              value={sourceFilter}
              onChange={(e) => { setSourceFilter(e.target.value); setPage(0); }}
            >
              <option value="">All Sources</option>
              <option value="linux">🐧 Linux (auth.log)</option>
              <option value="windows">🪟 Windows (Event Viewer)</option>
              <option value="network">🌐 Network (Wireshark)</option>
              <option value="endpoint">💻 Endpoint (EDR)</option>
            </select>
          </div>

          {/* Status Select */}
          <div style={{ width: '140px' }}>
            <select 
              className="form-select"
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
            >
              <option value="">All Statuses</option>
              <option value="failed">❌ Failed / Denied</option>
              <option value="success">✅ Success</option>
              <option value="detected">🚨 Detected</option>
              <option value="blocked">🛡️ Blocked</option>
            </select>
          </div>

          {/* Source IP Filter */}
          <div style={{ width: '160px' }}>
            <input 
              type="text"
              className="form-input"
              placeholder="Source IP..."
              value={ipFilter}
              onChange={(e) => { setIpFilter(e.target.value); setPage(0); }}
            />
          </div>

          <button type="submit" className="btn btn-secondary">
            <Filter size={14} /> Filter
          </button>
        </form>
      </div>

      {/* Logs Table */}
      <div className="cyber-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="cyber-table-container">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Source</th>
                <th>Event Type</th>
                <th>Source IP</th>
                <th>Target / Dest</th>
                <th>Status</th>
                <th>Message</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    No security logs matching the current filter.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    <td className="mono" style={{ fontSize: '11.5px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}
                    </td>
                    <td>
                      <span className="badge" style={{ background: '#1e293b', color: '#94a3b8' }}>
                        {log.source === 'linux' ? '🐧 Linux' : (log.source === 'windows' ? '🪟 Windows' : '🌐 Network')}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: '12px', color: 'var(--color-cyan)' }}>
                      {log.event_type}
                    </td>
                    <td className="mono" style={{ fontSize: '12px', fontWeight: '600' }}>
                      {log.source_ip || '-'}
                    </td>
                    <td className="mono" style={{ fontSize: '12px' }}>
                      {log.destination_ip ? `${log.destination_ip}:${log.port || ''}` : (log.username || '-')}
                    </td>
                    <td>
                      <span className={`badge badge-${log.status === 'failed' || log.status === 'denied' ? 'CRITICAL' : (log.status === 'detected' ? 'HIGH' : 'RESOLVED')}`}>
                        {log.status}
                      </span>
                    </td>
                    <td style={{ maxWidth: '340px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '12.5px' }} title={log.message}>
                      {log.message}
                    </td>
                    <td>
                      <button 
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedLog(log)}
                        title="View Raw Log Details"
                      >
                        <Eye size={12} /> View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderTop: '1px solid var(--border-subtle)', background: 'rgba(13, 20, 36, 0.4)' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Showing <strong>{logs.length > 0 ? page * limit + 1 : 0}</strong> - <strong>{Math.min(total, (page + 1) * limit)}</strong> of <strong>{total}</strong> logs
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button 
              className="btn btn-secondary btn-sm" 
              disabled={page === 0}
              onClick={() => setPage(p => Math.max(0, p - 1))}
            >
              <ChevronLeft size={14} /> Prev
            </button>
            <button 
              className="btn btn-secondary btn-sm" 
              disabled={(page + 1) * limit >= total}
              onClick={() => setPage(p => p + 1)}
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Log Details Modal */}
      {selectedLog && (
        <div className="modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FileText size={18} color="var(--color-cyan)" />
                <h3 style={{ fontSize: '16px', color: '#fff' }}>Security Log Record #{selectedLog.id}</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedLog(null)}>✕</button>
            </div>

            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'rgba(19, 29, 51, 0.5)', padding: '14px', borderRadius: '8px' }}>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Timestamp:</span> <div className="mono" style={{ fontSize: '13px' }}>{selectedLog.timestamp}</div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Source Platform:</span> <div>{selectedLog.source}</div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Event Type:</span> <div className="mono" style={{ color: 'var(--color-cyan)' }}>{selectedLog.event_type}</div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Status:</span> <div><span className={`badge badge-${selectedLog.status === 'failed' ? 'CRITICAL' : 'RESOLVED'}`}>{selectedLog.status}</span></div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Source IP:</span> <div className="mono">{selectedLog.source_ip || 'N/A'}</div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Destination:</span> <div className="mono">{selectedLog.destination_ip ? `${selectedLog.destination_ip}:${selectedLog.port || ''}` : 'N/A'}</div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>User / Identity:</span> <div>{selectedLog.username || 'N/A'}</div></div>
                <div><span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Action:</span> <div className="mono">{selectedLog.action || 'N/A'}</div></div>
              </div>

              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>Message:</div>
                <div style={{ background: '#0a0e17', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '13px' }}>
                  {selectedLog.message}
                </div>
              </div>

              {selectedLog.raw_payload && (
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>Raw Payload / Event XML:</div>
                  <pre style={{ background: '#0a0e17', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', color: '#38bdf8', fontSize: '12px', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
                    {selectedLog.raw_payload}
                  </pre>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedLog(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
