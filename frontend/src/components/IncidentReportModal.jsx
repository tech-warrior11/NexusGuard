import React, { useState, useEffect } from 'react';
import { Download, FileText, Copy, Check, Printer } from 'lucide-react';
import { api } from '../services/api';

export function IncidentReportModal({ incidentId, onClose }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState('preview'); // 'preview' | 'markdown'

  useEffect(() => {
    if (!incidentId) return;
    const fetchReport = async () => {
      setLoading(true);
      try {
        const res = await api.getIncidentReport(incidentId);
        setReport(res);
      } catch (err) {
        alert('Failed to generate report: ' + err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [incidentId]);

  const handleCopy = () => {
    if (!report) return;
    navigator.clipboard.writeText(report.markdown_report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!report) return;
    const blob = new Blob([report.markdown_report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Incident_Report_${report.incident_number}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '900px', height: '85vh' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={18} color="var(--color-cyan)" />
            <h3 style={{ fontSize: '16px', color: '#fff' }}>
              Official SOC Incident Report: {report?.incident_number || 'Loading...'}
            </h3>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button 
              className={`btn btn-sm ${viewMode === 'preview' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setViewMode('preview')}
            >
              Formatted Preview
            </button>
            <button 
              className={`btn btn-sm ${viewMode === 'markdown' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setViewMode('markdown')}
            >
              Markdown Source
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onClose}>✕</button>
          </div>
        </div>

        <div className="modal-body" style={{ overflowY: 'auto' }}>
          {loading ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Compiling incident report from NexusGuard detection engine...
            </div>
          ) : report ? (
            viewMode === 'preview' ? (
              <div 
                style={{ background: '#0a0e17', padding: '24px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}
                dangerouslySetInnerHTML={{ __html: report.html_report }} 
              />
            ) : (
              <textarea 
                className="form-textarea"
                rows={20}
                value={report.markdown_report}
                readOnly
                style={{ width: '100%', height: '100%', minHeight: '400px', fontSize: '12px' }}
              />
            )
          ) : null}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={handleCopy} disabled={!report}>
            <Copy size={14} /> {copied ? 'Report Copied!' : 'Copy Markdown'}
          </button>
          <button className="btn btn-primary" onClick={handleDownload} disabled={!report}>
            <Download size={14} /> Download (.md)
          </button>
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
