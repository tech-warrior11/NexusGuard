import React, { useState } from 'react';
import { Shield, Lock } from 'lucide-react';
import { api } from '../services/api';

export function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(username, password);
      localStorage.setItem('token', data.access_token);
      onLoginSuccess();
    } catch (err) {
      setError('Invalid SOC credentials or unauthorized access.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="layout" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: 'var(--bg-dark)' }}>
      <div className="card" style={{ width: '400px', padding: '40px' }}>
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <div className="logo-glow" style={{ justifyContent: 'center', margin: '0 auto 20px auto', width: '50px', height: '50px' }}>
            <Shield size={32} />
          </div>
          <h2 style={{ fontSize: '24px', fontWeight: 'bold' }}>NEXUS<span style={{ color: 'var(--color-cyan)' }}>GUARD</span></h2>
          <div className="text-muted" style={{ fontSize: '14px', marginTop: '5px' }}>Restricted Area. Authorized Personnel Only.</div>
        </div>

        {error && (
          <div className="alert alert-error" style={{ marginBottom: '20px' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label>Analyst ID (Username)</label>
            <input 
              type="text" 
              className="form-control" 
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="e.g., soc_analyst"
              required 
            />
          </div>
          <div className="form-group" style={{ marginTop: '20px' }}>
            <label>Access Key (Password)</label>
            <input 
              type="password" 
              className="form-control" 
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              required 
            />
          </div>
          
          <button 
            type="submit" 
            className="btn btn-primary" 
            style={{ width: '100%', marginTop: '30px', display: 'flex', justifyContent: 'center', gap: '8px' }}
            disabled={loading}
          >
            <Lock size={16} />
            {loading ? 'Authenticating...' : 'Secure Login'}
          </button>
        </form>
      </div>
    </div>
  );
}
