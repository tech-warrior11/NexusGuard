import React, { useState, useEffect } from 'react';
import { X, User, Lock, CheckCircle, LogOut, Shield } from 'lucide-react';
import { api } from '../services/api';

export function UserProfileModal({ onClose }) {
  const [view, setView] = useState('profile'); // 'profile' or 'change_password'
  
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  // Parse user info from JWT
  const [userInfo, setUserInfo] = useState({ username: 'Analyst', role: 'SOC Analyst' });

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        setUserInfo({
          username: payload.sub || 'Analyst',
          role: payload.role || 'SOC Analyst'
        });
      } catch (e) {
        console.error("Could not parse token", e);
      }
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    window.location.reload();
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }
    
    setLoading(true);
    try {
      await api.updateCredentials(newPassword);
      setSuccess(true);
      setTimeout(() => {
        onClose();
      }, 2000);
    } catch (err) {
      setError(err.message || 'Failed to update credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ width: '450px', background: 'var(--bg-card)' }}>
        <div className="modal-header">
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
            {view === 'profile' ? <User size={20} color="var(--color-cyan)" /> : <Lock size={20} color="var(--color-cyan)" />} 
            {view === 'profile' ? 'User Profile' : 'Update Credentials'}
          </h2>
          <button className="btn-close" onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer' }}><X size={20} /></button>
        </div>
        
        <div className="modal-body" style={{ padding: '20px 0 0 0' }}>
          {view === 'profile' ? (
            <div className="profile-view">
              <div style={{ textAlign: 'center', padding: '20px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <div style={{ 
                  width: '80px', height: '80px', borderRadius: '50%', background: 'rgba(0, 240, 255, 0.1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 15px auto',
                  border: '2px solid var(--color-cyan)'
                }}>
                  <Shield size={40} color="var(--color-cyan)" />
                </div>
                <h3 style={{ margin: '0 0 5px 0', fontSize: '24px' }}>{userInfo.username}</h3>
                <span className="badge" style={{ background: 'var(--color-primary)', color: '#fff' }}>{userInfo.role}</span>
              </div>
              
              <div style={{ padding: '20px' }}>
                <button 
                  className="btn btn-secondary" 
                  style={{ width: '100%', marginBottom: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}
                  onClick={() => setView('change_password')}
                >
                  <Lock size={16} /> Change Password
                </button>
                <button 
                  className="btn" 
                  style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px', background: 'rgba(255, 68, 68, 0.1)', color: 'var(--color-danger)', border: '1px solid rgba(255, 68, 68, 0.3)' }}
                  onClick={handleLogout}
                >
                  <LogOut size={16} /> Logout Securely
                </button>
              </div>
            </div>
          ) : (
            // Change Password View
            success ? (
              <div style={{ textAlign: 'center', padding: '30px 0' }}>
                <CheckCircle size={48} color="var(--color-success)" style={{ margin: '0 auto 15px auto' }} />
                <h3>Password Updated!</h3>
                <p className="text-muted" style={{ marginTop: '10px' }}>Your new credentials have been securely saved.</p>
              </div>
            ) : (
              <form onSubmit={handlePasswordSubmit} style={{ padding: '0 20px 20px 20px' }}>
                {error && <div className="alert alert-error" style={{ marginBottom: '15px' }}>{error}</div>}
                
                <div className="form-group" style={{ marginBottom: '15px' }}>
                  <label style={{ display: 'block', marginBottom: '5px', color: 'var(--text-muted)' }}>New Password</label>
                  <input 
                    type="password" 
                    className="form-control" 
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    placeholder="Enter new password"
                    required 
                  />
                </div>
                
                <div className="form-group" style={{ marginBottom: '25px' }}>
                  <label style={{ display: 'block', marginBottom: '5px', color: 'var(--text-muted)' }}>Confirm Password</label>
                  <input 
                    type="password" 
                    className="form-control" 
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    placeholder="Confirm new password"
                    required 
                  />
                </div>
                
                <div style={{ display: 'flex', gap: '10px', justifyContent: 'space-between' }}>
                  <button type="button" className="btn btn-secondary" onClick={() => { setView('profile'); setError(''); }}>Back to Profile</button>
                  <button type="submit" className="btn btn-primary" disabled={loading}>
                    {loading ? 'Updating...' : 'Save Password'}
                  </button>
                </div>
              </form>
            )
          )}
        </div>
      </div>
    </div>
  );
}
