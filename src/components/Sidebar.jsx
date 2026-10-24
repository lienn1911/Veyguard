import React, { useState } from 'react';
import { createPortal } from 'react-dom';
import Icon from './Icon.jsx';
import { apiFetch } from '../apiFetch.js';

const items = [
  { label: 'Home', icon: 'home', page: 'dashboard' },
  { label: 'Investigations', icon: 'network', page: 'cases' },
  { label: 'Audit log', icon: 'audit', page: 'audit' },
  { label: 'AI settings', icon: 'lock', page: 'settings' },
];

export default function Sidebar({ page, open, collapsed, onSelect, onLogout, logoutError, onPasswordChanged, username }) {
  const [accountOpen, setAccountOpen] = useState(false);
  const [changeOpen, setChangeOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  function closeChange() {
    if (saving) return;
    setChangeOpen(false);
    setCurrentPassword('');
    setNewPassword('');
    setConfirmation('');
    setError('');
  }

  async function changePassword(event) {
    event.preventDefault();
    if (newPassword !== confirmation) { setError('New passwords do not match.'); return; }
    setSaving(true);
    setError('');
    try {
      const response = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Could not change password.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmation('');
      onPasswordChanged();
    } catch (failure) {
      setError(failure.message || 'Could not reach the local API.');
    } finally {
      setSaving(false);
    }
  }

  return <><aside className={`sidebar${open ? ' open' : ''}${collapsed ? ' collapsed' : ''}`} aria-label="Main navigation">
    <nav>{items.map((item, index) => item.section
      ? <div className="nav-section" key={item.section}>{item.section}</div>
      : <button key={`${item.label}-${index}`} className={`nav-item${(page === item.page || (page === 'review' && item.page === 'cases')) ? ' active' : ''}`} aria-current={page === item.page || (page === 'review' && item.page === 'cases') ? 'page' : undefined} title={collapsed ? item.label : undefined} onClick={() => onSelect(item.page)}><Icon name={item.icon} size={20} /><span className="nav-label">{item.label}</span></button>
    )}</nav>
    <div className="sidebar-account">
      {accountOpen && <div className="account-menu"><span>Signed in as {username}</span><button type="button" onClick={() => { setAccountOpen(false); setChangeOpen(true); }}>Change password</button><button type="button" onClick={onLogout}>Sign out</button>{logoutError && <span role="alert">{logoutError}</span>}</div>}
      <button className="sidebar-profile" type="button" onClick={() => setAccountOpen((value) => !value)} aria-expanded={accountOpen} aria-label="Account menu"><span className="profile-avatar">{username.slice(0, 1).toUpperCase()}</span><span className="profile-copy"><strong>{username}</strong><small>SOC Desk workspace</small></span><Icon name="user" size={18} solid /></button>
    </div>
  </aside>{changeOpen && createPortal(<div className="password-dialog-backdrop" onMouseDown={closeChange}><div className="password-dialog" role="dialog" aria-modal="true" aria-labelledby="change-password-title" onMouseDown={(event) => event.stopPropagation()} onKeyDown={(event) => { if (event.key === 'Escape') closeChange(); }}><form onSubmit={changePassword}><header><h2 id="change-password-title">Change password</h2><button type="button" onClick={closeChange} aria-label="Close change password"><Icon name="close" size={18} /></button></header><label>Current password<input autoFocus type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} maxLength={1024} required /></label><label>New password<input type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} minLength={15} maxLength={128} required /></label><label>Confirm new password<input type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} minLength={15} maxLength={128} required /></label><p className="password-dialog-hint">Use 15–128 characters and a unique passphrase. Spaces and Unicode are welcome.</p>{error && <p className="password-dialog-error" role="alert">{error}</p>}<footer><button type="button" onClick={closeChange} disabled={saving}>Cancel</button><button type="submit" disabled={saving || !currentPassword || !newPassword || !confirmation}>{saving ? 'Updating…' : 'Update password'}</button></footer></form></div></div>, document.body)}</>;
}
