import React, { useState } from 'react';
import Icon from './Icon.jsx';

const items = [
  { label: 'Home', icon: 'home', page: 'dashboard' },
  { section: 'INVESTIGATION' },
  { label: 'Cases', icon: 'network', page: 'cases' },
  { label: 'Alerts', icon: 'bell', page: 'alerts' },
];

export default function Sidebar({ page, open, collapsed, onSelect, onLogout, username }) {
  const [accountOpen, setAccountOpen] = useState(false);
  return <aside className={`sidebar${open ? ' open' : ''}${collapsed ? ' collapsed' : ''}`} aria-label="Main navigation">
    <nav>{items.map((item, index) => item.section
      ? <div className="nav-section" key={item.section}>{item.section}</div>
      : <button key={`${item.label}-${index}`} className={`nav-item${(page === item.page || (page === 'review' && item.page === 'cases')) ? ' active' : ''}`} aria-current={page === item.page || (page === 'review' && item.page === 'cases') ? 'page' : undefined} title={collapsed ? item.label : undefined} onClick={() => onSelect(item.page)}><Icon name={item.icon} size={20} /><span className="nav-label">{item.label}</span></button>
    )}</nav>
    <div className="sidebar-account">
      {accountOpen && <div className="account-menu"><span>Signed in as {username}</span><button type="button" onClick={onLogout}>Sign out</button></div>}
      <button className="sidebar-profile" type="button" onClick={() => setAccountOpen((value) => !value)} aria-expanded={accountOpen} aria-label="Account menu"><span className="profile-avatar">{username.slice(0, 1).toUpperCase()}</span><span className="profile-copy"><strong>{username}</strong><small>SOC Desk workspace</small></span><Icon name="user" size={18} solid /></button>
    </div>
  </aside>;
}
