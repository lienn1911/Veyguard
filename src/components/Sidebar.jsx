import React from 'react';
import Icon from './Icon.jsx';

export default function Sidebar({ page, open, collapsed, onToggle, onSelect }) {
  return (
    <aside
      className={`sidebar${open ? ' open' : ''}${collapsed ? ' collapsed' : ''}`}
      aria-label="Main navigation"
    >
      <div className="brand">
        <span className="brand-icon">
          <Icon name="shield" size={24} />
        </span>
        <strong className="brand-name">SOC Triage</strong>
      </div>

      <nav>
        <button
          className={`nav-item${page === 'dashboard' ? ' active' : ''}`}
          aria-label="Dashboard"
          aria-current={page === 'dashboard' ? 'page' : undefined}
          title={collapsed ? 'Dashboard' : undefined}
          onClick={() => onSelect('dashboard')}
        >
          <Icon name="grid" />
          <span className="nav-label">Dashboard</span>
        </button>
        <button
          className={`nav-item${page === 'review' || page === 'cases' ? ' active' : ''}`}
          aria-label="Cases"
          aria-current={page === 'review' || page === 'cases' ? 'page' : undefined}
          title={collapsed ? 'Cases' : undefined}
          onClick={() => onSelect('cases')}
        >
          <span className="nav-glyph" aria-hidden="true">◎</span>
          <span className="nav-label">Cases</span>
        </button>
        <button className={`nav-item${page === 'alerts' ? ' active' : ''}`} aria-label="Alerts" aria-current={page === 'alerts' ? 'page' : undefined} title={collapsed ? 'Alerts' : undefined} onClick={() => onSelect('alerts')}>
          <span className="nav-glyph" aria-hidden="true">♧</span>
          <span className="nav-label">Alerts</span>
        </button>
      </nav>
      <button className="sidebar-toggle" type="button" onClick={onToggle} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'} aria-expanded={!collapsed} title={collapsed ? 'Expand navigation' : 'Collapse navigation'}><span aria-hidden="true">{collapsed ? '›' : '‹'}</span><span className="sidebar-toggle-label">{collapsed ? 'Expand' : 'Collapse'}</span></button>
    </aside>
  );
}
