import React from 'react';
import Icon from './Icon.jsx';
import { titleForMode } from '../lib/format.js';

const NAV = [
  { id: 'dashboard', label: 'Overview', icon: 'overview' },
  { id: 'review', label: 'Incidents', icon: 'incidents' },
  { id: 'audit', label: 'Audit log', icon: 'audit' },
];

export default function Sidebar({ page, open, onSelect, status, incidentCount }) {
  const mode = status?.mode || 'offline';
  const ai = status?.ai;

  return (
    <aside className={`sidebar${open ? ' open' : ''}`} aria-label="Main navigation">
      <div className="brand">
        <span className="brand-mark">
          <Icon name="shield" size={20} />
        </span>
        <span className="brand-text">
          <strong>SOC Triage</strong>
          <small>CIC-IDS2017</small>
        </span>
      </div>

      <nav className="nav">
        {NAV.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`nav-item${page === item.id ? ' active' : ''}`}
            aria-current={page === item.id ? 'page' : undefined}
            onClick={() => onSelect(item.id)}
          >
            <Icon name={item.icon} size={17} />
            <span>{item.label}</span>
            {item.id === 'review' && incidentCount ? (
              <span className="nav-count">{incidentCount}</span>
            ) : null}
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="env-card">
          <span className={`env-dot env-${mode}`} aria-hidden="true" />
          <div>
            <strong>{titleForMode(mode)}</strong>
            <span>{ai ? `${ai.provider} · ${ai.model}` : 'API not reachable'}</span>
          </div>
        </div>
        <p className="sidebar-note">
          Verdicts are proposals. Closure, dismissal and severity changes remain analyst actions.
        </p>
      </div>
    </aside>
  );
}
