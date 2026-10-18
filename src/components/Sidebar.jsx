import React from 'react';
import Icon from './Icon.jsx';

export default function Sidebar({ page, open, onSelect }) {
  return (
    <aside
      className={`sidebar${open ? ' open' : ''}`}
      aria-label="Main navigation"
    >
      <div className="brand">
        <span className="brand-icon">
          <Icon name="shield" size={24} />
        </span>
        <strong>SOC Triage</strong>
      </div>

      <nav>
        <button
          className={`nav-item${page === 'dashboard' ? ' active' : ''}`}
          aria-current={page === 'dashboard' ? 'page' : undefined}
          onClick={() => onSelect('dashboard')}
        >
          <Icon name="grid" />
          Dashboard
        </button>
        <button
          className={`nav-item${page === 'review' ? ' active' : ''}`}
          aria-current={page === 'review' ? 'page' : undefined}
          onClick={() => onSelect('review')}
        >
          <span className="nav-glyph" aria-hidden="true">◎</span>
          Alert Review
        </button>
      </nav>
    </aside>
  );
}
