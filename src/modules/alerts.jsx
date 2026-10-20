import React, { useMemo, useState } from 'react';
import Icon from '../components/Icon.jsx';
import {
  categoryClass,
  formatNumber,
  formatTimestamp,
  verdictClass,
} from '../lib/format.js';

const VERDICT_FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'untriaged', label: 'Untriaged' },
  { id: 'Likely Attack', label: 'Attack' },
  { id: 'Likely Benign', label: 'Benign' },
  { id: 'Needs Review', label: 'Review' },
];

const SORTS = [
  { id: 'newest', label: 'Newest first' },
  { id: 'oldest', label: 'Oldest first' },
  { id: 'flows', label: 'Most flows' },
  { id: 'category', label: 'Category' },
];

export default function Alerts({ incidents, selectedId, onSelect }) {
  const [query, setQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [sort, setSort] = useState('newest');

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = incidents.filter((incident) => {
      if (verdictFilter === 'untriaged') {
        if (incident.triage?.verdict) return false;
      } else if (verdictFilter !== 'all' && incident.triage?.verdict !== verdictFilter) {
        return false;
      }
      if (!needle) return true;
      return [
        incident.incident_id,
        incident.category,
        incident.source_ip,
        incident.destination_ip,
      ]
        .join(' ')
        .toLowerCase()
        .includes(needle);
    });

    const sorted = [...filtered];
    sorted.sort((a, b) => {
      if (sort === 'flows') return (b.flow_count || 0) - (a.flow_count || 0);
      if (sort === 'category') return String(a.category).localeCompare(String(b.category));
      const left = a.window_start || '';
      const right = b.window_start || '';
      return sort === 'oldest' ? left.localeCompare(right) : right.localeCompare(left);
    });
    return sorted;
  }, [incidents, query, verdictFilter, sort]);

  return (
    <section className="list-pane" aria-label="Incident list">
      <div className="list-toolbar">
        <div className="search">
          <Icon name="search" size={15} />
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search id, category or IP"
            aria-label="Search incidents"
          />
        </div>
        <label className="select">
          <Icon name="sort" size={14} />
          <select value={sort} onChange={(event) => setSort(event.target.value)} aria-label="Sort incidents">
            {SORTS.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="filter-row" role="group" aria-label="Filter by verdict">
        {VERDICT_FILTERS.map((filter) => (
          <button
            key={filter.id}
            type="button"
            className={`chip chip-toggle${verdictFilter === filter.id ? ' is-active' : ''}`}
            aria-pressed={verdictFilter === filter.id}
            onClick={() => setVerdictFilter(filter.id)}
          >
            {filter.label}
          </button>
        ))}
      </div>

      <div className="list-meta">
        <span>
          {visible.length} of {incidents.length} incidents
        </span>
        {selectedId ? <span className="mono muted">{selectedId}</span> : null}
      </div>

      <ul className="incident-list">
        {visible.map((incident) => {
          const verdict = incident.triage?.verdict;
          const decision = incident.triage?.decision;
          return (
            <li key={incident.incident_id}>
              <button
                type="button"
                className={`incident-row${selectedId === incident.incident_id ? ' is-selected' : ''}`}
                aria-current={selectedId === incident.incident_id ? 'true' : undefined}
                onClick={() => onSelect(incident.incident_id)}
              >
                <span className="row-top">
                  <span className={`tag tag-${categoryClass(incident.category)}`}>
                    {incident.category}
                  </span>
                  {verdict ? (
                    <span className={`verdict verdict-${verdictClass(verdict)}`}>
                      {verdict}
                      {decision === 'confirmed' ? <Icon name="check" size={11} /> : null}
                    </span>
                  ) : (
                    <span className="chip chip-muted">Not triaged</span>
                  )}
                  <time className="mono row-time">{formatTimestamp(incident.window_start)}</time>
                </span>
                <span className="row-id mono">{incident.incident_id}</span>
                <span className="row-route mono">
                  {incident.source_ip} <Icon name="arrow" size={12} /> {incident.destination_ip}
                  <em>{formatNumber(incident.flow_count)} flows</em>
                </span>
              </button>
            </li>
          );
        })}
        {visible.length === 0 ? (
          <li className="list-empty">
            <Icon name="search" size={20} />
            <p>No incidents match the current filters.</p>
          </li>
        ) : null}
      </ul>
    </section>
  );
}
