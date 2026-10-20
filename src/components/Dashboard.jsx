import React from 'react';
import Icon from './Icon.jsx';
import { categoryClass, formatNumber, formatTimestamp, verdictClass } from '../lib/format.js';

function Kpi({ label, value, hint, tone, icon }) {
  return (
    <div className={`kpi${tone ? ` kpi-${tone}` : ''}`}>
      <div className="kpi-top">
        <span>{label}</span>
        {icon ? <Icon name={icon} size={15} /> : null}
      </div>
      <strong>{value}</strong>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

export default function Dashboard({ dataset, incidents, onOpen, onReview, onRefresh, mode }) {
  const counts = dataset?.counts || {};
  const summary = dataset?.triage_summary || {};
  const categories = Object.entries(counts.alert_categories || {});
  const maxCategory = Math.max(1, ...categories.map(([, value]) => value));
  const untriaged = incidents.filter((incident) => !incident.triage?.verdict).length;
  const recent = incidents.slice(0, 6);

  return (
    <section className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Detection · Triage · Timeline</p>
          <h1>Overview</h1>
          <p className="page-sub">
            Rule-based incidents from CIC-IDS2017 network flows, with AI triage proposals awaiting
            analyst review.
          </p>
        </div>
        <div className="page-actions">
          {mode !== 'live' ? (
            <span className="chip chip-muted">
              <Icon name="database" size={14} />
              {mode === 'mock' ? 'Mock model' : 'Bundled preview'}
            </span>
          ) : null}
          <button type="button" className="btn btn-quiet" onClick={onRefresh}>
            <Icon name="refresh" size={15} />
            Refresh
          </button>
        </div>
      </header>

      <div className="kpi-row">
        <Kpi label="Incidents" value={formatNumber(counts.incidents)} hint="Rule-grouped cases" icon="incidents" />
        <Kpi
          label="Likely Attack"
          value={formatNumber(summary['Likely Attack'] || 0)}
          hint={untriaged ? `${untriaged} not triaged` : 'All triaged'}
          tone="attack"
          icon="alert"
        />
        <Kpi
          label="Likely Benign"
          value={formatNumber(summary['Likely Benign'] || 0)}
          hint="Needs confirmation on attack categories"
          tone="benign"
          icon="checkCircle"
        />
        <Kpi
          label="Needs Review"
          value={formatNumber(summary['Needs Review'] || 0)}
          hint="Insufficient or rejected evidence"
          tone="review"
          icon="info"
        />
        <Kpi
          label="Pending analyst decision"
          value={formatNumber(summary.pending_confirmation || 0)}
          hint="Proposals not yet accepted"
          icon="user"
        />
      </div>

      <div className="dash-grid">
        <section className="panel" aria-label="Recent incidents">
          <div className="panel-head">
            <div>
              <h2>Recent incidents</h2>
              <p>One row per one-minute aggregation window</p>
            </div>
            <button type="button" className="btn btn-quiet" onClick={onReview}>
              Open list
              <Icon name="arrow" size={15} />
            </button>
          </div>

          {recent.length === 0 ? (
            <div className="empty">
              <Icon name="incidents" size={22} />
              <p>No incidents in the current dataset.</p>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table table-compact">
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Category</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Window</th>
                    <th className="num">Flows</th>
                    <th>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((incident) => (
                    <tr
                      key={incident.incident_id}
                      className="row-clickable"
                      onClick={() => onOpen(incident.incident_id)}
                      tabIndex={0}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          onOpen(incident.incident_id);
                        }
                      }}
                    >
                      <td className="mono">{incident.incident_id}</td>
                      <td>
                        <span className={`tag tag-${categoryClass(incident.category)}`}>
                          {incident.category}
                        </span>
                      </td>
                      <td className="mono">{incident.source_ip}</td>
                      <td className="mono">{incident.destination_ip}</td>
                      <td className="mono muted">{formatTimestamp(incident.window_start)}</td>
                      <td className="num">{formatNumber(incident.flow_count)}</td>
                      <td>
                        {incident.triage?.verdict ? (
                          <span className={`verdict verdict-${verdictClass(incident.triage.verdict)}`}>
                            {incident.triage.verdict}
                          </span>
                        ) : (
                          <span className="chip chip-muted">Not triaged</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div className="stack">
          <section className="panel" aria-label="Alert categories">
            <div className="panel-head">
              <div>
                <h2>Alert categories</h2>
                <p>Detection rule matches</p>
              </div>
            </div>
            <div className="bar-list">
              {categories.map(([category, value]) => (
                <div className="bar-row" key={category}>
                  <span className={`tag tag-${categoryClass(category)}`}>{category}</span>
                  <div className="bar-track">
                    <span
                      className={`bar bar-${categoryClass(category)}`}
                      style={{ width: `${Math.max(6, (value / maxCategory) * 100)}%` }}
                    />
                  </div>
                  <span className="num">{formatNumber(value)}</span>
                </div>
              ))}
              {categories.length === 0 ? <p className="muted small">No alert data.</p> : null}
            </div>
          </section>

          <section className="panel" aria-label="Dataset scope">
            <div className="panel-head">
              <div>
                <h2>Detection scope</h2>
                <p>{dataset?.provenance?.dataset || 'Dataset'}</p>
              </div>
            </div>
            <dl className="facts">
              <div>
                <dt>Flows represented</dt>
                <dd>{formatNumber(counts.represented_flows)}</dd>
              </div>
              <div>
                <dt>Sampled flow records</dt>
                <dd>{formatNumber(counts.sampled_flows)}</dd>
              </div>
              <div>
                <dt>Windows scanned</dt>
                <dd>{formatNumber(dataset?.evaluation?.groups_scanned)}</dd>
              </div>
              <div>
                <dt>Rule matches</dt>
                <dd>{formatNumber(dataset?.evaluation?.rule_matches)}</dd>
              </div>
            </dl>
            <p className="panel-note">
              Incident totals count grouped cases. Alert counts are detection records and are never
              mixed into the incident totals.
            </p>
          </section>
        </div>
      </div>
    </section>
  );
}
