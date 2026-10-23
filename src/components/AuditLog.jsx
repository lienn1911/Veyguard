import React, { useCallback, useEffect, useState } from 'react';
import Icon from './Icon.jsx';
import { getAudit } from '../lib/api.js';
import { formatTimestamp, shortId } from '../lib/format.js';

const EVENT_LABELS = {
  'triage.started': { label: 'Investigation started', tone: 'info' },
  'triage.tool_call': { label: 'Tool call', tone: 'muted' },
  'triage.completed': { label: 'Verdict proposed', tone: 'ok' },
  'triage.rejected': { label: 'Proposal rejected by backend', tone: 'warn' },
  'triage.error': { label: 'Investigation failed', tone: 'error' },
  'analyst.decision': { label: 'Analyst decision', tone: 'ok' },
  'ANALYST_DECISION': { label: 'Investigation step reviewed', tone: 'ok' },
  'CASE_NOTE_DRAFTED': { label: 'Case note drafted', tone: 'info' },
  'ANALYST_NOTE_ADDED': { label: 'Analyst note added', tone: 'info' },
  'INVESTIGATION_STEP_COMPLETED': { label: 'Approved step completed', tone: 'ok' },
  'CASE_ASSIGNED': { label: 'Case assigned', tone: 'info' },
  'CASE_RECORD_SAVED': { label: 'Case summary saved', tone: 'ok' },
  'CASE_RESOLVED': {label: 'Case resolved', tone: 'ok'},
};

function eventDetail(entry) {
  const payload = entry.payload || {};
  switch (entry.event) {
    case 'triage.started':
      return `${payload.provider} · ${payload.model} · ${payload.category || ''}`;
    case 'triage.tool_call':
      return `${payload.tool} · ${payload.ok ? 'ok' : payload.error_code || 'failed'}${payload.blocked ? ' · blocked' : ''}`;
    case 'triage.completed':
      return `${payload.verdict} · ${(payload.evidence_ids || []).length} evidence ids${
        payload.requires_confirmation ? ' · needs confirmation' : ''
      }`;
    case 'triage.rejected':
      return (payload.issues || []).slice(0, 2).join(' ');
    case 'triage.error':
      return `${payload.code}: ${payload.message}`;
    case 'analyst.decision':
      return `${payload.decision}${payload.note ? ` — ${payload.note}` : ''}`;
    case 'CASE_RECORD_SAVED':
      return `${payload.case_summary || ''} ${payload.ai_summary ? `AI: ${payload.ai_summary}` : 'No live AI summary.'} ${payload.approved_checks} approved, ${payload.rejected_checks} rejected`;
    case 'CASE_RESOLVED':
      return `Resolved by ${payload.analyst_id || entry.actor} · ${payload.reason || 'No reason recorded'}`;
  default:
      return '';
  }
}

export default function AuditLog({ mode, refreshToken }) {
  const [state, setState] = useState({ status: 'idle', entries: [], verification: null, error: null });
  const [searchQuery, setSearchQuery] = useState('');
  const [eventFilter, setEventFilter] = useState('all');
  const [actorFilter, setActorFilter] = useState('all');
  const [dateSort, setDateSort] = useState('newest');
  const load = useCallback(async () => {
    if (mode === 'offline') {
      setState({ status: 'offline', entries: [], verification: null, error: null });
      return;
    }
    setState((prev) => ({ ...prev, status: 'loading' }));
    try {
      const payload = await getAudit(200);
      setState({
        status: 'ready',
        entries: payload.entries || [],
        verification: payload.verification || null,
        error: null,
      });
    } catch (error) {
      setState({ status: 'error', entries: [], verification: null, error: error.message });
    }
  }, [mode]);

  useEffect(() => {
    load();
  }, [load, refreshToken]);

  const verified = state.verification?.ok;

  const eventTypes = [...new Set(
    state.entries.map((entry) => entry.event).filter(Boolean)
  )].sort();

  const actors = [...new Set(
    state.entries.map((entry) => entry.actor).filter(Boolean)
  )].sort();

  const filteredEntries = state.entries
    .filter((entry) => {
      const text = [
        entry.incident_id,
        entry.event_id,
        entry.event,
        entry.actor,
        EVENT_LABELS[entry.event]?.label,
        eventDetail(entry)
      ].filter(Boolean).join(' ').toLowerCase();

      const matchesSearch = text.includes(
        searchQuery.trim().toLowerCase()
      );

      const matchesEvent =
        eventFilter === 'all' ||
        entry.event === eventFilter;

      const matchesActor =
        actorFilter === 'all' ||
        entry.actor === actorFilter;

      return matchesSearch && matchesEvent && matchesActor;
    })
    .sort((a, b) => {
      // Audit sequence gives us a stable event order.
      const aSeq = Number(a.seq) || 0;
      const bSeq = Number(b.seq) || 0;

      return dateSort === 'newest'
        ? bSeq - aSeq
        : aSeq - bSeq;
    });


  return (
    <section className="page audit-log-page">
      <header className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="page-sub">
            Recorded AI investigations, analyst decisions, approvals and case notes. Each entry is hash-chained so edits are detectable.
          </p>
        </div>
        <div className="page-actions">
          {state.status === 'ready' ? (
            <span className={`chip ${verified ? 'chip-ok' : 'chip-warn'}`}>
              <Icon name={verified ? 'shield' : 'alert'} size={13} />
              {verified ? `Chain verified · ${state.verification.checked} records` : 'Chain check failed'}
            </span>
          ) : null}
          <button type="button" className="btn btn-quiet" onClick={load}>
            <Icon name="refresh" size={15} />
            Refresh
          </button>
        </div>
      </header>

      {mode === 'offline' ? (
        <div className="panel notice-panel">
          <Icon name="database" size={18} />
          <div>
            <strong>The API is offline.</strong>
            <p>
              Audit records live in the backend, so there is nothing to show from the bundled
              preview. This page never fabricates audit entries from browser state.
            </p>
          </div>
        </div>
      ) : null}

      {state.status === 'error' ? (
        <div className="panel notice-panel error">
          <Icon name="alert" size={18} />
          <div>
            <strong>Could not load the audit log.</strong>
            <p>{state.error}</p>
          </div>
        </div>
      ) : null}

      {state.status === 'ready' ? (
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Events</h2>
              <p>AI and analyst actions share one append-only audit trail.</p>
            </div>
            <span className="chip chip-muted">{state.entries.length} latest</span>
          </div>

          <div className="audit-filters">
            <input
              type="search"
              placeholder="Search case ID, event, or analyst..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search audit events"
            />

            <select
              value={eventFilter}
              onChange={(e) => setEventFilter(e.target.value)}
              aria-label="Filter by event type"
            >
              <option value="all">All Event Types</option>
              {eventTypes.map((type) => (
                <option key={type} value={type}>
                  {EVENT_LABELS[type]?.label || type}
                </option>
              ))}
            </select>

            <select
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
              aria-label="Filter by actor"
            >
              <option value="all">All Actors</option>
              {actors.map((actor) => (
                <option key={actor} value={actor}>
                  {actor}
                </option>
              ))}
            </select>

            <select
              value={dateSort}
              onChange={(e) => setDateSort(e.target.value)}
              aria-label="Sort audit events"
            >
              <option value="newest">Newest First</option>
              <option value="oldest">Oldest First</option>
            </select>

            <div className="audit-filter-bottom">
              <span>
                Showing {filteredEntries.length} of {state.entries.length} loaded events
              </span>

              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setEventFilter('all');
                  setActorFilter('all');
                  setDateSort('newest');
                }}
              >
                Clear filters
              </button>
            </div>
          </div>

          {state.entries.length === 0 ? (
            <div className="empty">
              <Icon name="audit" size={20} />
              <p>No audit events yet. Run an AI triage investigation to populate the trail.</p>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th className="num">#</th>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Incident</th>
                    <th>Actor</th>
                    <th>Detail</th>
                    <th>Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEntries.map((entry) => {
                    const meta = EVENT_LABELS[entry.event] || { label: entry.event, tone: 'muted' };
                    return (
                      <tr key={entry.event_id || entry.seq}>
                        <td className="num muted">{entry.seq}</td>
                        <td className="mono muted">{formatTimestamp(entry.ts)}</td>
                        <td>
                          <span className={`event event-${meta.tone}`}>{meta.label}</span>
                        </td>
                        <td className="mono">{entry.incident_id || '—'}</td>
                        <td className="muted small">{entry.actor}</td>
                        <td className="muted small detail-cell">{eventDetail(entry)}</td>
                        <td className="mono muted small" title={entry.hash}>
                          {shortId(entry.hash, 6)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filteredEntries.length === 0 && (
                <p className="audit-no-results">
                  No audit events match your filters.
                </p>
              )}
            </div>
          )}
        </section>
      ) : null}
    </section>
  );
}
