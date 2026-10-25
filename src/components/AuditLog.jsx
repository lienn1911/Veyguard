import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Icon from './Icon.jsx';
import SelectField from './SelectField.jsx';
import { getAudit } from '../lib/api.js';
import { formatTimestamp } from '../lib/format.js';

const EVENT_LABELS = {
  'triage.started': { label: 'Investigation started', tone: 'info' },
  'triage.tool_call': { label: 'Tool call', tone: 'muted' },
  'triage.completed': { label: 'Verdict proposed', tone: 'ok' },
  'triage.rejected': { label: 'Proposal rejected by backend', tone: 'warn' },
  'triage.error': { label: 'Investigation failed', tone: 'error' },
  'analyst.decision': { label: 'Analyst decision', tone: 'ok' },
  ANALYST_DECISION: { label: 'Investigation step reviewed', tone: 'ok' },
  CASE_NOTE_DRAFTED: { label: 'Case note drafted', tone: 'info' },
  ANALYST_NOTE_ADDED: { label: 'Analyst note added', tone: 'info' },
  INVESTIGATION_STEP_COMPLETED: { label: 'Approved step completed', tone: 'ok' },
  CASE_ASSIGNED: { label: 'Case assigned', tone: 'info' },
  CASE_REVIEW_PRIORITY_SET: { label: 'Review priority changed', tone: 'info' },
  CASE_RECORD_SAVED: { label: 'Triage report saved', tone: 'ok' },
  CASE_RESOLVED: { label: 'Case resolved', tone: 'ok' },
};

function displayActor(actor) {
  return actor === 'system:triage-agent' ? 'Agent' : actor || 'System';
}

function eventDetail(entry) {
  const payload = entry.payload || {};
  switch (entry.event) {
    case 'CASE_REVIEW_PRIORITY_SET':
      return `${payload.previous_level} → ${payload.level || 'Rule suggestion'} · ${payload.reason}`;
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
      return `${payload.approved_checks ?? 0} steps approved · ${payload.rejected_checks ?? 0} rejected`;
    case 'CASE_RESOLVED':
      return `Resolved by ${payload.analyst_id || entry.actor} · ${payload.reason || 'No reason recorded'}`;
    default:
      return '';
  }
}

/**
 * Group a flat, ascending audit stream into per-case buckets.
 * Every case keeps its events in chronological order; the case list itself
 * is ordered by the most recent activity of each case (newest first).
 */
function groupByCase(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const key = entry.incident_id || 'UNASSIGNED';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(entry);
  }
  return [...groups.entries()]
    .map(([incidentId, events]) => {
      events.sort((a, b) => (Number(a.seq) || 0) - (Number(b.seq) || 0));
      const last = events[events.length - 1];
      const completed = [...events].reverse().find((e) => e.event === 'triage.completed');
      const decided = [...events].reverse().find((e) => e.event === 'analyst.decision');
      const runs = new Set(events.map((e) => e.payload?.run_id).filter(Boolean));
      return {
        incidentId,
        events,
        lastTs: last?.ts || '',
        runs:
          runs.size ||
          (events.some((e) => e.event === 'triage.started')
            ? events.filter((e) => e.event === 'triage.started').length
            : 0),
        verdict: completed?.payload?.verdict,
        decided: Boolean(decided),
        decidedStatus: decided?.payload?.decision,
      };
    })
    .sort((a, b) => (a.lastTs < b.lastTs ? 1 : -1));
}

function CaseGroup({ group, open, onToggle, dateSort }) {
  const latest = group.decidedStatus
    ? group.decidedStatus === 'confirmed'
      ? 'Assessment confirmed'
      : 'Assessment rejected'
    : group.verdict || 'No assessment yet';
  return (
    <>
      <tr className={`audit-group-row${open ? ' is-open' : ''}`}>
        <td colSpan={4} className="audit-group-cell">
          <button
            type="button"
            className="audit-group-toggle"
            onClick={onToggle}
            aria-expanded={open}
            aria-label={`${open ? 'Collapse' : 'Expand'} ${group.incidentId}`}
          >
            <span className="audit-case-identity">
              <strong>{group.incidentId}</strong>
              <small>
                {group.events.length} events · {latest}
              </small>
            </span>
            <time>{formatTimestamp(group.lastTs)}</time>
            <Icon name="chevronDown" size={18} className="audit-expand-chevron" />
          </button>
        </td>
      </tr>
      {open && (
        <tr className="audit-event-head">
          <th>Time</th>
          <th>Activity</th>
          <th>Performed by</th>
          <th>Result</th>
        </tr>
      )}
      {open &&
        [...group.events]
          .sort((a, b) =>
            dateSort === 'newest' ? Number(b.seq) - Number(a.seq) : Number(a.seq) - Number(b.seq),
          )
          .map((entry) => {
            const meta = EVENT_LABELS[entry.event] || { label: entry.event, tone: 'muted' };
            return (
              <tr key={entry.event_id || entry.seq} className="audit-event-row">
                <td>
                  <time>{formatTimestamp(entry.ts)}</time>
                </td>
                <td>
                  <span className={`event event-${meta.tone}`}>{meta.label}</span>
                </td>
                <td>{displayActor(entry.actor)}</td>
                <td>
                  <p className="audit-result-summary">
                    {eventDetail(entry) ||
                      entry.payload?.decision ||
                      entry.payload?.note ||
                      'Recorded'}
                  </p>
                  <details className="audit-entry-details">
                    <summary>Details</summary>
                    <dl>
                      <div>
                        <dt>Event ID</dt>
                        <dd>{entry.event_id || entry.seq}</dd>
                      </div>
                      <div>
                        <dt>Event type</dt>
                        <dd>{entry.event}</dd>
                      </div>
                      <div>
                        <dt>Integrity hash</dt>
                        <dd>{entry.hash || 'Not recorded'}</dd>
                      </div>
                    </dl>
                    <pre>{JSON.stringify(entry.payload || {}, null, 2)}</pre>
                  </details>
                </td>
              </tr>
            );
          })}
    </>
  );
}

export default function AuditLog({ mode, refreshToken }) {
  const [state, setState] = useState({
    status: 'idle',
    entries: [],
    verification: null,
    error: null,
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [eventFilter, setEventFilter] = useState('all');
  const [actorFilter, setActorFilter] = useState('all');
  const [dateSort, setDateSort] = useState('newest');
  const [openCases, setOpenCases] = useState(() => new Set());
  const load = useCallback(async () => {
    if (mode === 'offline') {
      setState({ status: 'offline', entries: [], verification: null, error: null });
      return;
    }
    setState((prev) => ({ ...prev, status: 'loading' }));
    try {
      const payload = await getAudit(500);
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

  const groups = useMemo(() => groupByCase(state.entries), [state.entries]);

  const toggleCase = useCallback((incidentId) => {
    setOpenCases((prev) => {
      const next = new Set(prev);
      if (next.has(incidentId)) next.delete(incidentId);
      else next.add(incidentId);
      return next;
    });
  }, []);

  const verified = state.verification?.ok;

  const eventTypes = [...new Set(state.entries.map((entry) => entry.event).filter(Boolean))].sort();

  const actors = [...new Set(state.entries.map((entry) => entry.actor).filter(Boolean))].sort();

  const filteredEntries = state.entries
    .filter((entry) => {
      const text = [
        entry.incident_id,
        entry.event_id,
        entry.event,
        entry.actor,
        displayActor(entry.actor),
        EVENT_LABELS[entry.event]?.label,
        eventDetail(entry),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

      const matchesSearch = text.includes(searchQuery.trim().toLowerCase());

      const matchesEvent = eventFilter === 'all' || entry.event === eventFilter;

      const matchesActor = actorFilter === 'all' || entry.actor === actorFilter;

      return (
        matchesSearch &&
        matchesEvent &&
        matchesActor &&
        (eventFilter === 'triage.tool_call' ||
          !!searchQuery.trim() ||
          entry.event !== 'triage.tool_call')
      );
    })
    .sort((a, b) => {
      // Audit sequence gives us a stable event order.
      const aSeq = Number(a.seq) || 0;
      const bSeq = Number(b.seq) || 0;

      return dateSort === 'newest' ? bSeq - aSeq : aSeq - bSeq;
    });

  // Filter the loaded audit events first, then retain the case-grouped view.
  const matchingGroups = groupByCase(filteredEntries);
  const visibleGroups = matchingGroups.sort((a, b) => {
    const aSeq = Math.max(...a.events.map((entry) => Number(entry.seq) || 0));
    const bSeq = Math.max(...b.events.map((entry) => Number(entry.seq) || 0));
    return dateSort === 'newest' ? bSeq - aSeq : aSeq - bSeq;
  });

  return (
    <section className="page audit-log-page">
      <header className="page-head">
        <div>
          <h1>Audit log</h1>
        </div>
        <div className="page-actions">
          {state.status === 'ready' ? (
            <span className={`chip ${verified ? 'chip-ok' : 'chip-warn'}`}>
              <Icon name={verified ? 'shield' : 'alert'} size={13} />
              {verified
                ? `Chain verified · ${state.verification.checked} records`
                : 'Chain check failed'}
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
            <p>Connect to the local service to view saved audit records.</p>
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
        <>
          <div className="audit-filters">
            <label className="audit-search-field">
              <span>Search activity</span>
              <input
                type="search"
                placeholder="Search case ID, event, or analyst..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </label>

            <SelectField
              label="Event type"
              value={eventFilter}
              onChange={setEventFilter}
              options={[
                { value: 'all', label: 'Key events' },
                ...eventTypes.map((type) => ({
                  value: type,
                  label: EVENT_LABELS[type]?.label || type,
                })),
              ]}
            />
            <SelectField
              label="Performed by"
              value={actorFilter}
              onChange={setActorFilter}
              options={[
                { value: 'all', label: 'All actors' },
                ...actors.map((actor) => ({ value: actor, label: displayActor(actor) })),
              ]}
            />
            <SelectField
              label="Sort by"
              value={dateSort}
              onChange={setDateSort}
              options={[
                { value: 'newest', label: 'Newest first' },
                { value: 'oldest', label: 'Oldest first' },
              ]}
            />
          </div>

          <section className="panel">
            {groups.length === 0 ? (
              <div className="empty">
                <Icon name="audit" size={20} />
                <p>No audit events yet. Run an AI triage investigation to populate the trail.</p>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="table audit-table">
                  <thead>
                    <tr>
                      <th colSpan={4} className="audit-case-heading">
                        Case
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleGroups.map((group) => (
                      <CaseGroup
                        key={group.incidentId}
                        group={group}
                        open={openCases.has(group.incidentId)}
                        onToggle={() => toggleCase(group.incidentId)}
                        dateSort={dateSort}
                      />
                    ))}
                  </tbody>
                </table>
                {visibleGroups.length === 0 && (
                  <p className="audit-no-results">No audit events match your filters.</p>
                )}
              </div>
            )}
          </section>
        </>
      ) : null}
    </section>
  );
}
