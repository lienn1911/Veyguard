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
    default:
      return '';
  }
}

export default function AuditLog({ mode, refreshToken }) {
  const [state, setState] = useState({ status: 'idle', entries: [], verification: null, error: null });

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

  return (
    <section className="page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Module 2 trail</p>
          <h1>Audit log</h1>
          <p className="page-sub">
            Append-only record of investigations and analyst decisions, hash-chained so edits are
            detectable.
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
              <p>Source: services.audit_log · Module 4 owns the project-wide audit log</p>
            </div>
            <span className="chip chip-muted">{state.entries.length} latest</span>
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
                  {[...state.entries].reverse().map((entry) => {
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
            </div>
          )}
        </section>
      ) : null}
    </section>
  );
}
