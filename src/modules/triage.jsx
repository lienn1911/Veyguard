import React, { useEffect, useState } from 'react';
import Icon from '../components/Icon.jsx';
import { formatDuration, formatTimestamp, verdictClass } from '../lib/format.js';

const TOOL_LABELS = {
  get_incident_details: 'Incident record',
  get_related_alerts: 'Related alerts',
  get_network_flows: 'Flow evidence',
  get_incident_statistics: 'Statistics',
};

function Elapsed({ startedAt }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, []);
  const seconds = Math.max(0, (now - startedAt) / 1000);
  return <span className="mono">{seconds.toFixed(1)}s</span>;
}

function StatusPill({ status }) {
  const map = {
    ok: { label: 'Validated', icon: 'checkCircle', tone: 'ok' },
    rejected: { label: 'Rejected by backend', icon: 'alert', tone: 'warn' },
    error: { label: 'Investigation failed', icon: 'close', tone: 'error' },
  };
  const meta = map[status] || map.error;
  return (
    <span className={`status status-${meta.tone}`}>
      <Icon name={meta.icon} size={13} />
      {meta.label}
    </span>
  );
}

function Trace({ investigation }) {
  const [open, setOpen] = useState(false);
  if (!investigation) return null;
  const calls = investigation.tool_calls || [];
  return (
    <div className="trace">
      <button type="button" className="trace-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
        <Icon name={open ? 'chevronDown' : 'chevron'} size={14} />
        Investigation trace
        <span className="muted">
          {investigation.steps} turns · {calls.length} tool calls
          {investigation.blocked_attempts?.length ? ` · ${investigation.blocked_attempts.length} blocked` : ''}
        </span>
      </button>
      {open ? (
        <ol className="trace-list">
          {calls.map((call, index) => (
            <li key={`${call.tool}-${index}`} className={call.ok ? 'ok' : 'bad'}>
              <Icon name={call.ok ? 'check' : call.blocked ? 'lock' : 'close'} size={12} />
              <span className="mono">{call.tool}</span>
              <span className="muted">{TOOL_LABELS[call.tool] || 'tool'}</span>
              <span className="trace-side">
                {call.ok ? `${call.duration_ms} ms` : call.error?.code || 'failed'}
              </span>
            </li>
          ))}
          {calls.length === 0 ? <li className="muted">No tool calls were made.</li> : null}
        </ol>
      ) : null}
    </div>
  );
}

export default function Triage({ incident, triage, decision, mode, ready, blockedReason, onRun, running, onDecide, onInspect }) {
  const [startedAt, setStartedAt] = useState(null);
  const [form, setForm] = useState(null); // 'confirmed' | 'rejected' | null
  const [analyst, setAnalyst] = useState('');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [decisionError, setDecisionError] = useState(null);

  useEffect(() => {
    if (running) setStartedAt(Date.now());
  }, [running]);

  useEffect(() => {
    setForm(null);
    setDecisionError(null);
    setNote('');
  }, [incident?.incident_id, triage?.run_id]);

  const offline = mode === 'offline';
  const disabled = offline || !ready || running;
  const status = triage?.status;
  const verdict = triage?.verdict;
  const proposal = triage?.proposal;
  const pending = proposal && (!decision || decision.status === 'pending');

  async function submitDecision(value) {
    setSubmitting(true);
    setDecisionError(null);
    try {
      await onDecide({ decision: value, analyst: analyst.trim(), note: note.trim() || undefined });
      setForm(null);
    } catch (error) {
      setDecisionError(error.message || 'Could not record the decision.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel triage" aria-label="AI triage">
      <div className="triage-head">
        <div>
          <p className="eyebrow">
            <Icon name="spark" size={12} /> Module 2
          </p>
          <h2>AI triage</h2>
        </div>
        <span className={`chip chip-mode chip-${mode}`}>
          <Icon name={mode === 'live' ? 'cpu' : mode === 'mock' ? 'terminal' : 'database'} size={12} />
          {mode === 'live' ? 'Live model' : mode === 'mock' ? 'Mock model' : 'Offline'}
        </span>
      </div>

      <div className="triage-actions">
        <button type="button" className="btn btn-primary btn-block" onClick={onRun} disabled={disabled}>
          {running ? (
            <>
              <span className="spinner" aria-hidden="true" />
              Investigating…
            </>
          ) : (
            <>
              <Icon name="play" size={14} />
              {triage ? 'Re-run AI triage' : 'Run AI triage'}
            </>
          )}
        </button>
        {running && startedAt ? (
          <p className="triage-progress">
            <Elapsed startedAt={startedAt} /> · read-only tools · verdict validated server-side
          </p>
        ) : null}
        {!running && disabled ? (
          <p className="triage-hint">
            {offline
              ? 'Start the Python API (python -m services.api) to run investigations.'
              : blockedReason || 'The AI provider is not configured.'}
          </p>
        ) : null}
      </div>

      {!triage && !running ? (
        <div className="triage-empty">
          <Icon name="cpu" size={20} />
          <p>The agent retrieves incident metadata, alerts, sampled flows and aggregates, then
            proposes one of three verdicts with cited evidence IDs.</p>
          <ul className="tool-list">
            {Object.entries(TOOL_LABELS).map(([tool, label]) => (
              <li key={tool}>
                <Icon name="terminal" size={12} />
                <span className="mono">{tool}</span>
                <em>{label}</em>
              </li>
            ))}
          </ul>
          <p className="triage-hint">
            Tools are read-only. A proposal is never a closure decision.
          </p>
        </div>
      ) : null}

      {triage ? (
        <div className="triage-result">
          <div className="result-head">
            <span className={`verdict verdict-${verdictClass(verdict)}`}>
              {verdict || 'No verdict'}
            </span>
            <StatusPill status={status} />
          </div>

          {status === 'ok' ? (
            <>
              <p className="result-reason">{triage.reason}</p>
              <div className="result-meta">
                <span>
                  confidence <strong>{triage.confidence || '—'}</strong>
                </span>
                <span>
                  evidence <strong>{triage.evidence_ids?.length || 0}</strong>
                </span>
                <span className="mono">{formatDuration(triage.duration_ms)}</span>
              </div>

              {triage.evidence_ids?.length ? (
                <div className="evidence-block">
                  <p className="label">Cited evidence</p>
                  <div className="chips">
                    {triage.evidence_ids.map((id) => (
                      <button
                        key={id}
                        type="button"
                        className="chip chip-evidence mono"
                        onClick={() => onInspect(id)}
                        title="Show the underlying record"
                      >
                        <Icon name="hash" size={11} />
                        {id}
                      </button>
                    ))}
                  </div>
                </div>
              ) : null}

              {triage.findings?.length ? (
                <ul className="findings">
                  {triage.findings.map((finding, index) => (
                    <li key={index}>
                      <span>{finding.observation}</span>
                      {finding.evidence_ids?.length ? (
                        <em className="mono">{finding.evidence_ids.join(' · ')}</em>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : null}

              {triage.limitations ? (
                <p className="limitation">
                  <Icon name="info" size={12} /> {triage.limitations}
                </p>
              ) : null}
            </>
          ) : null}

          {status === 'rejected' ? (
            <div className="alert-block warn">
              <p>
                Backend validation rejected the model's proposal. The verdict shown is
                <strong> not a classification</strong> — it is the safe fallback.
              </p>
              <ul>
                {(triage.validation?.issues || []).slice(0, 5).map((issue, index) => (
                  <li key={index}>
                    <span className="mono">{issue.code}</span> {issue.message}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {status === 'error' ? (
            <div className="alert-block error">
              <p>
                The investigation did not complete, so there is no verdict.
                <span className="mono"> {triage.error?.code}</span>
              </p>
              <p className="muted">{triage.error?.message}</p>
              <p className="muted small">
                Operational failures are never reported as benign or attack findings.
              </p>
            </div>
          ) : null}

          {triage.requires_confirmation ? (
            <div className="guardrail">
              <Icon name="lock" size={14} />
              <div>
                <strong>Human confirmation required</strong>
                <p>
                  A Likely Benign proposal on a {incident?.category} incident cannot be treated as
                  benign without an explicit analyst decision.
                </p>
              </div>
            </div>
          ) : null}

          {pending ? (
            <div className="decision">
              {form === null ? (
                <div className="decision-actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => setForm('confirmed')}
                  >
                    <Icon name="check" size={14} />
                    Accept proposal
                  </button>
                  <button type="button" className="btn btn-quiet" onClick={() => setForm('rejected')}>
                    Reject
                  </button>
                </div>
              ) : (
                <div className="decision-form">
                  <label>
                    Analyst
                    <input
                      type="text"
                      value={analyst}
                      onChange={(event) => setAnalyst(event.target.value)}
                      placeholder="e.g. a.singh"
                      autoFocus
                    />
                  </label>
                  <label>
                    Note {form === 'rejected' ? '(required)' : '(optional)'}
                    <textarea
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      rows={2}
                      placeholder={
                        form === 'rejected'
                          ? 'Why is the proposal wrong?'
                          : 'What did you verify?'
                      }
                    />
                  </label>
                  {decisionError ? <p className="form-error">{decisionError}</p> : null}
                  <div className="decision-actions">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={submitting || !analyst.trim() || (form === 'rejected' && !note.trim())}
                      onClick={() => submitDecision(form)}
                    >
                      {submitting ? 'Recording…' : form === 'confirmed' ? 'Confirm decision' : 'Reject proposal'}
                    </button>
                    <button type="button" className="btn btn-quiet" onClick={() => setForm(null)}>
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : null}

          {decision && decision.status !== 'pending' ? (
            <div className={`decision-record decision-${decision.status}`}>
              <Icon name={decision.status === 'confirmed' ? 'checkCircle' : 'close'} size={14} />
              <div>
                <strong>
                  {decision.status === 'confirmed' ? 'Proposal accepted' : 'Proposal rejected'}
                </strong>
                <p>
                  {decision.analyst} · {formatTimestamp(decision.at)}
                  {decision.note ? ` — ${decision.note}` : ''}
                </p>
              </div>
            </div>
          ) : null}

          <Trace investigation={triage.investigation} />

          <p className="run-meta mono">
            {triage.provider} · {triage.model} · {triage.run_id} · {formatTimestamp(triage.completed_at)}
          </p>
        </div>
      ) : null}
    </section>
  );
}
