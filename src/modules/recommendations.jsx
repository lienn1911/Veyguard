import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';

const endpoint = (id, action) => `/api/cases/${encodeURIComponent(id)}/${action}`;

export default function NextSteps({ incidentId, analystName, onEvidence, onTimeline, onReviewed }) {
  const [proposal, setProposal] = useState(null);
  const [decisions, setDecisions] = useState({});
  const [events, setEvents] = useState([]);
  const [note, setNote] = useState(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    let current = true;
    setProposal(null);
    setDecisions({});
    setNote(null);
    setSubmitted(false);
    setError('');
    fetch(endpoint(incidentId, 'recommendations')).then((response) => response.json()).then(async (checks) => {
      const history = await fetch(endpoint(incidentId, 'audit')).then((response) => response.json());
      if (!current) return;
      if (checks.error) throw new Error(checks.error);
      setProposal(checks);
      setDecisions(checks.decisions || {});
      setNote(checks.note || null);
      setSubmitted(Object.keys(checks.decisions || {}).length > 0);
      setEvents(history.events || []);
    }).catch(() => { if (current) setError('Local review service is unavailable. Restart with start.cmd.'); });
    return () => { current = false; };
  }, [incidentId]);

  async function submit() {
    setSaving(true);
    setError('');
    try {
      const response = await apiFetch(endpoint(incidentId, 'approval'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: analystName, decisions }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Approval could not be saved');
      setNote(result.note);
      setEvents(result.events);
      setSubmitted(true);
      onReviewed?.();
    } catch (failure) {
      setError(failure.message);
    } finally {
      setSaving(false);
    }
  }

  const complete = proposal?.checks.every((item) => decisions[item.id]);

  return <section className="process-panel next-steps" aria-label="Next steps">
    <div className="process-panel-head"><h3>Recommended next steps</h3></div>
    <p className="process-note">AI suggestions are grounded in the case evidence and limited to safe investigation steps. Review each step before saving your decision.</p>
    {error && <p className="review-error" role="alert">{error}</p>}
    {!proposal && !error && <p className="process-note">Loading checks…</p>}
    {proposal && <>
      {!proposal.checks.some((item) => item.ai_suggested) && <p className="process-note">{proposal.ai_status === 'ready' ? 'This AI check did not produce a validated next step. The safe case-rule checks remain available below.' : 'Run AI check to see case-specific suggestions. The safe case-rule checks remain available below.'}</p>}
      <div className="check-list">{proposal.checks.map((item) => <div className="check-item" key={item.id}>
        <p>{item.ai_suggested && <span className="recommendation-ai-badge">AI suggested</span>}{item.text}</p>
        {item.ai_suggested && <div className="recommendation-ai-reason"><p>{item.ai_reason}</p><div>{item.ai_evidence_ids.map((id) => <button type="button" key={id} onClick={() => onEvidence(id)}>{id}</button>)}</div></div>}
        <button className="check-evidence" type="button" onClick={() => item.action === 'REVIEW_INCIDENT_TIMELINE' ? onTimeline() : onEvidence(item.evidence_ids[0])}>{item.action === 'REVIEW_INCIDENT_TIMELINE' ? 'View timeline' : item.action === 'REVIEW_NETWORK_FLOWS' ? 'View flows' : 'View evidence'}</button>
        <div className="check-actions" aria-label={`Decision for ${item.id}`}>
          <button type="button" disabled={submitted} className={decisions[item.id] === 'approved' ? 'selected' : ''} aria-pressed={decisions[item.id] === 'approved'} onClick={() => setDecisions({ ...decisions, [item.id]: 'approved' })}>Approve</button>
          <button type="button" disabled={submitted} className={decisions[item.id] === 'rejected' ? 'selected' : ''} aria-pressed={decisions[item.id] === 'rejected'} onClick={() => setDecisions({ ...decisions, [item.id]: 'rejected' })}>Reject</button>
        </div>
      </div>)}</div>
      {!submitted && <div className="review-approval"><label htmlFor="analyst-name">Reviewed by</label><input id="analyst-name" value={analystName || ''} readOnly /><button type="button" disabled={!complete || !analystName || saving} onClick={submit}>{saving ? 'Saving…' : 'Save step decisions'}</button></div>}
      {submitted && <p className="process-note" role="status">Step decisions saved. Continue to Case record to save the final summary.</p>}
      {note && <div className="case-note"><strong>Case note draft</strong><p>{note.summary}</p><ul>{note.approved_checks.map((item) => <li key={item.id}>{item.text}</li>)}</ul><small>Needs Review · Draft only</small></div>}
      {submitted && !note && <p className="process-note">All checks were rejected. No case note was drafted.</p>}
    </>}
    <div className="workflow-guardrail"><strong>Human control</strong><p>No automatic closure, dismissal, or priority downgrade.</p></div>
    <details className="audit-details"><summary>Activity history · {events.length}</summary><ol>{events.map((event, index) => <li key={index}><time>{event.time.slice(0, 19).replace('T', ' ')}</time> · {event.action.replaceAll('_', ' ').toLowerCase()}{event.decision ? ` · ${event.decision.toLowerCase()}` : ''}{event.analyst_id ? ` · ${event.analyst_id}` : ''}</li>)}</ol></details>
  </section>;
}
