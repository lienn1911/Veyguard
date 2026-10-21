import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';

const endpoint = (id, action) => `/api/cases/${encodeURIComponent(id)}/${action}`;

export default function NextSteps({ incidentId, analystName, onEvidence, onReviewed }) {
  const [proposal, setProposal] = useState(null);
  const [decisions, setDecisions] = useState({});
  const [analyst, setAnalyst] = useState(analystName || '');
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
        body: JSON.stringify({ analyst, decisions }),
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
    <div className="process-panel-head"><h3>Suggested checks</h3></div>
    {error && <p className="review-error" role="alert">{error}</p>}
    {!proposal && !error && <p className="process-note">Loading checks…</p>}
    {proposal && <>
      <div className="check-list">{proposal.checks.map((item) => <div className="check-item" key={item.id}>
        <p>{item.text}</p>
        <button className="check-evidence" type="button" onClick={() => onEvidence(item.evidence_ids.find((id) => id.startsWith('ALT-')) || item.evidence_ids[0])}>View evidence</button>
        <div className="check-actions" aria-label={`Decision for ${item.id}`}>
          <button type="button" disabled={submitted} className={decisions[item.id] === 'approved' ? 'selected' : ''} aria-pressed={decisions[item.id] === 'approved'} onClick={() => setDecisions({ ...decisions, [item.id]: 'approved' })}>Approve</button>
          <button type="button" disabled={submitted} className={decisions[item.id] === 'rejected' ? 'selected' : ''} aria-pressed={decisions[item.id] === 'rejected'} onClick={() => setDecisions({ ...decisions, [item.id]: 'rejected' })}>Reject</button>
        </div>
      </div>)}</div>
      {!submitted && <div className="review-approval"><label htmlFor="analyst-name">Reviewed by</label><input id="analyst-name" value={analyst} onChange={(event) => setAnalyst(event.target.value)} placeholder="Your name" autoComplete="name" /><button type="button" disabled={!complete || !analyst.trim() || saving} onClick={submit}>{saving ? 'Saving…' : 'Finish review'}</button></div>}
      {submitted && <p className="process-note" role="status">Review saved.</p>}
      {note && <div className="case-note"><strong>Case note draft</strong><p>{note.summary}</p><ul>{note.approved_checks.map((item) => <li key={item.id}>{item.text}</li>)}</ul><small>Needs Review · Draft only</small></div>}
      {submitted && !note && <p className="process-note">All checks were rejected. No case note was drafted.</p>}
    </>}
    <div className="workflow-guardrail"><strong>Human control</strong><p>No automatic closure, dismissal, or priority downgrade.</p></div>
    <details className="audit-details"><summary>Activity history · {events.length}</summary><ol>{events.map((event, index) => <li key={index}><time>{event.time.slice(0, 19).replace('T', ' ')}</time> · {event.action.replaceAll('_', ' ').toLowerCase()}{event.decision ? ` · ${event.decision.toLowerCase()}` : ''}{event.analyst_id ? ` · ${event.analyst_id}` : ''}</li>)}</ol></details>
  </section>;
}
