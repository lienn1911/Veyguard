import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from '../components/Icon.jsx';

const stepPurpose = {
  REVIEW_NETWORK_FLOWS: 'Check ports, packet counts and traffic patterns.',
  CHECK_RELATED_ALERTS: 'Compare the rule matches and their supporting evidence.',
  REVIEW_INCIDENT_TIMELINE: 'Check when the activity started and how it changed.',
  ESCALATE_TO_ANALYST: 'Review the evidence before deciding whether to escalate.',
};

const endpoint = (id, action) => `/api/cases/${encodeURIComponent(id)}/${action}`;

export default function NextSteps({ incidentId, analystName, onEvidence, onTimeline, onReviewed, onCaseRecord, onOverview }) {
  const [proposal, setProposal] = useState(null);
  const [decisions, setDecisions] = useState({});
  const [remarks, setRemarks] = useState({});
  const [events, setEvents] = useState([]);
  const [note, setNote] = useState(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    let current = true;
    setProposal(null);
    setDecisions({});
    setRemarks({});
    setNote(null);
    setSubmitted(false);
    setError('');
    fetch(endpoint(incidentId, 'recommendations')).then((response) => response.json()).then(async (checks) => {
      const history = await fetch(endpoint(incidentId, 'audit')).then((response) => response.json());
      if (!current) return;
      if (checks.error) throw new Error(checks.error);
      setProposal(checks);
      setDecisions(checks.decisions || {});
      setRemarks(checks.remarks || {});
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
        body: JSON.stringify({ analyst: analystName, decisions, remarks: Object.fromEntries(Object.entries(remarks).filter(([id, value]) => decisions[id] && value.trim())) }),
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

  const checks = proposal?.checks || [];
  const reviewed = checks.filter((item) => decisions[item.id]).length;
  const approved = checks.filter((item) => decisions[item.id] === 'approved').length;
  const aiChecks = checks.filter((item) => item.ai_suggested);
  const renderCheck = (item, index) => <li className="recommendation-row" key={item.id}>
    <span className="recommendation-number" aria-hidden="true">{index + 1}</span>
    <div className="recommendation-content">
      <h3>{item.text}</h3>
      <p>{stepPurpose[item.action]}</p>
      {item.ai_suggested && <details className="recommendation-rationale"><summary>Reason and evidence</summary><p>{item.ai_reason}</p><div>{(item.ai_evidence_ids || []).map((id) => <button type="button" key={id} onClick={() => onEvidence(id)}>{id}</button>)}</div></details>}
      <label className="recommendation-remark"><span>Remark <small>(optional)</small></span><textarea value={remarks[item.id] || ''} onChange={(event) => setRemarks({ ...remarks, [item.id]: event.target.value })} disabled={submitted || saving} maxLength={1000} rows={2} placeholder="Add your reason or follow-up note" /></label>
    </div>
    <div className="recommendation-choice" role="group" aria-label={`Decision: ${item.text}`}>
      <button type="button" disabled={submitted || saving} className={decisions[item.id] === 'approved' ? 'selected approved' : ''} aria-pressed={decisions[item.id] === 'approved'} onClick={() => setDecisions({ ...decisions, [item.id]: 'approved' })}>{decisions[item.id] === 'approved' ? 'Approved' : 'Approve'}</button>
      <button type="button" disabled={submitted || saving} className={decisions[item.id] === 'rejected' ? 'selected rejected' : ''} aria-pressed={decisions[item.id] === 'rejected'} onClick={() => setDecisions({ ...decisions, [item.id]: 'rejected' })}>{decisions[item.id] === 'rejected' ? 'Rejected' : 'Reject'}</button>
    </div>
  </li>;

  return <section className="recommendations-workspace" aria-label="Investigation plan">
    {error && <p className="review-error" role="alert">{error}</p>}
    {!proposal && !error && <p className="process-note" role="status">Loading investigation steps…</p>}
    {proposal && <>
      {aiChecks.length ? <><ol className="recommendations-list">{aiChecks.map(renderCheck)}</ol></> : <div className="recommendations-empty" role="status"><span className="recommendations-empty-icon"><Icon name={proposal.ai_status === 'ready' ? 'checkCircle' : 'alert'} size={25} /></span><div className="recommendations-empty-copy"><strong>{proposal.ai_status === 'ready' ? 'No next steps proposed' : 'No AI recommendations yet'}</strong><p>{proposal.ai_status === 'ready' ? 'The investigation finished without suggesting a step.' : 'AI investigation did not finish.'}</p></div>{proposal.ai_status !== 'ready' && onOverview && <button type="button" className="recommendations-empty-action" onClick={onOverview}>Open Overview <Icon name="arrow" size={15} /></button>}</div>}
      {!submitted && aiChecks.length > 0 && <div className="recommendations-review-actions"><button type="button" className="recommendations-primary" disabled={!reviewed || !analystName || saving} onClick={submit}>{saving ? 'Saving…' : 'Save decisions'}</button></div>}
      {note && <details className="recommendations-details"><summary>Case note draft</summary><p>{note.summary}</p><ul>{note.approved_checks.map((item) => <li key={item.id}>{item.text}</li>)}</ul></details>}
    </>}
    <details className="recommendations-details"><summary>Activity history · {events.length}</summary><ol>{events.map((event, index) => <li key={index}><time>{event.time.slice(0, 19).replace('T', ' ')}</time> · {event.action.replaceAll('_', ' ').toLowerCase()}{event.decision ? ` · ${event.decision.toLowerCase()}` : ''}{event.analyst_id ? ` · ${event.analyst_id}` : ''}</li>)}</ol></details>
  </section>;
}
