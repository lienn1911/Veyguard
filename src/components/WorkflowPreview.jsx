import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import { formatConfidence } from '../lib/format.js';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/ai-assessment`;
const verdicts = new Set(['Likely Attack', 'Likely Benign', 'Needs Review']);
const apiError = (payload) => payload?.error?.code === 'PROVIDER_RATE_LIMITED'
  ? 'The AI provider reached its rate limit or quota. No assessment was produced; check the provider quota before retrying.'
  : typeof payload?.error === 'string' ? payload.error : payload?.error?.message;

export function TriagePreview({ incidentId, alerts, flows, onEvidence, analystName, autoRunning = false, refreshToken = '' }) {
  const [result, setResult] = useState(null);
  const [state, setState] = useState('loading');
  const [error, setError] = useState('');
  const [mode, setMode] = useState('');
  const [running, setRunning] = useState(false);
  const [decision, setDecision] = useState(null);
  const [reviewNote, setReviewNote] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [reviewError, setReviewError] = useState('');

  useEffect(() => {
    let active = true;
    setState('loading');
    setError('');
    setDecision(null);
    setReviewNote('');
    setReviewError('');
    fetch(endpoint(incidentId))
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) throw new Error(apiError(payload) === 'Unknown endpoint'
          ? 'The running API is outdated. Restart start.cmd, then try again.'
          : apiError(payload) || 'AI status unavailable');
        return payload;
      })
      .then((payload) => {
        if (!active) return;
        setResult(payload.mode === 'mock' ? null : payload.assessment || null);
        setDecision(payload.decision || null);
        setMode(payload.mode || '');
        setState(payload.mode === 'mock' || payload.status === 'not_configured' ? 'not_configured' : payload.status === 'ready' && payload.assessment ? 'ready' : payload.status === 'unavailable' ? 'error' : 'pending');
        if (payload.status === 'unavailable') setError(apiError(payload) || 'AI result unavailable. Run the check again.');
      })
      .catch((failure) => { if (active) { setState('error'); setError(failure.message || 'Could not load AI status. Restart the local service.'); } });
    return () => { active = false; };
  }, [incidentId, refreshToken]);

  async function runAnalysis() {
    if (running) return;
    setRunning(true);
    setError('');
    setState('loading');
    try {
      const response = await apiFetch(endpoint(incidentId), { method: 'POST' });
      const payload = await response.json();
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
      if (!response.ok || payload.status !== 'ready') {
        const message = apiError(payload);
        throw new Error(message === 'Unknown endpoint'
          ? 'The running API is outdated. Restart start.cmd, then try again.'
          : message || 'Analysis could not be completed.');
      }
      setMode(payload.mode || '');
      setResult(payload.assessment);
      setDecision(payload.decision || null);
      setReviewNote('');
      setState('ready');
    } catch (failure) {
      setState('error');
      setError(failure.message || 'Analysis could not be completed.');
    } finally {
      setRunning(false);
    }
  }

  async function saveReview(choice) {
    if (reviewing) return;
    setReviewing(true);
    setReviewError('');
    try {
      const response = await apiFetch(`/api/cases/${encodeURIComponent(incidentId)}/ai-decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: choice, analyst: analystName, note: reviewNote.trim() }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Could not save AI review.');
      setDecision(payload.decision);
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
    } catch (failure) {
      setReviewError(failure.message || 'Could not save AI review.');
    } finally {
      setReviewing(false);
    }
  }

  const validEvidence = new Set([...alerts.map((item) => item.alert_id), ...flows.map((item) => item.flow_id)]);
  const evidenceIds = Array.isArray(result?.evidence_ids) ? result.evidence_ids.filter((id) => validEvidence.has(id)) : [];
  const ready = mode === 'live' && state === 'ready' && verdicts.has(result?.verdict) && evidenceIds.length > 0;

  return <section className="ai-assessment" aria-live="polite">
    <div className="ai-assessment-heading"><h3>AI check</h3><span className={`ai-assessment-state ${ready ? 'ready' : state === 'error' ? 'error' : ''}`}>{ready ? 'Validated · review needed' : running ? 'Analysing' : state === 'loading' ? 'Loading' : state === 'error' ? 'Unavailable' : state === 'not_configured' ? 'Not configured' : 'Waiting for analysis'}</span></div>
    {ready ? <>
      <div className="ai-assessment-result"><span>Assessment</span><strong>{result.verdict}</strong>{((typeof result.confidence === 'number' && result.confidence >= 0 && result.confidence <= 1) || typeof result.confidence === 'string') && <small>{formatConfidence(result.confidence)}</small>}</div>
      {typeof result.summary === 'string' && result.summary.trim() && <p className="ai-assessment-summary">{result.summary}</p>}
      {result.limitations && <p className="ai-assessment-limits"><strong>Limits of this assessment</strong><br />{result.limitations}</p>}
      <div className="ai-assessment-evidence"><strong>Supporting evidence</strong><div>{evidenceIds.map((id) => <button type="button" key={id} onClick={() => onEvidence(id)}>{id}</button>)}</div></div>
      {decision?.status && decision.status !== 'pending' ? <p className="ai-review-saved" role="status">AI proposal {decision.status} by {decision.analyst}{decision.note ? ` · ${decision.note}` : ''}</p> : <div className="ai-review-controls"><label htmlFor="ai-review-reason">Analyst reason{result.requires_confirmation ? ' · required for a Likely Benign confirmation' : ''}</label><textarea id="ai-review-reason" value={reviewNote} onChange={(event) => setReviewNote(event.target.value)} rows={3} placeholder="Explain your decision using the evidence above" /><div><button type="button" disabled={reviewing || (result.requires_confirmation && result.verdict === 'Likely Benign' && !reviewNote.trim())} onClick={() => saveReview('confirmed')}>Confirm AI assessment</button><button type="button" disabled={reviewing || !reviewNote.trim()} onClick={() => saveReview('rejected')}>Reject assessment</button></div>{reviewError && <p role="alert">{reviewError}</p>}</div>}
    </> : <div className="ai-assessment-empty"><strong>{autoRunning || running ? 'Analysing evidence…' : state === 'loading' ? 'Checking analysis status…' : state === 'error' ? error : state === 'not_configured' ? 'Connect a live AI provider in Settings' : 'No AI assessment yet'}</strong><p>{state === 'pending' || autoRunning ? `${alerts.length} alerts and ${flows.length} linked sample records are available for analysis.` : 'The alert and case evidence remain available for manual review.'}</p>{state !== 'loading' && state !== 'not_configured' && <button type="button" className="process-next" onClick={runAnalysis} disabled={running || autoRunning}>{running || autoRunning ? 'Analysing…' : 'Run AI check'}</button>}</div>}
  </section>;
}
