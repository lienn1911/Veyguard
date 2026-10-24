import React, { useEffect, useState } from 'react';
import AssessmentSummary from './AssessmentSummary.jsx';
import { apiFetch } from '../apiFetch.js';
import { formatConfidence } from '../lib/format.js';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/ai-assessment`;
const verdicts = new Set(['Likely Attack', 'Likely Benign', 'Needs Review']);
const toolLabels = { get_incident_details: 'Case details', get_related_alerts: 'Related rule matches', get_network_flows: 'Communication records', get_incident_statistics: 'Traffic statistics' };
const apiError = (payload) => payload?.error?.code === 'PROVIDER_RATE_LIMITED'
  ? 'The AI provider reached its rate limit or quota. No assessment was produced; check the provider quota before retrying.'
  : typeof payload?.error === 'string' ? payload.error : payload?.error?.message;

export function TriagePreview({ incidentId, alerts, flows, onEvidence, onRecommendations, analystName, autoRunning = false, refreshToken = '' }) {
  const [result, setResult] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [state, setState] = useState('loading');
  const [error, setError] = useState('');
  const [mode, setMode] = useState('');
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(null);

  useEffect(() => {
    let active = true;
    setState('loading');
    setProgress(null);
    setError('');
    setInvestigation(null);
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
        setProgress(payload.progress || null);
        setInvestigation(payload.investigation || null);
        setMode(payload.mode || '');
        setState(payload.mode === 'mock' || payload.status === 'not_configured' ? 'not_configured' : payload.status === 'ready' && payload.assessment ? 'ready' : payload.status === 'unavailable' ? 'error' : payload.status === 'running' ? 'running' : 'pending');
        if (payload.status === 'unavailable') setError(apiError(payload) || 'AI result unavailable. Run the check again.');
      })
      .catch((failure) => { if (active) { setState('error'); setError(failure.message || 'Could not load AI status. Restart the local service.'); } });
    return () => { active = false; };
  }, [incidentId, refreshToken]);

  useEffect(() => {
    if (!(running || autoRunning || state === 'running')) return;
    let active = true;
    let timer;
    const controller = new AbortController();
    async function poll() {
      try {
        const response = await fetch(endpoint(incidentId), { signal: controller.signal });
        if (!response.ok) return;
        const payload = await response.json();
        if (!active) return;
        if (payload.progress) setProgress(payload.progress);
        if (!running && payload.status !== 'running') {
          setResult(payload.mode === 'live' ? payload.assessment || null : null);
          setInvestigation(payload.investigation || null);
          setMode(payload.mode || '');
          setState(payload.status === 'ready' ? 'ready' : payload.status === 'unavailable' ? 'error' : 'pending');
          if (payload.status === 'unavailable') setError(apiError(payload) || 'The check did not finish.');
        }
      } catch { /* Keep the last confirmed stage if a status request is interrupted. */ }
      finally { if (active) timer = setTimeout(poll, 1000); }
    }
    poll();
    return () => { active = false; clearTimeout(timer); controller.abort(); };
  }, [incidentId, running, autoRunning, state === 'running']);

  async function runAnalysis() {
    if (running) return;
    setProgress({ stage: 'prepare', percent: 10, description: 'Preparing this case for read-only evidence checks.' });
    setRunning(true);
    setError('');
    setState('loading');
    try {
      const response = await apiFetch(endpoint(incidentId), { method: 'POST' });
      const payload = await response.json();
      setInvestigation(payload.investigation || null);
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
      if (!response.ok || payload.status !== 'ready') {
        const message = apiError(payload);
        throw new Error(message === 'Unknown endpoint'
          ? 'The running API is outdated. Restart start.cmd, then try again.'
          : message || 'Analysis could not be completed.');
      }
      const assessment = payload.assessment;
      const allowedIds = new Set([...alerts.map((item) => item.alert_id), ...flows.map((item) => item.flow_id)]);
      if (payload.mode !== 'live' || !verdicts.has(assessment?.verdict) || !Array.isArray(assessment?.evidence_ids) || (assessment.verdict !== 'Needs Review' && !assessment.evidence_ids.some((id) => allowedIds.has(id)))) {
        throw new Error('The AI response could not be verified against this case. Please retry.');
      }
      setMode(payload.mode || '');
      setResult(payload.assessment);
      setInvestigation(payload.investigation || null);
      setState('ready');
    } catch (failure) {
      setState('error');
      setError(failure.message || 'Analysis could not be completed.');
    } finally {
      setRunning(false);
    }
  }

  const validEvidence = new Set([...alerts.map((item) => item.alert_id), ...flows.map((item) => item.flow_id)]);
  const evidenceIds = Array.isArray(result?.evidence_ids) ? result.evidence_ids.filter((id) => validEvidence.has(id)) : [];
  const ready = mode === 'live' && state === 'ready' && verdicts.has(result?.verdict) && (evidenceIds.length > 0 || result?.verdict === 'Needs Review');
  const busy = running || autoRunning || state === 'running';
  const stages = ['Prepare case', 'Read evidence', 'Assess findings', 'Validate evidence', 'Prepare review'];
  const stageIndex = { prepare: 0, evidence: 1, analyse: 2, validate: 3, save: 4, complete: 4 }[progress?.stage] ?? 0;
  const percent = progress?.percent ?? 10;

  return <section className="ai-assessment" aria-live="polite">
    <div className="ai-assessment-heading"><h3>AI assessment</h3>{!ready && state !== 'error' && <span className={`ai-investigation-status ${ready ? 'ready' : ''}`}>{ready ? 'Result ready' : busy ? 'Investigating' : state === 'not_configured' ? 'Setup needed' : state === 'loading' ? 'Checking' : 'Not run'}</span>}</div>

    {ready ? <>
      <div className="ai-assessment-result"><span>AI proposal</span><strong className={`ai-verdict-${result.verdict.toLowerCase().replaceAll(' ', '-')}`}>{result.verdict}</strong>{((typeof result.confidence === 'number' && result.confidence >= 0 && result.confidence <= 1) || typeof result.confidence === 'string') && <small>{formatConfidence(result.confidence)}</small>}</div>
      {typeof result.summary === 'string' && result.summary.trim() && <section className="ai-assessment-reason" aria-label="Assessment summary"><AssessmentSummary text={result.summary} /></section>}

    </> : <div className={`ai-investigation-empty${state === 'error' ? ' is-error' : ''}`}>
      <div className="ai-investigation-action"><h4>{state === 'error' ? 'Could not complete' : busy ? 'Checking case evidence…' : state === 'not_configured' ? 'Connect an AI provider' : 'Investigate this signal'}</h4>
        {state === 'error' && <><p className="ai-analysis-error" role="alert">{error}</p><div className="ai-interrupted-trace"><strong>{investigation?.tool_calls?.length ? `${investigation.tool_calls.length} queries attempted` : 'No evidence queried'}</strong>{investigation?.tool_calls?.length > 0 && <ol>{investigation.tool_calls.map((call, index) => <li key={`${call.tool}-${index}`}>{toolLabels[call.tool] || call.tool}{call.ok ? ' · completed' : ' · failed'}</li>)}</ol>}</div></>}
        {state === 'not_configured' && <p>Set up a live provider in AI settings.</p>}
        {state === 'pending' && !busy && <p>AI chooses read-only queries, checks evidence and proposes a judgment and next steps for you to review.</p>}
        {busy && <div className="triage-progress">
          <ol className="triage-progress-steps">{stages.map((label, index) => <li key={label} className={index < stageIndex ? 'done' : index === stageIndex ? 'current' : ''} aria-current={index === stageIndex ? 'step' : undefined}><span>{index + 1}</span>{label}</li>)}</ol>
          <div className="triage-progress-percent">{percent}%</div>
          <div className="triage-progress-track" role="progressbar" aria-label="AI check workflow progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent} aria-valuetext={`${percent}%, ${stages[stageIndex]}`}><span style={{ width: `${percent}%` }} /></div>
        </div>}
        {state !== 'not_configured' && <button type="button" className="ai-analysis-run" onClick={runAnalysis} disabled={state === 'loading' || busy}>{busy ? 'Investigating…' : state === 'loading' ? 'Checking…' : state === 'error' && /limit|quota/i.test(error) ? 'Retry after quota resets' : state === 'error' ? 'Retry investigation' : 'Start investigation'}</button>}
      </div>
    </div>}

  </section>;
}

export function AssessmentReview({ incidentId, analystName, result, initialDecision, onSaved, hideHeading = false }) {
  const [decision, setDecision] = useState(initialDecision || null);
  const [reviewNote, setReviewNote] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [reviewError, setReviewError] = useState('');
  const [reviewChoice, setReviewChoice] = useState(null);
  const protectedBenign = result.requires_confirmation && result.verdict === 'Likely Benign';
  useEffect(() => { setDecision(initialDecision || null); }, [initialDecision]);
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
      await onSaved?.();
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
    } catch (failure) {
      setReviewError(failure.message || 'Could not save AI review.');
    } finally {
      setReviewing(false);
    }
  }

  return <section className="report-assessment-review" aria-label="Review AI conclusion">{decision?.status && decision.status !== 'pending' ? <div className="ai-review-saved" role="status"><strong>{decision.status === 'confirmed' ? 'Agreed with AI conclusion' : 'Disagreed with AI conclusion'}</strong><span>{decision.analyst}{decision.at ? ` · ${`${new Date(decision.at).toISOString().slice(0, 16).replace('T', ' ')} UTC`}` : ''}</span>{decision.note && <p>{decision.note}</p>}</div> : <div className="ai-review-controls">
    {!hideHeading && <h4>Review AI conclusion</h4>}
    <div className="conclusion-review-actions"><button type="button" disabled={reviewing} className="assessment-confirm" onClick={() => protectedBenign ? setReviewChoice('confirmed') : saveReview('confirmed')}>{reviewing ? 'Saving…' : 'Agree'}</button><button type="button" disabled={reviewing} className="assessment-reject" aria-expanded={reviewChoice === 'rejected'} onClick={() => setReviewChoice('rejected')}>Disagree</button></div>
    {reviewChoice && <div className="conclusion-reason"><label htmlFor="ai-review-reason">{reviewChoice === 'rejected' ? 'Why do you disagree?' : 'Reason for confirming this benign conclusion'} · required</label><textarea id="ai-review-reason" value={reviewNote} onChange={(event) => setReviewNote(event.target.value)} rows={3} placeholder="Explain your decision using the evidence above" /><div><button type="button" disabled={reviewing || !reviewNote.trim()} className="assessment-confirm" onClick={() => saveReview(reviewChoice)}>Save decision</button><button type="button" disabled={reviewing} onClick={() => setReviewChoice(null)}>Cancel</button></div></div>}
    {reviewError && <p role="alert">{reviewError}</p>}
  </div>}</section>;
}
