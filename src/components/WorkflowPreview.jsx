import React, { useEffect, useState } from 'react';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/ai-assessment`;
const verdicts = new Set(['Likely Attack', 'Likely Benign', 'Needs Review']);

export function TriagePreview({ incidentId, alerts, flows, onEvidence }) {
  const [result, setResult] = useState(null);
  const [state, setState] = useState('loading');
  const [error, setError] = useState('');
  const [mode, setMode] = useState('');
  const [running, setRunning] = useState(false);

  useEffect(() => {
    let active = true;
    setState('loading');
    setError('');
    fetch(endpoint(incidentId))
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok && payload.error === 'Unknown endpoint') return { status: 'pending', assessment: null };
        if (!response.ok) throw new Error('AI status unavailable');
        return payload;
      })
      .then((payload) => {
        if (!active) return;
        setResult(payload.assessment || null);
        setMode(payload.mode || '');
        setState(payload.status === 'ready' && payload.assessment ? 'ready' : payload.status === 'unavailable' ? 'error' : 'pending');
        if (payload.status === 'unavailable') setError(payload.error?.message || 'AI result unavailable. Run the check again.');
      })
      .catch(() => { if (active) { setState('error'); setError('Could not load AI status. Restart the local service.'); } });
    return () => { active = false; };
  }, [incidentId]);

  async function runAnalysis() {
    if (running) return;
    setRunning(true);
    setError('');
    try {
      const response = await fetch(endpoint(incidentId), { method: 'POST' });
      const payload = await response.json();
      if (!response.ok || payload.status !== 'ready') throw new Error(payload.error?.message || 'Analysis could not be completed.');
      setMode(payload.mode || '');
      setResult(payload.assessment);
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
  const ready = state === 'ready' && verdicts.has(result?.verdict) && evidenceIds.length > 0;

  return <section className="ai-assessment" aria-live="polite">
    <div className="ai-assessment-heading"><h3>AI check</h3><span className={`ai-assessment-state ${ready ? 'ready' : ''}`}>{ready ? 'Ready for review' : state === 'loading' ? 'Loading' : state === 'error' ? 'Unavailable' : 'Waiting for analysis'}</span></div>
    {mode && <p className="ai-assessment-note">{mode === 'mock' ? 'Demo simulation · no live AI model' : 'Live AI model · analyst review required'}</p>}
    {ready ? <>
      <div className="ai-assessment-result"><span>Assessment</span><strong>{result.verdict}</strong>{typeof result.confidence === 'number' && result.confidence >= 0 && result.confidence <= 1 && <small>{Math.round(result.confidence * 100)}% confidence</small>}</div>
      {typeof result.summary === 'string' && result.summary.trim() && <p className="ai-assessment-summary">{result.summary}</p>}
      <div className="ai-assessment-evidence"><strong>Supporting evidence</strong><div>{evidenceIds.map((id) => <button type="button" key={id} onClick={() => onEvidence(id)}>{id}</button>)}</div></div>
      <p className="ai-assessment-note">Analyst review is required before any next step.</p>
    </> : <div className="ai-assessment-empty"><strong>{state === 'loading' ? 'Checking analysis status…' : state === 'error' ? error : 'No AI assessment yet'}</strong><p>{state === 'pending' ? `${alerts.length} alerts and ${flows.length} example records are available for analysis.` : 'The alert and case evidence remain available for manual review.'}</p>{state !== 'loading' && <button type="button" className="process-next" onClick={runAnalysis} disabled={running}>{running ? 'Analysing…' : 'Run AI check'}</button>}</div>}
  </section>;
}
