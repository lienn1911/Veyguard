import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/record`;

export default function CaseRecord({ incidentId, analystName, onAudit }) {
  const [state, setState] = useState({ status: 'loading', record: null });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [resolutionReason, setResolutionReason] = useState('');
  const [resolutionConfirmed, setResolutionConfirmed] = useState(false);
  const [resolving, setResolving] = useState(false);

  useEffect(() => {
    let active = true;
    setState({ status: 'loading', record: null });
    setError('');
    fetch(endpoint(incidentId))
      .then(async (response) => {
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Case record unavailable');
        return result;
      })
      .then((result) => { if (active) setState(result); })
      .catch((failure) => { if (active) setError(failure.message); });
    return () => { active = false; };
  }, [incidentId]);

  async function save() {
    setSaving(true);
    setError('');
    try {
      const response = await apiFetch(endpoint(incidentId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: analystName }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not save case record');
      setState(result);
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
    } catch (failure) {
      setError(failure.message);
    } finally {
      setSaving(false);
    }
  }

  async function resolve() {
    if (!resolutionConfirmed || resolutionReason.trim().length < 10) {
      setError('Enter a resolution reason and confirm your decision.');
      return;
    }

    setResolving(true);
    setError('');

    try {
      const response = await apiFetch(
        `/api/cases/${encodeURIComponent(incidentId)}/resolve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            analyst: analystName,
            reason: resolutionReason.trim(),
            confirmed: true
          })
        }
      );

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || 'Could not resolve case');
      }

      setState(result);

      window.dispatchEvent(
        new CustomEvent('case-activity-updated', {
          detail: incidentId
        })
      );
    } catch (failure) {
      setError(failure.message);
    } finally {
      setResolving(false);
    }
  }

  const record = state.record;
  return <section className="case-record" aria-live="polite">
    <div className="incident-section-heading"><h2>Case record</h2></div>
    <p className="case-record-intro">Review the final summary, then save a snapshot to the audit log. This uses the existing AI assessment and does not make another AI request.</p>
    {error && <p className="review-error" role="alert">{error}</p>}
    {state.status === 'loading' && !error && <p>Loading case record…</p>}
    {record && <div className="case-record-summary">
      <div><small>Case summary</small><p>{record.case_summary}</p></div>
      <div><small>AI assessment summary</small><p>{record.ai_summary || 'No live AI assessment is available for this case.'}</p>{record.ai_verdict && <span>{record.ai_verdict}{record.ai_decision && record.ai_decision !== 'pending' ? ` · analyst ${record.ai_decision}` : ' · analyst review pending'}</span>}</div>
      <div><small>Recommended steps reviewed</small><p>{record.approved_checks} approved · {record.rejected_checks} rejected · {record.total_checks} total</p></div>
    </div>}
    {state.status === 'waiting_for_review' && <p className="case-record-notice">Finish reviewing every recommendation before saving the case record.</p>}
    {state.status === 'ready' && <button type="button" className="case-record-save" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save summary to audit log'}</button>}
    {state.status === 'saved' && <div className="case-record-saved" role="status"><strong>Saved to audit log</strong><p>Record {state.event_id} · {state.saved_at?.slice(0, 16).replace('T', ' ')} UTC</p><button type="button" onClick={onAudit}>View audit log →</button></div>}
    {state.status === 'saved' && (
      <div className="case-resolution">
        <h3>Final Analyst Decision</h3>

        <p>
          The case record has been saved.
          Confirm the resolution to remove this case
          from the active Priority Queue.
        </p>

        <label htmlFor="resolution-reason">
          Resolution reason
        </label>

        <textarea
          id="resolution-reason"
          value={resolutionReason}
          onChange={(e) => setResolutionReason(e.target.value)}
          placeholder="Explain why the investigation can be considered resolved..."
          maxLength={1000}
          rows={3}
        />

        <label className="case-resolution-confirm">
          <input
            type="checkbox"
            checked={resolutionConfirmed}
            onChange={(e) => setResolutionConfirmed(e.target.checked)}
          />
          I have reviewed the evidence and explicitly authorize
          this case resolution.
        </label>

        <button
          type="button"
          className="case-record-save"
          disabled={
            resolving ||
            !resolutionConfirmed ||
            resolutionReason.trim().length < 10
          }
          onClick={resolve}
        >
          {resolving ? 'Resolving...' : 'Resolve Case'}
        </button>
      </div>
    )}

    {state.status === 'resolved' && (
      <div className="case-record-saved" role="status">
        <strong>Case Resolved</strong>
        <p>
          Resolution: {state.resolution?.reason}
        </p>
        <p>
          Resolved by: {state.resolution?.analyst_id}
        </p>
        <button type="button" onClick={onAudit}>
          View audit log →
        </button>
      </div>
    )}

  </section>;
}
