import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from './Icon.jsx';
import { AssessmentReview } from './WorkflowPreview.jsx';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/record`;

const reportTime = (value) => !value ? 'Not recorded' : /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? `${new Date(value).toISOString().slice(0, 19).replace('T', ' ')} UTC` : `${value.slice(0, 19).replace('T', ' ')} (dataset time)`;
const caseTimeRange = (start, end) => !start || !end ? 'Not recorded' : start.slice(0, 10) === end.slice(0, 10)
  ? `${start.slice(0, 10)} · ${start.slice(11, 16)}–${end.slice(11, 16)}`
  : `${start.slice(0, 16).replace('T', ' ')} – ${end.slice(0, 16).replace('T', ' ')}`;

export default function CaseRecord({ incidentId, incident, alerts = [], flows = [], criteria, analystName, onAudit, onRecommendations, onAiCheck, onEvidence }) {
  const [state, setState] = useState({ status: 'loading', record: null });
  const [details, setDetails] = useState({});
  useEffect(() => {
    let active = true;
    setDetails({});
    for (const part of ['recommendations', 'ai-assessment', 'audit']) {
      fetch(`/api/cases/${encodeURIComponent(incidentId)}/${part}`).then(async (response) => {
        if (!response.ok) throw new Error('Unavailable');
        return response.json();
      }).then((value) => { if (active) setDetails((previous) => ({ ...previous, [part]: value })); })
        .catch(() => { if (active) setDetails((previous) => ({ ...previous, [part]: { unavailable: true } })); });
    }
    return () => { active = false; };
  }, [incidentId]);
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
        if (!response.ok) throw new Error(result.error || 'Triage report unavailable');
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
      if (!response.ok) throw new Error(result.error || 'Could not save report');
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
  const activity = record?.activity
    ? record.activity.map((event) => ({ ...event.payload, time: event.ts, action: event.event, actor: event.actor }))
    : details.audit?.events || [];
  const currentAi = state.status === 'ready' ? details['ai-assessment'] || {} : {};
  const review = record?.analyst_review || currentAi.decision || {};
  const trace = record?.ai_investigation || currentAi.investigation;
  const metadata = record?.ai_run_metadata || currentAi.run_metadata || {};
  const plan = record?.investigation_steps || (details.recommendations?.checks || []).map((step) => ({
    ...step, decision: details.recommendations?.decisions?.[step.id],
    events: activity.filter((event) => event.recommendation_id === step.id).map((event) => ({ ...event, event: event.action, ts: event.time, payload: event })),
  }));
  const evidenceLinks = (ids) => <div className="report-evidence-links">{ids?.length ? ids.map((id) => <button type="button" key={id} onClick={() => onEvidence?.(id)}>{id}</button>) : <span>Not recorded</span>}</div>;
  const toolNames = { get_incident_details: 'Read case details', get_related_alerts: 'Inspect related alerts', get_network_flows: 'Inspect flow evidence', get_incident_statistics: 'Check traffic statistics' };
  return <section className="case-record" aria-live="polite">
    <div className="incident-section-heading"><h2>Triage report</h2><p className="case-step-purpose">Review and save your triage findings.</p></div>
    {error && <p className="review-error" role="alert">{error}</p>}
    {state.status === 'loading' && !error && <p>Loading triage report…</p>}
    {record && <article className="case-report" aria-label="Case triage report">
      <section className="case-report-panel case-report-assessment"><h3>Triage assessment</h3>{record.ai_summary ? <><dl className="case-report-facts"><div><dt>AI verdict</dt><dd>{record.ai_verdict}</dd></div></dl><p>{record.ai_summary}</p></> : <div className="case-report-empty"><strong>AI investigation not complete</strong><p>{record.ai_status === 'unavailable' ? record.ai_error || 'The provider was unavailable.' : record.ai_status === 'not_configured' ? 'AI provider is not connected.' : 'No AI result is recorded for this case.'}</p>{state.status === 'ready' && <button type="button" onClick={onAiCheck}>Open Overview →</button>}</div>}
        {record.ai_summary && <details className="case-report-appendix"><summary>Supporting evidence</summary>{evidenceLinks(record.ai_evidence_ids || currentAi.assessment?.evidence_ids || [])}{!!record.ai_mappings?.length && record.ai_mappings.map((mapping, index) => <p key={index}>{mapping.technique_id} · {mapping.reason}</p>)}</details>}
<div className="report-analyst-review">{state.status === 'ready' && currentAi.assessment && record.ai_summary ? <AssessmentReview incidentId={incidentId} analystName={analystName} result={currentAi.assessment} initialDecision={currentAi.decision} onSaved={async () => {
          const [recordResponse, auditResponse, aiResponse] = await Promise.all([fetch(endpoint(incidentId)), fetch(`/api/cases/${encodeURIComponent(incidentId)}/audit`), fetch(`/api/cases/${encodeURIComponent(incidentId)}/ai-assessment`)]);
          if (recordResponse.ok) setState(await recordResponse.json());
          if (auditResponse.ok) { const audit = await auditResponse.json(); setDetails((previous) => ({ ...previous, audit })); }
          if (aiResponse.ok) { const ai = await aiResponse.json(); setDetails((previous) => ({ ...previous, 'ai-assessment': ai })); }
        }} /> : <><h4>Analyst review</h4><dl className="case-report-facts"><div><dt>Analyst</dt><dd>{review.analyst || 'Not reviewed'}</dd></div><div><dt>Decision / time</dt><dd>{review.status || 'Awaiting review'} · {reportTime(review.at)}</dd></div></dl>{review.note && <p>{review.note}</p>}</>}</div><details className="case-report-appendix report-ai-activity"><summary>AI activity and validation</summary>
        <dl className="case-report-facts"><div><dt>Run ID</dt><dd>{record.ai_run_id || 'Not recorded'}</dd></div><div><dt>Performed by</dt><dd>{trace ? 'AI agent · read-only tools' : 'No AI check recorded'}</dd></div><div><dt>Started / completed</dt><dd>{reportTime(metadata.started_at)} / {reportTime(metadata.completed_at)}</dd></div><div><dt>Evidence validation</dt><dd>{record.ai_validation?.ok === true ? 'Passed' : record.ai_validation?.ok === false ? 'Failed' : 'Not recorded'}</dd></div><div><dt>Duration</dt><dd>{typeof metadata.duration_ms === 'number' ? `${(metadata.duration_ms / 1000).toFixed(2)} seconds` : 'Not recorded'}</dd></div></dl>
        {!!trace?.tool_calls?.length && <ol className="case-report-tool-list">{trace.tool_calls.map((call, index) => <li key={index}><span>{toolNames[call.tool] || call.tool}</span><span>{call.ok ? 'Completed' : call.blocked ? 'Blocked' : 'Failed'}{typeof call.result_count === 'number' ? ` · ${call.result_count} records` : ''}</span></li>)}</ol>}
        {!!record.ai_findings?.length && <details className="case-report-appendix"><summary>Detailed findings</summary>{record.ai_findings.map((finding, index) => <div key={index}><p>{finding.observation}</p>{evidenceLinks(finding.evidence_ids)}</div>)}</details>}
        {record.ai_limitations && <p><strong>Limitations</strong><br />{record.ai_limitations}</p>}
      </details>
      </section>
      <section className="case-report-panel case-report-plan"><h3>Investigation plan</h3><p className="report-plan-counts">{plan.filter((step) => step.decision === 'approved').length} approved · {plan.filter((step) => step.decision === 'rejected').length} rejected · {plan.filter((step) => !step.decision).length} awaiting review</p>
        <div className="case-report-table-wrap"><table><thead><tr><th>Step</th><th>Review</th><th>Execution</th></tr></thead><tbody>{plan.map((step) => {
          const completed = [...(step.events || [])].reverse().find((event) => event.event === 'INVESTIGATION_STEP_COMPLETED');
          const reviewed = [...(step.events || [])].reverse().find((event) => ['APPROVED', 'REJECTED'].includes(event.payload?.decision));
          return <tr key={step.id}><td>{step.text}</td><td>{step.decision || 'Not reviewed'}{reviewed && <small>{reviewed.actor} · {reportTime(reviewed.ts)}</small>}</td><td>{completed ? <><strong>Completed</strong><small>{completed.actor} · {reportTime(completed.ts)}</small>{completed.payload?.note && <p>{completed.payload.note}</p>}</> : step.decision === 'approved' ? 'Pending completion' : '—'}</td></tr>;
        })}</tbody></table></div>
        {plan.length === 0 && <p>No steps available.</p>}
        {state.status === 'ready' && <button type="button" onClick={onRecommendations}>Review next steps →</button>}
      </section>
      <section className="case-report-panel case-report-source"><h3>Case and evidence</h3><div className="case-report-source-grid">
        <section className="case-report-panel"><h3>Case details</h3><p className="case-report-summary">{record.case_summary}</p><dl className="case-report-facts">
          <div><dt>Rule signal</dt><dd>{incident?.type || 'Unavailable'}</dd></div><div><dt>Recorded review priority</dt><dd>{record.review_priority?.level || 'Not recorded'}{record.review_priority?.source === 'analyst' ? ` · set by ${record.review_priority.analyst}` : record.review_priority ? ' · rule suggestion' : ''}</dd></div>
          <div><dt>Source → destination</dt><dd>{incident?.source_ip || '—'} → {incident?.destination_ip || '—'}</dd></div><div><dt>Time range</dt><dd>{caseTimeRange(incident?.window_start, incident?.window_end)}</dd></div>
        </dl></section>
        <section className="case-report-panel"><h3>Detection and evidence</h3><div className="case-report-metrics"><div><strong>{alerts.length}</strong><span>alerts</span></div><div><strong>{incident?.flow_count?.toLocaleString() ?? '—'}</strong><span>matched flows</span></div><div><strong>{flows.length}</strong><span>samples</span></div></div>{criteria && <details className="case-report-appendix"><summary>Rule criteria</summary><p>{criteria}</p></details>}
          <details className="case-report-appendix"><summary>Alert evidence · {alerts.length}</summary><div className="case-report-table-wrap"><table><thead><tr><th>Time (dataset clock)</th><th>Alert / evidence</th><th>Rule match</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.alert_id}><td>{reportTime(alert.timestamp)}</td><td><button type="button" onClick={() => onEvidence?.(alert.alert_id)}>{alert.alert_id}</button></td><td>{alert.rule_basis || 'Not recorded'}</td></tr>)}</tbody></table></div></details>
          <details className="case-report-appendix"><summary>Sample flow appendix · {flows.length} records</summary><p>Samples represent part of the matched traffic.</p><div className="case-report-table-wrap"><table><thead><tr><th>Evidence ID</th><th>Time</th><th>Destination port</th><th>Packets</th></tr></thead><tbody>{flows.map((flow) => <tr key={flow.flow_id}><td><button type="button" onClick={() => onEvidence?.(flow.flow_id)}>{flow.flow_id}</button></td><td>{reportTime(flow.timestamp)}</td><td>{flow.destination_port ?? '—'}</td><td>{flow.packet_count ?? '—'}</td></tr>)}</tbody></table></div></details>
        </section>
      </div></section>
      <section className="case-report-panel case-report-activity"><h3>Record and activity</h3>{state.event_id && <dl className="case-report-facts"><div><dt>Record ID</dt><dd>{state.event_id}</dd></div><div><dt>Saved at</dt><dd>{reportTime(state.saved_at)}</dd></div></dl>}
        {state.resolution && <p>Resolution: {state.resolution.reason} · {state.resolution.analyst_id} · {reportTime(state.resolved_at)}</p>}
        <p className="report-activity-count">{activity.length} recorded events · {state.status === 'saved' ? 'Saved report' : 'Unsaved report'}</p>
        {activity.length > 0 ? <ol className="report-recent-activity">{activity.slice(-3).reverse().map((event, index) => <li key={index}><strong>{event.action?.replaceAll(/[._]/g, ' ')}</strong><span>{event.actor || event.analyst_id || 'System'} · {reportTime(event.time)}</span></li>)}</ol> : <p>No activity recorded.</p>}
        <details className="case-report-appendix"><summary>{record.activity && state.status !== 'ready' ? 'Activity at report save' : 'Current activity trail'}</summary>{!details.audit ? <p>Loading activity…</p> : details.audit.unavailable ? <p>Activity unavailable.</p> : <ol>{activity.map((event, index) => <li key={index}><time>{reportTime(event.time)}</time> · {event.action?.replaceAll(/[._]/g, ' ')} · {event.actor || event.analyst_id || 'System'}{(event.note || event.tool || event.decision || event.error_code) && <p>{event.note || [event.tool, event.decision, event.error_code].filter(Boolean).join(' · ')}</p>}</li>)}</ol>}</details>
      </section>
    </article>}
    {state.status === 'ready' && <div className="case-record-save-area"><p>Saving a report does not resolve the case.</p><button type="button" className="case-record-save" disabled={saving} onClick={save}><Icon name="save" size={16} /> {saving ? 'Saving…' : 'Save report'}</button></div>}
    {state.status === 'saved' && <div className="case-record-saved" role="status"><strong>Report saved</strong><p>Record {state.event_id} · {state.saved_at?.slice(0, 16).replace('T', ' ')} UTC</p><button type="button" onClick={onAudit}>View audit log →</button></div>}
    {state.status === 'saved' && (
      <div className="case-resolution">
        <h3>Resolve this case</h3>

        <p>
          The triage report has been saved.
          Resolve only when your investigation is finished. This removes the case
          from the active review queue and records your reason. It does not block traffic or remediate a host.
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
