import React, { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import SelectField from './SelectField.jsx';
import Timeline, { attackReferences, ruleCriteria } from '../modules/timeline.jsx';
import { TriagePreview } from './WorkflowPreview.jsx';
import NextSteps from '../modules/recommendations.jsx';
import CaseRecord from './CaseRecord.jsx';
import data from '../real-alerts.json';
import timelineData from '../real-timelines.json';
import rawContextData from '../raw-context.json';
import RawFlowRecords from './RawFlowRecords.jsx';
import { apiFetch } from '../apiFetch.js';
import { PriorityBadge } from './ReviewPriority.jsx';
import { priorityRank } from '../lib/reviewPriority.js';

const shortTime = (value) => value?.replace('T', ' ').slice(0, 16) || '—';
const minuteOf = (value) => value?.slice(0, 16);
const formatRuleBasis = (value) => value?.replace(/\b\d{4,}\b/g, (number) => Number(number).toLocaleString('en-US'));
const aiVerdicts = new Set(['Likely Attack', 'Likely Benign', 'Needs Review']);
const caseSteps = ['Overview', 'Timeline', 'Recommendations', 'Triage report'];

function MinuteFlowDisclosure({ incidentId, minute, count }) {
  const [open, setOpen] = useState(false);
  return <details className="minute-flow-disclosure" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary><strong>{typeof count === 'number' ? `${count.toLocaleString()} communication records` : 'Communication records'}</strong><span>Raw flow evidence</span></summary>
    {open && <RawFlowRecords incidentId={incidentId} minute={minute} />}
  </details>;
}

function caseAssessment(incident, response) {
  if (!response) return { label: 'Checking…', tone: 'pending' };
  if (response.mode === 'mock' || response.status === 'not_configured') return { label: 'AI not configured', tone: 'pending' };
  if (response.status === 'unavailable') return { label: response.error?.code === 'EVIDENCE_INTEGRITY_FAILED' ? 'AI needs rerun' : 'AI unavailable', tone: 'unavailable' };
  if (response.status === 'running' || response.status === 'analysing') return { label: 'Analysing', tone: 'analysing' };
  if (response.status !== 'ready') return { label: 'AI not run', tone: 'pending' };
  const result = response.assessment;
  const evidence = new Set([...incident.alert_ids, ...incident.evidence_sample_ids]);
  if (!aiVerdicts.has(result?.verdict) || !Array.isArray(result.evidence_ids) || (result.verdict !== 'Needs Review' && !result.evidence_ids.some((id) => evidence.has(id)))) return { label: 'AI unavailable', tone: 'unavailable' };
  const tone = result.verdict === 'Likely Attack' ? 'attack' : result.verdict === 'Likely Benign' ? 'benign' : 'review';
  return { label: result.verdict, tone, confidence: typeof result.confidence === 'number' && result.confidence >= 0 && result.confidence <= 1 ? `${Math.round(result.confidence * 100)}%` : typeof result.confidence === 'string' ? result.confidence : null };
}

export default function AlertReview({ mode, selectedId, onSelectCase, onCases, onAudit, username }) {
  const [query, setQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [dateSort, setDateSort] = useState('priority');
  const [step, setStep] = useState(0);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [selectedMinute, setSelectedMinute] = useState(null);
  const [queue, setQueue] = useState(null);
  const [queueError, setQueueError] = useState('');
  const [assessments, setAssessments] = useState({});
  const [overviewAi, setOverviewAi] = useState({ status: 'loading' });
  const [autoAnalysis, setAutoAnalysis] = useState({ enabled: false, running: null, paused_reason: null });
  const [analysisError, setAnalysisError] = useState('');
  const [copiedId, setCopiedId] = useState(null);
  const evidenceRef = useRef(null);
  const incident = data.incidents.find((item) => item.incident_id === selectedId);
  const alerts = data.alerts.filter((item) => item.incident_id === selectedId);
  const flows = data.flows.filter((flow) => incident?.evidence_sample_ids.includes(flow.flow_id));
  const events = timelineData.timelines.find((item) => item.incident_id === selectedId)?.events || [];
  const evidence = [...alerts, ...flows].find((item) => (item.alert_id || item.flow_id) === selectedEvidence);
  const evidenceEvent = events.find((event) => event.evidence_id === selectedEvidence);
  const matchingAlerts = alerts.filter((alert) => minuteOf(alert.timestamp) === selectedMinute);

  useEffect(() => {
    setStep(0);
    setSelectedMinute(null);
    setSelectedEvidence(null);
  }, [selectedId]);

  useEffect(() => {
    if (mode === 'cases' || !incident) return;
    let active = true;
    const endpoint = `/api/cases/${encodeURIComponent(selectedId)}/ai-assessment`;
    let autoRequested = false;
    async function load() {
      try {
        const response = await fetch(endpoint);
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error?.message || payload.error || 'AI status unavailable');
        if (!active) return;
        setOverviewAi(payload);
        const stale = payload.error?.code === 'EVIDENCE_INTEGRITY_FAILED';
        if (!autoRequested && payload.mode !== 'mock' && (payload.status === 'pending' || stale)) {
          autoRequested = true;
          setOverviewAi({ status: 'running', mode: 'live' });
          apiFetch(`/api/cases/${encodeURIComponent(selectedId)}/auto-check`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
          }).then(async (reply) => {
            const next = await reply.json();
            if (!active) return;
            if (next.queued) autoRequested = false;
            setOverviewAi(next);
            if (!next.queued) window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: selectedId }));
          }).catch(() => { if (active) setOverviewAi({ status: 'unavailable', error: { message: 'Automatic check could not start. Retry from Overview.' } }); });
        }
      } catch (error) {
        if (active) setOverviewAi({ status: 'unavailable', error: error.message });
      }
    }
    setOverviewAi({ status: 'loading' });
    load();
    const refresh = (event) => { if (event.detail === selectedId) load(); };
    window.addEventListener('case-activity-updated', refresh);
    const poll = window.setInterval(load, 5000);
    return () => { active = false; window.clearInterval(poll); window.removeEventListener('case-activity-updated', refresh); };
  }, [mode, selectedId]);

  useEffect(() => {
    if (selectedEvidence) evidenceRef.current?.scrollIntoView({ block: 'nearest' });
  }, [selectedEvidence]);

  useEffect(() => {
    const refresh = (event) => {
      if (event.detail === selectedId) refreshQueue();
    };
    window.addEventListener('case-activity-updated', refresh);
    return () => window.removeEventListener('case-activity-updated', refresh);
  }, [selectedId]);

  useEffect(() => {
    let active = true;
    async function loadQueue() {
      try {
        const response = await fetch('/api/cases/queue');
        if (!response.ok) throw new Error('Case queue unavailable');
        const result = await response.json();
        if (active) { setQueue(result.cases); setQueueError(''); }
      } catch {
        if (active) setQueueError('Case status unavailable. Restart the local service.');
      }
    }
    loadQueue();
    const refresh = window.setInterval(loadQueue, 15000);
    return () => { active = false; window.clearInterval(refresh); };
  }, [mode, selectedId]);

  useEffect(() => {
    if (mode !== 'cases') return;
    let active = true;
    async function loadAuto() {
      try {
        const response = await fetch('/api/ai/auto-analysis');
        if (response.ok && active) setAutoAnalysis(await response.json());
      } catch { /* The case list remains usable while the API reconnects. */ }
    }
    async function loadAssessments() {
      const entries = await Promise.all(data.incidents.map(async (item) => {
        try {
          const response = await fetch(`/api/cases/${encodeURIComponent(item.incident_id)}/ai-assessment`);
          if (!response.ok) throw new Error('AI status unavailable');
          return [item.incident_id, await response.json()];
        } catch {
          return [item.incident_id, { status: 'unavailable' }];
        }
      }));
      if (active) setAssessments(Object.fromEntries(entries));
    }
    loadAssessments();
    loadAuto();
    const refresh = window.setInterval(() => { loadAssessments(); loadAuto(); }, 5000);
    return () => { active = false; window.clearInterval(refresh); };
  }, [mode]);

  useEffect(() => {
    if (mode === 'cases' || !selectedId) return;
    let active = true;
    async function loadAuto() {
      try {
        const response = await fetch('/api/ai/auto-analysis');
        if (response.ok && active) setAutoAnalysis(await response.json());
      } catch { /* Keep the case readable while reconnecting. */ }
    }
    loadAuto();
    const poll = window.setInterval(loadAuto, 5000);
    return () => { active = false; window.clearInterval(poll); };
  }, [mode, selectedId]);

  async function setAutomatic(enabled) {
    setAnalysisError('');
    try {
      const response = await apiFetch('/api/ai/auto-analysis', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not change automatic investigation.');
      setAutoAnalysis(result);
    } catch (error) { setAnalysisError(error.message); }
  }

  async function refreshQueue() {
    try {
      const response = await fetch('/api/cases/queue');
      if (!response.ok) throw new Error('Case status unavailable');
      const result = await response.json();
      setQueue(result.cases);
      setQueueError('');
    } catch (error) {
      setQueueError(error.message);
    }
  }

  function openEvidence(id) {
    const record = [...alerts, ...flows].find((item) => (item.alert_id || item.flow_id) === id);
    setSelectedMinute(record ? minuteOf(record.timestamp) : null);
    setSelectedEvidence(id);
    setStep(1);
  }

  async function copyEvidenceId() {
    if (!selectedEvidence || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(selectedEvidence);
      setCopiedId(selectedEvidence);
    } catch {
      setCopiedId(null);
    }
  }

  const aiMapping = overviewAi.assessment?.technique_mappings?.find((item) => item.evidence_id === selectedEvidence);
  const aiTechnique = aiMapping && Object.values(attackReferences).find((item) => item.id === aiMapping.technique_id);
  const evidencePanel = evidence && <div ref={evidenceRef} className="evidence-detail incident-record-detail" aria-live="polite">
    <header className="record-detail-header">
      <div className="record-detail-title"><span className="record-detail-icon"><Icon name="shield" size={18} /></span><div><strong>Record details</strong></div></div>
      <button className="record-detail-close" type="button" onClick={() => setSelectedEvidence(null)} aria-label="Close record details"><Icon name="close" size={18} /></button>
    </header>
    <div className="record-detail-route">
      <div className="record-detail-endpoint"><span>Source</span><strong>{evidence.source_ip || '—'}</strong>{evidence.source_port && <small>Port {evidence.source_port}</small>}</div>
      <span className="record-detail-arrow"><Icon name="arrow" size={20} /></span>
      <div className="record-detail-endpoint"><span>Destination</span><strong>{evidence.destination_ip || '—'}</strong>{evidence.destination_port && <small>Port {evidence.destination_port}</small>}</div>
    </div>
    <div className="record-detail-meta">
      <div><span>Recorded at</span><time>{shortTime(evidence.timestamp)} <small>dataset time</small></time></div>
      <div><span>Record ID</span><code>{selectedEvidence}</code></div>
    </div>
    <dl className="record-detail-findings">{evidence.rule_basis && <div><dt>Detection details</dt><dd>{formatRuleBasis(evidence.rule_basis)}</dd></div>}{evidence.type && ruleCriteria(evidence.type, data.rules) && <div><dt>Rule criteria</dt><dd>{ruleCriteria(evidence.type, data.rules)}</dd></div>}{aiMapping ? <div><dt>AI-suggested ATT&CK</dt><dd>{aiTechnique ? <a href={`https://attack.mitre.org/techniques/${aiTechnique.id}/`} target="_blank" rel="noopener noreferrer">{aiTechnique.id} · {aiTechnique.name}</a> : 'Unmapped'} · {aiMapping.reason}</dd></div> : <>{evidence.type === 'DoS' && <div><dt>ATT&CK mapping</dt><dd>Unmapped: flow and packet counts alone do not show network exhaustion or a service outage.</dd></div>}{evidence.type && attackReferences[evidence.type] && <div><dt>Rule-based ATT&CK hint</dt><dd><a href={`https://attack.mitre.org/techniques/${attackReferences[evidence.type].id}/`} target="_blank" rel="noopener noreferrer">{attackReferences[evidence.type].id} · {attackReferences[evidence.type].name}</a> · not a confirmed attack</dd></div>}{evidenceEvent?.technique && evidenceEvent.technique !== 'Unmapped' && !attackReferences[evidence.type] && <div><dt>Rule-based ATT&CK hint</dt><dd>{typeof evidenceEvent.technique === 'string' ? evidenceEvent.technique : `${evidenceEvent.technique.id} · ${evidenceEvent.technique.name}`}</dd></div>}</>}</dl>
    <footer className="record-detail-footer"><button type="button" className="incident-copy-id" onClick={copyEvidenceId}>{copiedId === selectedEvidence && <Icon name="check" size={14} />}{copiedId === selectedEvidence ? 'Copied ID' : 'Copy record ID'}</button></footer>
  </div>;


const filteredCases = data.incidents
  .filter((item) => {
    const ai = caseAssessment(
      item,
      assessments[item.incident_id]
    );

    const matchesVerdict =
      verdictFilter === 'all' ||
      (verdictFilter === 'Not Assessed'
        ? !aiVerdicts.has(ai.label)
        : ai.label === verdictFilter);

    const matchesQuery = !query.trim() || `${item.type} ${item.incident_id} ${item.source_ip} ${item.destination_ip} ${data.alerts.find((alert) => alert.incident_id === item.incident_id)?.rule_basis || ''}`.toLowerCase().includes(query.trim().toLowerCase());
    return matchesVerdict && matchesQuery;
  })
  .sort((a, b) => {
    const aTime = Date.parse(a.window_start);
    const bTime = Date.parse(b.window_start);

    if (dateSort === 'priority') return priorityRank(queue?.[b.incident_id]?.review_priority) - priorityRank(queue?.[a.incident_id]?.review_priority) || bTime - aTime;
    return dateSort === 'newest'
      ? bTime - aTime
      : aTime - bTime;
  });

  if (mode === 'cases' || !incident) return <section className="iris-cases-page"><header className="case-list-heading"><div className="case-list-title"><h1>Investigations</h1><span className="case-results-count" role="status">{filteredCases.length} {filteredCases.length === 1 ? 'case' : 'cases'}</span></div><label className="case-auto-switch case-auto-toggle" title="Investigate pending cases one at a time. Your review and approval remain required."><span>Background AI analysis</span><span className="case-auto-track"><input type="checkbox" role="switch" aria-label="Investigate pending cases in the background" checked={autoAnalysis.enabled} onChange={(event) => setAutomatic(event.target.checked)} /><span aria-hidden="true" /></span></label></header>{queueError && <p className="case-queue-error" role="status">{queueError}</p>}
{(autoAnalysis.running || autoAnalysis.paused_reason) && <p className="case-auto-status" role="status">{autoAnalysis.running ? `Investigating ${autoAnalysis.running}…` : `Paused: ${autoAnalysis.paused_reason}`}</p>}
{analysisError && <p className="case-queue-error" role="alert">{analysisError}</p>}


<div className="investigation-filters">
  <label className="case-search"><span>Search cases</span><input type="search" placeholder="Search by IP, type or case ID" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
  <SelectField label="AI result" value={verdictFilter} onChange={setVerdictFilter} options={[{ value: 'all', label: 'All results' }, { value: 'Likely Attack', label: 'Likely Attack' }, { value: 'Likely Benign', label: 'Likely Benign' }, { value: 'Needs Review', label: 'Needs Review' }, { value: 'Not Assessed', label: 'Not completed' }]} />
  <SelectField label="Sort by" value={dateSort} onChange={setDateSort} options={[{ value: 'priority', label: 'Review priority' }, { value: 'newest', label: 'Newest first' }, { value: 'oldest', label: 'Oldest first' }]} />
</div>
<div className="iris-cases-table">
  <div className="iris-cases-columns"><span>Case</span><span>Review priority</span><span>First seen</span><span>Why flagged</span><span>AI result</span><span>Actions</span></div>
  {filteredCases.map((item) => {
    const caseAlerts = data.alerts.filter((alert) => alert.incident_id === item.incident_id);
    const state = queue?.[item.incident_id];
    const ai = caseAssessment(item, assessments[item.incident_id]);
    return <div className="iris-cases-row" key={item.incident_id}>
      <span className="case-queue-name"><strong className="case-stable-id">{item.incident_id}</strong><span className="case-addresses">{item.source_ip} → {item.destination_ip}</span></span>
      <span className="case-review-priority"><PriorityBadge priority={state?.review_priority} /></span>
      <time>{shortTime(item.window_start)}</time>
      <span className="case-list-reason">{formatRuleBasis(caseAlerts[0]?.rule_basis) || 'Rule details unavailable'}</span>
      <span className="case-list-review"><span className={`case-ai-assessment ${autoAnalysis.running === item.incident_id ? 'analysing' : ai.tone}`}>{autoAnalysis.running === item.incident_id ? 'Analysing' : ai.label}</span>{state?.case_status === 'Resolved' && <span className="case-queue-status">Resolved</span>}</span>
      <span className="case-open-action"><button type="button" className="case-view" onClick={() => onSelectCase(item.incident_id)} aria-label={`Open case ${item.incident_id}`}>View case <Icon name="arrow" size={16} /></button></span>
    </div>;
  })}
  {filteredCases.length === 0 && <div className="case-list-empty"><strong>No matching cases</strong><p>Try another search or clear the filters.</p><button type="button" onClick={() => { setQuery(''); setVerdictFilter('all'); }}>Clear filters</button></div>}
</div></section>;

  const evidenceContent = <div className="case-minute-evidence">
    {matchingAlerts.map((alert) => <section className="case-minute-reason" key={alert.alert_id}>
      <strong>Why flagged</strong><p>{formatRuleBasis(alert.rule_basis) || 'Rule details unavailable.'}</p>
      <div className="minute-rule-details"><h4>Rule details</h4><dl>
        <div><dt>Source → destination</dt><dd>{alert.source_ip} → {alert.destination_ip}</dd></div>
        <div><dt>Recorded at</dt><dd>{shortTime(alert.timestamp)} · dataset time</dd></div>
        <div><dt>Evidence ID</dt><dd><button type="button" onClick={() => openEvidence(alert.alert_id)}>{alert.alert_id}</button></dd></div>
        <div><dt>Rule criteria</dt><dd>{ruleCriteria(alert.type, data.rules) || 'Not recorded'}</dd></div>
        {attackReferences[alert.type] && <div><dt>ATT&CK hint</dt><dd><a href={`https://attack.mitre.org/techniques/${attackReferences[alert.type].id}/`} target="_blank" rel="noopener noreferrer">{attackReferences[alert.type].id} · {attackReferences[alert.type].name}</a> · not a confirmed attack</dd></div>}
        {alert.type === 'DoS' && <div><dt>ATT&CK mapping</dt><dd>Unmapped · service impact is not established by flow counts.</dd></div>}
      </dl></div>{selectedEvidence === alert.alert_id && <div className="incident-evidence-list">{evidencePanel}</div>}
    </section>)}
    {overviewAi.status === 'ready' && overviewAi.assessment?.findings?.some((finding) => (finding.evidence_ids || []).some((id) => [...matchingAlerts, ...flows.filter((flow) => minuteOf(flow.timestamp) === selectedMinute)].some((item) => (item.alert_id || item.flow_id) === id))) && <details className="case-minute-ai"><summary>AI findings for this minute</summary>{overviewAi.assessment.findings.filter((finding) => (finding.evidence_ids || []).some((id) => [...matchingAlerts, ...flows.filter((flow) => minuteOf(flow.timestamp) === selectedMinute)].some((item) => (item.alert_id || item.flow_id) === id))).map((finding, index) => <div key={`ai-${index}`}><p>{finding.observation}</p>{(finding.evidence_ids || []).map((id) => <button type="button" key={id} onClick={() => openEvidence(id)}>{id}</button>)}</div>)}</details>}
    {selectedEvidence?.startsWith('FLOW-') && <div className="incident-evidence-list">{evidencePanel}</div>}
    <MinuteFlowDisclosure key={`${incident.incident_id}:${selectedMinute}`} incidentId={incident.incident_id} minute={selectedMinute} count={rawContextData.cases[incident.incident_id]?.minutes?.find((item) => item.minute === selectedMinute)?.flows} />
  </div>;
  return <div className="iris-review incident-page">
    <header className="iris-case-header incident-header">
      <div className="incident-header-main"><div><button type="button" className="incident-back" onClick={onCases} aria-label="Back to cases" title="Back to cases"><span aria-hidden="true">‹</span></button><h1>Case <small className="case-stable-id">{incident.incident_id}</small></h1></div></div>
    </header>

    <div className="case-detail-workspace incident-workbench">
      <nav className="iris-case-tabs" aria-label="Case sections">{caseSteps.map((label, index) => <button type="button" key={label} className={step === index ? 'selected' : ''} aria-current={step === index ? 'page' : undefined} onClick={() => setStep(index)}>{label}</button>)}</nav>
      <div className="incident-primary">
        {step === 0 && <section className="incident-section incident-overview" aria-labelledby="incident-overview-title">
          <div className="incident-section-heading"><h2 id="incident-overview-title">Overview</h2><p className="case-step-purpose">Review the case signal and AI investigation before examining the timeline.</p></div>
          <dl className="overview-snapshot">
            <div className="overview-snapshot-route"><dt>Communication path</dt><dd><span>{incident.source_ip}</span><Icon name="arrow" size={16} /><span>{incident.destination_ip}</span></dd></div>
            <div className="overview-snapshot-time"><dt>Observed</dt><dd>{shortTime(incident.window_start)} – {shortTime(incident.window_end)}</dd></div>
            <div className="overview-snapshot-metric"><dt>Alerts</dt><dd>{alerts.length}</dd></div>
            <div className="overview-snapshot-metric"><dt>Matched flow records</dt><dd>{incident.flow_count.toLocaleString()}</dd></div>
          </dl>
          <section className="overview-trigger" aria-label="Why flagged"><span className="overview-trigger-icon"><Icon name="alert" size={18} /></span><div><h3>Why flagged</h3><p>{formatRuleBasis(alerts[0]?.rule_basis) || 'No rule basis available.'}</p></div></section>
          <div className="incident-overview-ai" aria-live="polite">
            <TriagePreview incidentId={incident.incident_id} alerts={alerts} flows={flows} onEvidence={openEvidence} onRecommendations={() => setStep(2)} analystName={username} autoRunning={autoAnalysis.running === incident.incident_id || overviewAi.status === 'running'} refreshToken={`${overviewAi.status}:${overviewAi.run_id || ''}`} />
          </div>
        </section>}
        {step === 1 && <section className="incident-section" aria-labelledby="incident-timeline"><Timeline incident={incident} alerts={alerts} rawContext={rawContextData.cases[incident.incident_id]} selectedMinute={selectedMinute} evidenceContent={evidenceContent} onSelectMinute={(minute) => { setSelectedMinute(minute); setSelectedEvidence(null); }} />{overviewAi.status === 'ready' && overviewAi.assessment?.findings?.length > 0 && <details className="timeline-ai-findings"><summary>AI findings · {overviewAi.assessment.findings.length}</summary><ul>{overviewAi.assessment.findings.map((finding, index) => <li key={index}>{finding.observation}{(finding.evidence_ids || []).map((id) => <button type="button" key={id} onClick={() => openEvidence(id)}>{id}</button>)}</li>)}</ul></details>}</section>}
        {step === 2 && <section className="incident-section incident-step-panel" aria-labelledby="incident-recommendations"><div className="incident-section-heading"><h2 id="incident-recommendations">Recommendations</h2><p className="case-step-purpose">Choose which suggested investigation steps a person should carry out next.</p></div><NextSteps incidentId={incident.incident_id} analystName={username} onEvidence={openEvidence} onTimeline={() => setStep(1)} onReviewed={refreshQueue} onOverview={() => setStep(0)} onCaseRecord={() => setStep(3)} /></section>}
        {step === 3 && <section className="incident-section incident-step-panel"><CaseRecord incidentId={incident.incident_id} incident={incident} alerts={alerts} flows={flows} criteria={ruleCriteria(incident.type, data.rules)} analystName={username} onAudit={onAudit} onRecommendations={() => setStep(2)} onAiCheck={() => setStep(0)} onEvidence={openEvidence} /></section>}
        <nav className="case-footer-nav" aria-label="Move between case sections">
          {step > 0 && <button type="button" className="case-footer-back" onClick={() => setStep(step - 1)}><span className="case-footer-back-icon"><Icon name="arrow" size={16} /></span>{caseSteps[step - 1]}</button>}
          <span className="case-footer-position">{step + 1} of {caseSteps.length}</span>
          <button type="button" className="case-footer-next" onClick={step === caseSteps.length - 1 ? onCases : () => setStep(step + 1)}>{step === caseSteps.length - 1 ? 'Back to cases' : `Next: ${caseSteps[step + 1]}`}<Icon name="arrow" size={16} /></button>
        </nav>
      </div>
    </div>
  </div>;
}
