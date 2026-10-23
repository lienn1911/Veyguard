import React, { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import Timeline, { attackReferences, ruleCriteria } from '../modules/timeline.jsx';
import { TriagePreview } from './WorkflowPreview.jsx';
import NextSteps from '../modules/recommendations.jsx';
import CaseNotes from './CaseNotes.jsx';
import CaseAuditSummary from './CaseAuditSummary.jsx';
import CaseRecord from './CaseRecord.jsx';
import data from '../real-alerts.json';
import timelineData from '../real-timelines.json';
import { formatConfidence } from '../lib/format.js';

const shortTime = (value) => value?.replace('T', ' ').slice(0, 16) || '—';
const minuteOf = (value) => value?.slice(0, 16);
const formatRuleBasis = (value) => value?.replace(/\b\d{4,}\b/g, (number) => Number(number).toLocaleString('en-US'));
const caseName = (type) => type === 'PortScan' ? 'Many ports checked' : type === 'BruteForce' ? 'Repeated login-port connections' : type === 'DDoS' ? 'Distributed traffic surge' : type === 'DoS' ? 'Heavy network traffic' : type === 'NeedsReview' ? 'Unclassified activity · needs review' : type || 'Unclassified activity';
const aiVerdicts = new Set(['Likely Attack', 'Likely Benign', 'Needs Review']);
const caseSteps = ['Overview', 'Timeline', 'Evidence', 'AI check', 'Recommendations', 'Case record'];
const StepArrow = ({ back = false }) => <span className={`case-step-arrow${back ? ' back' : ''}`} aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12h15m-6-6 6 6-6 6" /></svg></span>;

function caseAssessment(incident, response) {
  if (!response) return { label: 'Checking…', tone: 'pending' };
  if (response.mode === 'mock' || response.status === 'not_configured') return { label: 'Not configured', tone: 'pending' };
  if (response.status === 'unavailable') return { label: 'Unavailable', tone: 'unavailable' };
  if (response.status === 'running' || response.status === 'analysing') return { label: 'Analysing', tone: 'analysing' };
  if (response.status !== 'ready') return { label: 'Not run', tone: 'pending' };
  const result = response.assessment;
  const evidence = new Set([...incident.alert_ids, ...incident.evidence_sample_ids]);
  if (!aiVerdicts.has(result?.verdict) || !Array.isArray(result.evidence_ids) || !result.evidence_ids.some((id) => evidence.has(id))) return { label: 'Unavailable', tone: 'unavailable' };
  const tone = result.verdict === 'Likely Attack' ? 'attack' : result.verdict === 'Likely Benign' ? 'benign' : 'review';
  return { label: result.verdict, tone, confidence: typeof result.confidence === 'number' && result.confidence >= 0 && result.confidence <= 1 ? `${Math.round(result.confidence * 100)}%` : typeof result.confidence === 'string' ? result.confidence : null };
}

export default function AlertReview({ mode, selectedId, onSelectCase, onCases, onAudit, username }) {
  const [query, setQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [dateSort, setDateSort] = useState('newest');
  const [step, setStep] = useState(0);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [selectedMinute, setSelectedMinute] = useState(null);
  const [evidenceTab, setEvidenceTab] = useState('alerts');
  const [queue, setQueue] = useState(null);
  const [queueError, setQueueError] = useState('');
  const [assessments, setAssessments] = useState({});
  const [overviewAi, setOverviewAi] = useState({ status: 'loading' });
  const [activityRefresh, setActivityRefresh] = useState(0);
  const [copiedId, setCopiedId] = useState(null);
  const evidenceRef = useRef(null);
  const incident = data.incidents.find((item) => item.incident_id === selectedId);
  const alerts = data.alerts.filter((item) => item.incident_id === selectedId);
  const flows = data.flows.filter((flow) => incident?.evidence_sample_ids.includes(flow.flow_id));
  const events = timelineData.timelines.find((item) => item.incident_id === selectedId)?.events || [];
  const evidence = [...alerts, ...flows].find((item) => (item.alert_id || item.flow_id) === selectedEvidence);
  const evidenceEvent = events.find((event) => event.evidence_id === selectedEvidence);
  const search = query.trim().toLowerCase();
  const matchingAlerts = alerts.filter((alert) => (!selectedMinute || minuteOf(alert.timestamp) === selectedMinute) && `${alert.timestamp} ${alert.type} ${alert.rule_basis} ${alert.alert_id}`.toLowerCase().includes(search));
  const matchingFlows = flows.filter((flow) => (!selectedMinute || minuteOf(flow.timestamp) === selectedMinute) && `${flow.timestamp} ${flow.source_ip} ${flow.destination_ip} ${flow.destination_port} ${flow.flow_id}`.toLowerCase().includes(search));

  useEffect(() => {
    setStep(0);
    setSelectedMinute(null);
    setSelectedEvidence(null);
    setEvidenceTab('alerts');
    setQuery('');
  }, [selectedId]);

  useEffect(() => {
    if (mode === 'cases' || !incident) return;
    let active = true;
    const endpoint = `/api/cases/${encodeURIComponent(selectedId)}/ai-assessment`;
    async function load() {
      try {
        const response = await fetch(endpoint);
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error?.message || payload.error || 'AI status unavailable');
        if (!active) return;
        setOverviewAi(payload);
      } catch (error) {
        if (active) setOverviewAi({ status: 'unavailable', error: error.message });
      }
    }
    setOverviewAi({ status: 'loading' });
    load();
    const refresh = (event) => { if (event.detail === selectedId) load(); };
    window.addEventListener('case-activity-updated', refresh);
    return () => { active = false; window.removeEventListener('case-activity-updated', refresh); };
  }, [mode, selectedId]);

  useEffect(() => {
    if (selectedEvidence) evidenceRef.current?.scrollIntoView({ block: 'nearest' });
  }, [selectedEvidence, evidenceTab]);

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
    const refresh = window.setInterval(loadAssessments, 15000);
    return () => { active = false; window.clearInterval(refresh); };
  }, [mode]);

  async function refreshQueue() {
    setActivityRefresh((value) => value + 1);
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
    setQuery('');
    setSelectedMinute(record ? minuteOf(record.timestamp) : null);
    setEvidenceTab(id?.startsWith('FLOW-') ? 'flows' : 'alerts');
    setSelectedEvidence(id);
    setStep(2);
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

  const evidencePanel = evidence && <div ref={evidenceRef} className="evidence-detail incident-record-detail" aria-live="polite">
    <div><strong>Record details</strong><button type="button" onClick={() => setSelectedEvidence(null)} aria-label="Close record details"><Icon name="close" size={18} /></button></div>
    <dl><dt>Time</dt><dd>{shortTime(evidence.timestamp)} UTC</dd><dt>From</dt><dd>{evidence.source_ip}{evidence.source_port ? `:${evidence.source_port}` : ''}</dd><dt>To</dt><dd>{evidence.destination_ip}{evidence.destination_port ? `:${evidence.destination_port}` : ''}</dd><dt>Record ID</dt><dd className="mono">{selectedEvidence}</dd>{evidence.rule_basis && <><dt>Detection details</dt><dd>{formatRuleBasis(evidence.rule_basis)}</dd></>}{evidence.type && ruleCriteria(evidence.type, data.rules) && <><dt>Rule criteria</dt><dd>{ruleCriteria(evidence.type, data.rules)}</dd></>}{evidence.type === 'DoS' && <><dt>ATT&CK mapping</dt><dd>Not assigned: flow and packet counts alone do not show network exhaustion or a service outage.</dd></>}{evidence.type && attackReferences[evidence.type] && <><dt>Possible ATT&CK behavior</dt><dd><a href={`https://attack.mitre.org/techniques/${attackReferences[evidence.type].id}/`} target="_blank" rel="noopener noreferrer">{attackReferences[evidence.type].id} · {attackReferences[evidence.type].name}</a> · not a confirmed attack</dd></>}{evidenceEvent?.technique && evidenceEvent.technique !== 'Unmapped' && !attackReferences[evidence.type] && <><dt>ATT&CK mapping</dt><dd>{typeof evidenceEvent.technique === 'string' ? evidenceEvent.technique : `${evidenceEvent.technique.id} · ${evidenceEvent.technique.name}`}</dd></>}</dl>
    <button type="button" className="incident-copy-id" onClick={copyEvidenceId}>{copiedId === selectedEvidence ? 'Copied ID' : 'Copy record ID'}</button>
  </div>;


const filteredCases = data.incidents
  .filter((item) => {
    const ai = caseAssessment(
      item,
      assessments[item.incident_id]
    );

    const caseStatus =
      queue?.[item.incident_id]?.case_status || 'Open';

    const matchesVerdict =
      verdictFilter === 'all' ||
      (verdictFilter === 'Not Assessed'
        ? !aiVerdicts.has(ai.label)
        : ai.label === verdictFilter);

    const matchesStatus =
      statusFilter === 'all' ||
      caseStatus === statusFilter;

    return matchesVerdict && matchesStatus;
  })
  .sort((a, b) => {
    const aTime = Date.parse(a.window_start);
    const bTime = Date.parse(b.window_start);

    return dateSort === 'newest'
      ? bTime - aTime
      : aTime - bTime;
  });

  if (mode === 'cases' || !incident) return <section className="iris-cases-page"><header><h1>Investigations</h1><p>{data.incidents.length} cases · {data.alerts.length} related alerts</p></header>{queueError && <p className="case-queue-error" role="status">{queueError}</p>}


<div className="investigation-filters">

  {/* 1. Sort by Date */}
  <select
    value={dateSort}
    onChange={(e) => setDateSort(e.target.value)}
    aria-label="Sort by detection date"
  >
    <option value="newest">Newest First</option>
    <option value="oldest">Oldest First</option>
  </select>

  {/* 2. AI Assessment */}
  <select
    value={verdictFilter}
    onChange={(e) => setVerdictFilter(e.target.value)}
    aria-label="Filter by AI assessment"
  >
    <option value="all">All Assessments</option>
    <option value="Likely Attack">Likely Attack</option>
    <option value="Likely Benign">Likely Benign</option>
    <option value="Needs Review">Needs Review</option>
    <option value="Not Assessed">Not Assessed</option>
  </select>

  {/* 3. Case Resolution */}
  <select
    value={statusFilter}
    onChange={(e) => setStatusFilter(e.target.value)}
    aria-label="Filter by case resolution"
  >
    <option value="all">All Cases</option>
    <option value="Open">Open Cases</option>
    <option value="Resolved">Resolved Cases</option>
  </select>

</div>

<div className="iris-cases-table">
  <div className="iris-cases-columns"><span>Case</span><span>First seen · UTC</span><span>Review status</span><span>AI assessment</span><span>AI confidence</span><span>Alerts</span></div>{filteredCases.map((item) => {
    const caseAlerts = data.alerts.filter((alert) => alert.incident_id === item.incident_id);
    const state = queue?.[item.incident_id];
    const ai = caseAssessment(item, assessments[item.incident_id]);
    return <button type="button" className="iris-cases-row" key={item.incident_id} onClick={() => onSelectCase(item.incident_id)}><span className="case-queue-name"><strong>{data.incidents.indexOf(item) + 1} <span>· {caseName(caseAlerts[0]?.type)}</span></strong><small>{item.source_ip} → {item.destination_ip}</small></span><time>{shortTime(item.window_start)}</time><span className="case-queue-status">{state?.status || (queueError ? 'Unavailable' : 'Loading…')}</span><span className={`case-ai-assessment ${ai.tone}`}><span className="case-ai-label">{ai.label}</span></span><span className="case-ai-confidence">{ai.confidence ? formatConfidence(ai.confidence) : '—'}</span><span className="case-alert-count">{caseAlerts.length} alerts</span></button>;
  })}</div></section>;

  const caseNumber = data.incidents.findIndex((item) => item.incident_id === incident.incident_id) + 1;
  const type = alerts[0]?.type || 'Unknown';
  const overviewAssessment = caseAssessment(incident, overviewAi);
  const overviewReady = overviewAi.status === 'ready' && ['attack', 'benign', 'review'].includes(overviewAssessment.tone);
  return <div className="iris-review incident-page">
    <header className="iris-case-header incident-header">
      <div className="incident-header-main"><div><button type="button" className="incident-back" onClick={onCases} aria-label="Back to Investigations" title="Back to Investigations"><Icon name="arrow" size={18} /></button><h1>Case #{caseNumber} · {caseName(type)}</h1></div><span className="iris-header-badge">{queue?.[selectedId]?.status || 'Status unavailable'}</span></div>
    </header>

    <div className="case-detail-workspace incident-workbench">
      <nav className="iris-case-tabs" aria-label="Case steps"><button type="button" onClick={onCases}><span className="case-step-dot" />Cases</button>{caseSteps.map((label, index) => <button type="button" key={label} className={`${step === index ? 'selected' : ''}${step > index ? ' complete' : ''}`} aria-current={step === index ? 'step' : undefined} onClick={() => setStep(index)}><span className="case-step-dot" />{label}</button>)}</nav>
      <div className="incident-primary">
        {step === 0 && <section className="incident-section incident-overview" aria-labelledby="incident-why">
          <div className="incident-section-heading"><h2 id="incident-why">Overview</h2></div>
          <div className="incident-overview-facts"><div><small>Alerts</small><strong>{alerts.length}</strong></div><div><small>Matched flow records</small><strong>{incident.flow_count.toLocaleString()}</strong></div><div><small>Source → destination</small><strong>{incident.source_ip} → {incident.destination_ip}</strong></div><div><small>Attack label</small><strong>{type}</strong></div></div>
          <h3><span className="incident-overview-heading-icon"><Icon name="flow" size={15} /></span>What happened</h3>
          <p>{caseName(type)}: the rule matched {alerts.length} {alerts.length === 1 ? 'time' : 'times'} between {shortTime(incident.window_start)} and {shortTime(incident.window_end)} UTC.</p>
          <h3><span className="incident-overview-heading-icon"><Icon name="alert" size={15} /></span>Why it was flagged</h3>
          <p>{formatRuleBasis(alerts[0]?.rule_basis) || 'No rule basis available.'}</p>
          <div className="incident-overview-ai" aria-live="polite">
            <div className="incident-overview-ai-head"><span className="incident-overview-heading-icon"><Icon name="shield" size={15} /></span><strong>AI assessment</strong></div>
            {overviewReady ? <><p className="incident-overview-ai-verdict">{overviewAssessment.label}{overviewAssessment.confidence && <small>{formatConfidence(overviewAssessment.confidence)}</small>}</p>{overviewAi.assessment.summary && <p>{overviewAi.assessment.summary}</p>}<small>AI suggestion · analyst review required</small></> : <p>{overviewAi.status === 'running' ? 'Checking the case evidence now…' : overviewAi.status === 'loading' ? 'Checking for an existing assessment…' : overviewAi.status === 'not_configured' || overviewAi.mode === 'mock' ? 'Connect a live AI provider in Settings to see an assessment.' : overviewAi.status === 'unavailable' ? (typeof overviewAi.error === 'string' ? overviewAi.error : 'AI result unavailable. Open AI check to retry.') : 'No AI assessment yet.'}</p>}
          </div>
        </section>}
        {step === 1 && <section className="incident-section" aria-labelledby="incident-timeline"><div className="incident-section-heading"><h2 id="incident-timeline">Timeline</h2></div><Timeline incident={incident} events={events} alerts={alerts} selectedMinute={selectedMinute} onEvidence={openEvidence} onSelectMinute={(minute) => { setSelectedMinute(minute); setSelectedEvidence(null); setQuery(''); setStep(2); }} /></section>}
        {step === 2 && <section className="incident-section incident-evidence" aria-labelledby="incident-evidence-heading"><div className="incident-section-heading"><h2 id="incident-evidence-heading">Evidence</h2></div>
          <div className="incident-evidence-toolbar"><div>{selectedMinute ? <><strong>{shortTime(selectedMinute)} UTC</strong><button type="button" onClick={() => { setSelectedMinute(null); setSelectedEvidence(null); }}>All minutes</button></> : <strong>All alert minutes</strong>}</div><div className="incident-evidence-search"><span className="incident-evidence-search-icon"><Icon name="search" size={16} /></span><input aria-label="Search case evidence" placeholder="Search record ID, IP, or rule…" value={query} onChange={(event) => setQuery(event.target.value)} /></div></div>
          <div className="incident-evidence-tabs" role="tablist" aria-label="Evidence type"><button type="button" role="tab" aria-selected={evidenceTab === 'alerts'} className={evidenceTab === 'alerts' ? 'active' : ''} onClick={() => setEvidenceTab('alerts')}>Alerts <span>{matchingAlerts.length}</span></button><button type="button" role="tab" aria-selected={evidenceTab === 'flows'} className={evidenceTab === 'flows' ? 'active' : ''} onClick={() => setEvidenceTab('flows')}>Sample flows <span>{matchingFlows.length}</span></button></div>
          <div className="incident-evidence-list">{evidenceTab === 'alerts' ? matchingAlerts.map((alert) => <React.Fragment key={alert.alert_id}><button type="button" className={`incident-evidence-row${selectedEvidence === alert.alert_id ? ' selected' : ''}`} onClick={() => setSelectedEvidence(selectedEvidence === alert.alert_id ? null : alert.alert_id)} aria-expanded={selectedEvidence === alert.alert_id}><span className={`alert-type-chip ${alert.type.toLowerCase()}`}>{alert.type}</span><span><strong>{alert.alert_id}</strong><small>{shortTime(alert.timestamp)} UTC · {alert.flow_count.toLocaleString()} flow records</small></span><Icon name="arrow" size={15} /></button>{selectedEvidence === alert.alert_id && evidencePanel}</React.Fragment>) : matchingFlows.map((flow) => <React.Fragment key={flow.flow_id}><button type="button" className={`incident-evidence-row${selectedEvidence === flow.flow_id ? ' selected' : ''}`} onClick={() => setSelectedEvidence(selectedEvidence === flow.flow_id ? null : flow.flow_id)} aria-expanded={selectedEvidence === flow.flow_id}><span className="flow-symbol"><Icon name="flow" size={16} /></span><span><strong className="mono">{flow.flow_id}</strong><small>{shortTime(flow.timestamp)} UTC · {flow.source_ip}:{flow.source_port} → {flow.destination_ip}:{flow.destination_port}</small></span><Icon name="arrow" size={15} /></button>{selectedEvidence === flow.flow_id && evidencePanel}</React.Fragment>)}{(evidenceTab === 'alerts' ? matchingAlerts.length : matchingFlows.length) === 0 && <p className="incident-evidence-empty">No matching records in this view.</p>}</div>
        </section>}
        {step === 2 && <CaseNotes incidentId={incident.incident_id} username={username} evidenceIds={[...incident.alert_ids, ...incident.evidence_sample_ids]} onEvidence={openEvidence} />}
        {step === 3 && <section className="incident-section incident-step-panel" aria-label="AI check"><CaseAuditSummary incidentId={incident.incident_id} refreshToken={activityRefresh} aiOnly /><TriagePreview incidentId={incident.incident_id} alerts={alerts} flows={flows} onEvidence={openEvidence} analystName={username} autoRunning={overviewAi.status === 'running'} refreshToken={`${overviewAi.status}:${overviewAi.run_id || ''}`} /><section className="incident-limitations"><h2>Limits & possible false positives</h2><ul><li>Only rule-matched minutes appear in the chart; normal traffic is not shown.</li><li>Flow records are linked samples, not the complete traffic dataset.</li><li>High traffic can also come from legitimate activity such as backups or load tests.</li></ul></section></section>}
        {step === 4 && <section className="incident-section incident-step-panel" aria-labelledby="incident-recommendations"><div className="incident-section-heading"><h2 id="incident-recommendations">Recommendations</h2></div><NextSteps incidentId={incident.incident_id} analystName={username} onEvidence={openEvidence} onTimeline={() => setStep(1)} onReviewed={refreshQueue} /></section>}
        {step === 5 && <section className="incident-section incident-step-panel"><CaseRecord incidentId={incident.incident_id} analystName={username} onAudit={onAudit} /></section>}
        <div className="case-step-actions"><button type="button" onClick={step === 0 ? onCases : () => setStep(step - 1)}><StepArrow back />{step === 0 ? 'Cases' : caseSteps[step - 1]}</button><span>{step + 1} / {caseSteps.length}</span><button type="button" onClick={step === caseSteps.length - 1 ? onCases : () => setStep(step + 1)}>{step === caseSteps.length - 1 ? 'Cases' : caseSteps[step + 1]}<StepArrow /></button></div>
      </div>
    </div>
  </div>;
}
