import React, { useEffect, useState } from 'react';
import Icon from './Icon.jsx';
import Timeline from '../modules/timeline.jsx';
import { TriagePreview } from './WorkflowPreview.jsx';
import NextSteps from '../modules/recommendations.jsx';
import CaseNotes from './CaseNotes.jsx';
import data from '../real-alerts.json';
import timelineData from '../real-timelines.json';

const views = ['Overview', 'Timeline', 'Evidence', 'AI check', 'Recommendations'];
const shortTime = (value) => value.replace('T', ' ').slice(0, 16);
const caseName = (type) => type === 'PortScan' ? 'Many ports checked' : type === 'DDoS' ? 'Distributed traffic surge' : type === 'DoS' ? 'Heavy network traffic' : type === 'NeedsReview' ? 'Unclassified activity · needs review' : type;
const alertReason = (alert) => alert.type === 'PortScan'
  ? `${alert.destination_port_count.toLocaleString()} service ports checked in one minute`
  : alert.type === 'DDoS' ? `${alert.source_count} sources sent heavy traffic in one minute`
  : alert.type === 'NeedsReview' ? 'High-volume activity without a known attack-rule match; analyst review needed'
  : 'Unusually heavy traffic in one minute';
const aiVerdicts = new Set(['Likely Attack', 'Likely Benign', 'Needs Review']);

function caseAssessment(incident, response) {
  if (!response) return { label: 'Checking…' };
  if (response.status === 'unavailable') return { label: 'Unavailable' };
  if (response.status === 'running' || response.status === 'analysing') return { label: 'Analysing' };
  if (response.status !== 'ready') return { label: 'Pending' };
  const result = response.assessment;
  const evidence = new Set([...incident.alert_ids, ...incident.evidence_sample_ids]);
  if (!aiVerdicts.has(result?.verdict) || !Array.isArray(result.evidence_ids) || !result.evidence_ids.some((id) => evidence.has(id))) return { label: 'Unavailable' };
  return { label: result.verdict, confidence: typeof result.confidence === 'number' && result.confidence >= 0 && result.confidence <= 1 ? `${Math.round(result.confidence * 100)}%` : null };
}

export default function AlertReview({ mode, selectedId, onSelectCase, onCases, username }) {
  const [view, setView] = useState(0);
  const sectionIndex = [0, 2, 1, 3, 4][view];
  const [query, setQuery] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [queue, setQueue] = useState(null);
  const [queueError, setQueueError] = useState('');
  const [assessments, setAssessments] = useState({});
  const incident = data.incidents.find((item) => item.incident_id === selectedId);
  const alerts = data.alerts.filter((item) => item.incident_id === selectedId);
  const flows = data.flows.filter((flow) => incident?.evidence_sample_ids.includes(flow.flow_id));
  const events = timelineData.timelines.find((item) => item.incident_id === selectedId)?.events || [];
  const evidence = [...alerts, ...flows].find((item) => (item.alert_id || item.flow_id) === selectedEvidence);
  const evidenceEvent = events.find((event) => event.evidence_id === selectedEvidence);
  const search = query.trim().toLowerCase();
  const matchingFlows = flows.filter((flow) => `${flow.timestamp} ${flow.source_ip} ${flow.destination_ip} ${flow.destination_port} ${flow.flow_id}`.toLowerCase().includes(search));
  const matchingAlerts = alerts.filter((alert) => `${alert.timestamp} ${alert.type} ${alert.rule_basis} ${alert.alert_id}`.toLowerCase().includes(search));

  useEffect(() => {
    let active = true;
    fetch('/api/cases/queue')
      .then((response) => { if (!response.ok) throw new Error('Case queue unavailable'); return response.json(); })
      .then((result) => { if (active) { setQueue(result.cases); setQueueError(''); } })
      .catch(() => { if (active) setQueueError('Case status unavailable. Restart the local service.'); });
    return () => { active = false; };
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

  const caseState = queue?.[selectedId];
  const stateFor = (id) => queue?.[id];
  const evidencePanel = evidence && <div className="evidence-detail process-evidence" aria-live="polite"><div><strong>Record details</strong><button type="button" onClick={() => setSelectedEvidence(null)} aria-label="Close record details"><Icon name="close" size={18} /></button></div><dl><dt>Time</dt><dd>{evidence.timestamp.replace('T', ' ')}</dd><dt>From</dt><dd>{evidence.source_ip}{evidence.source_port ? `:${evidence.source_port}` : ''}</dd><dt>To</dt><dd>{evidence.destination_ip}{evidence.destination_port ? `:${evidence.destination_port}` : ''}</dd><dt>Record ID</dt><dd>{selectedEvidence}</dd>{evidence.rule_basis && <><dt>Detection details</dt><dd>{evidence.rule_basis}</dd></>}{evidenceEvent?.technique && evidenceEvent.technique !== 'Unmapped' && <><dt>ATT&CK mapping</dt><dd>{typeof evidenceEvent.technique === 'string' ? evidenceEvent.technique : `${evidenceEvent.technique.id} · ${evidenceEvent.technique.name}`}</dd></>}</dl></div>;

  function selectView(index) {
    setView(index);
    setQuery('');
    setSelectedEvidence(null);
  }

  if (mode === 'cases' || !incident) return <section className="iris-cases-page"><header><h1>Investigations</h1><p>{data.incidents.length} cases · {data.alerts.length} related alerts</p></header>{queueError && <p className="case-queue-error" role="status">{queueError}</p>}<div className="iris-cases-table"><div className="iris-cases-columns"><span>Case</span><span>First seen · UTC</span><span>Review status</span><span>AI assessment</span><span>Alerts</span></div>{data.incidents.map((item, index) => {
    const caseAlerts = data.alerts.filter((alert) => alert.incident_id === item.incident_id);
    const state = stateFor(item.incident_id);
    const ai = caseAssessment(item, assessments[item.incident_id]);
    return <button type="button" className="iris-cases-row" key={item.incident_id} onClick={() => { setView(0); setQuery(''); onSelectCase(item.incident_id); }}><span className="case-queue-name"><strong>Case #{index + 1} <span>· {caseName(caseAlerts[0]?.type)}</span></strong><small>{item.source_ip} → {item.destination_ip}</small></span><time>{shortTime(item.window_start)}</time><span className="case-queue-status">{state?.status || (queueError ? 'Unavailable' : 'Loading…')}</span><span className="case-ai-assessment">{ai.label}{ai.confidence && <small>{ai.confidence}</small>}</span><span className="case-alert-count">{caseAlerts.length} alerts</span></button>;
  })}</div></section>;

  return <div className="iris-review">
    <header className="iris-case-header">
      <div className="iris-header-title"><h1>Case #{data.incidents.findIndex((item) => item.incident_id === incident.incident_id) + 1} · {caseName(alerts[0]?.type)}</h1><small>{alerts.length} alerts · {incident.source_ip} → {incident.destination_ip}</small></div>
      <div className="case-review-controls"><span className="iris-header-badge">{caseState?.status || 'Historical sample'}</span></div>
    </header>

    <div className="case-detail-workspace">
    <nav className="iris-case-tabs" aria-label="Case sections"><button type="button" className="complete" onClick={onCases}><span className="case-step-dot" aria-hidden="true" />Cases</button>{views.map((label, index) => <button type="button" key={label} className={index === view ? 'selected' : index < view ? 'complete' : ''} aria-current={view === index ? 'step' : undefined} onClick={() => selectView(index)}><span className="case-step-dot" aria-hidden="true" />{label}</button>)}</nav>
    <div className="iris-review-body">
      <div className="iris-stream">
        {view === 2 && <div className="iris-stream-search"><input aria-label="Search evidence" placeholder="Search evidence…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>}
        {incident && <div className="iris-stream-content">
          <div className="iris-stream-heading"><h2>{views[view]}</h2><small>{sectionIndex === 1 || sectionIndex === 2 ? `${alerts.length} alerts · ${flows.length} linked flow records` : ''}</small></div>

          {view === 0 && <div className="case-overview"><div className="case-overview-lead"><span className={`alert-type-chip ${alerts[0]?.type?.toLowerCase()}`}>{alerts[0]?.type || 'Unknown'}</span><h3>What happened</h3><p>{alerts[0] ? `${alertReason(alerts[0])}. The rule matched ${alerts.length} time${alerts.length === 1 ? '' : 's'} between ${shortTime(incident.window_start)} and ${shortTime(incident.window_end)} UTC.` : 'No alerts linked to this case.'}</p></div><div className="case-overview-metrics"><div><span>Alerts</span><strong>{alerts.length}</strong></div><div><span>Traffic records</span><strong>{incident.flow_count.toLocaleString()}</strong></div><div><span>Source → destination</span><strong>{incident.source_ip} → {incident.destination_ip}</strong></div></div><section><h3>Why it was flagged</h3><p>{alerts[0]?.rule_basis || 'No rule basis available.'}</p></section><div className="case-overview-footer"><p>A rule match is not an analyst verdict. Check the event order and supporting records before deciding next steps.</p><button type="button" onClick={() => selectView(1)}>Continue to Timeline <Icon name="arrow" size={14} /></button></div></div>}

          {sectionIndex === 1 && <div className="case-evidence"><p className="case-evidence-intro">{matchingAlerts.length} rule matches and {matchingFlows.length} linked flow records. Open a group to inspect individual records and their source IDs.</p><details open={matchingAlerts.length <= 3}><summary><span>Rule matches</span><strong>{matchingAlerts.length} alerts</strong></summary><div className="iris-activity-list">{matchingAlerts.map((alert) => <button type="button" className="iris-activity" key={alert.alert_id} onClick={() => setSelectedEvidence(alert.alert_id)}><span className="iris-activity-avatar alert"><Icon name="alert" size={18} /></span><span className="iris-activity-copy"><strong>{alertReason(alert)}</strong><span>{alert.flow_count.toLocaleString()} traffic records · {alert.alert_id}</span></span><time>{alert.timestamp.slice(11, 16)}</time></button>)}{matchingAlerts.length === 0 && <p className="iris-list-note">No matching alerts</p>}</div></details><details><summary><span>Network flow evidence</span><strong>{matchingFlows.length} linked records</strong></summary><div className="iris-activity-list">{matchingFlows.map((flow) => <button type="button" className="iris-activity" key={flow.flow_id} onClick={() => setSelectedEvidence(flow.flow_id)}><span className="iris-activity-avatar"><Icon name="flow" size={18} /></span><span className="iris-activity-copy"><strong>{flow.source_ip} → {flow.destination_ip}</strong><span>Port {flow.destination_port} · {flow.flow_id}</span></span><time>{flow.timestamp.slice(11, 16)}</time></button>)}{matchingFlows.length === 0 && <p className="iris-list-note">No matching flows</p>}</div></details><CaseNotes incidentId={incident.incident_id} username={username} evidenceIds={[...incident.alert_ids, ...incident.evidence_sample_ids]} onEvidence={setSelectedEvidence} /></div>}

          {sectionIndex === 2 && <Timeline events={events} alerts={alerts} flows={flows} rules={data.rules} selectedEvidence={selectedEvidence} onEvidence={setSelectedEvidence} onSelectMinute={() => setSelectedEvidence(null)} evidencePanel={evidencePanel} />}
          {view === 3 && <TriagePreview incidentId={incident.incident_id} alerts={alerts} flows={flows} onEvidence={setSelectedEvidence} />}
          {view === 4 && <NextSteps incidentId={incident.incident_id} analystName={username} onEvidence={setSelectedEvidence} onReviewed={refreshQueue} />}
          {view !== 1 && evidencePanel}
        </div>}
      </div>
    </div>
    </div>

  </div>;
}
