import React, { useEffect, useState } from 'react';
import Icon from './Icon.jsx';
import Timeline from '../modules/timeline.jsx';
import { TriagePreview } from './WorkflowPreview.jsx';
import NextSteps from '../modules/recommendations.jsx';
import CaseNotes from './CaseNotes.jsx';
import data from '../real-alerts.json';
import timelineData from '../real-timelines.json';

const views = ['Activity', 'Alerts', 'AI check', 'Timeline', 'Next steps'];
const shortTime = (value) => value.replace('T', ' ').slice(0, 16);
const caseName = (type) => type === 'PortScan' ? 'Many ports checked' : type === 'DDoS' ? 'Distributed traffic surge' : 'Heavy network traffic';
const alertReason = (alert) => alert.type === 'PortScan'
  ? `${alert.destination_port_count.toLocaleString()} service ports checked in one minute`
  : alert.type === 'DDoS' ? `${alert.source_count} sources sent heavy traffic in one minute`
  : 'Unusually heavy traffic in one minute';

export default function AlertReview({ mode, selectedId, onSelectCase, onCases, username }) {
  const [view, setView] = useState(0);
  const [query, setQuery] = useState('');
  const [recordFilter, setRecordFilter] = useState('All activity');
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [queue, setQueue] = useState(null);
  const [queueError, setQueueError] = useState('');
  const incident = data.incidents.find((item) => item.incident_id === selectedId);
  const alerts = data.alerts.filter((item) => item.incident_id === selectedId);
  const flows = data.flows.filter((flow) => incident?.evidence_sample_ids.includes(flow.flow_id));
  const events = timelineData.timelines.find((item) => item.incident_id === selectedId)?.events || [];
  const evidence = [...alerts, ...flows].find((item) => (item.alert_id || item.flow_id) === selectedEvidence);
  const evidenceEvent = events.find((event) => event.evidence_id === selectedEvidence);
  const search = query.trim().toLowerCase();
  const matchingFlows = flows.filter((flow) => `${flow.timestamp} ${flow.source_ip} ${flow.destination_ip} ${flow.destination_port} ${flow.flow_id}`.toLowerCase().includes(search));
  const representativeFlows = matchingFlows.filter((flow, index, items) => index === items.findIndex((item) => item.timestamp === flow.timestamp && item.destination_port === flow.destination_port));
  const matchingAlerts = alerts.filter((alert) => `${alert.timestamp} ${alert.type} ${alert.rule_basis} ${alert.alert_id}`.toLowerCase().includes(search));
  const activityItems = (recordFilter === 'Network flows' ? representativeFlows : recordFilter === 'Alerts' ? matchingAlerts : [...representativeFlows, ...matchingAlerts]).sort((a, b) => a.timestamp.localeCompare(b.timestamp) || String(a.alert_id || a.flow_id).localeCompare(String(b.alert_id || b.flow_id))).slice(0, 12);
  const matchingEvents = events.filter((event) => `${event.timestamp} ${event.title} ${event.evidence_id}`.toLowerCase().includes(search));

  useEffect(() => {
    let active = true;
    fetch('/api/cases/queue')
      .then((response) => { if (!response.ok) throw new Error('Case queue unavailable'); return response.json(); })
      .then((result) => { if (active) { setQueue(result.cases); setQueueError(''); } })
      .catch(() => { if (active) setQueueError('Case status unavailable. Restart the local service.'); });
    return () => { active = false; };
  }, [mode, selectedId]);

  async function assignSelf() {
    if (!incident || !username) return;
    try {
      const response = await fetch(`/api/cases/${encodeURIComponent(incident.incident_id)}/assign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: username }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Assignment failed');
      setQueue((current) => ({ ...current, [incident.incident_id]: result.case }));
      setQueueError('');
    } catch (error) {
      setQueueError(error.message);
    }
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

  const caseState = queue?.[selectedId];
  const stateFor = (id) => queue?.[id];

  function selectView(index) {
    setView(index);
    if (index === 0) setRecordFilter('All activity');
    if (index === 1) setRecordFilter('Alerts');
    setQuery('');
    setSelectedEvidence(null);
  }

  if (mode === 'cases' || !incident) return <section className="iris-cases-page"><header><h1>Cases</h1><p>{data.incidents.length} investigations · {data.alerts.length} related alerts</p></header>{queueError && <p className="case-queue-error" role="status">{queueError}</p>}<div className="iris-cases-table"><div className="iris-cases-columns"><span>Case</span><span>First seen · UTC</span><span>Review status</span><span>Assigned analyst</span><span>Alerts</span></div>{data.incidents.map((item, index) => {
    const caseAlerts = data.alerts.filter((alert) => alert.incident_id === item.incident_id);
    const state = stateFor(item.incident_id);
    return <button type="button" className="iris-cases-row" key={item.incident_id} onClick={() => { setView(0); setQuery(''); onSelectCase(item.incident_id); }}><span className="case-queue-name"><strong>Case #{index + 1} <span>· {caseName(caseAlerts[0]?.type)}</span></strong><small>{item.source_ip} → {item.destination_ip}</small></span><time>{shortTime(item.window_start)}</time><span className="case-queue-status">{state?.status || (queueError ? 'Unavailable' : 'Loading…')}</span><span>{state?.owner || 'Unassigned'}</span><span className="case-alert-count">{caseAlerts.length} alerts</span></button>;
  })}</div></section>;

  return <div className="iris-review">
    <nav className="iris-case-tabs" aria-label="Case sections"><button type="button" onClick={onCases}>Cases</button>{views.map((label, index) => <button type="button" key={label} className={view === index ? 'selected' : ''} aria-current={view === index ? 'page' : undefined} onClick={() => selectView(index)}>{label === 'Activity' ? 'Stream' : label === 'Timeline' ? 'Timelines' : label}</button>)}</nav>
    <header className="iris-case-header">
      <span className="iris-header-icon"><Icon name="shield" size={23} /></span>
      <div className="iris-header-title"><span>{incident.incident_id}</span><h1>Case #{data.incidents.findIndex((item) => item.incident_id === incident.incident_id) + 1} · {caseName(alerts[0]?.type)}</h1><small>{shortTime(incident.window_start)}–{shortTime(incident.window_end)} UTC · {alerts.length} alerts · {incident.source_ip} → {incident.destination_ip}</small></div>
      <div className="case-review-controls"><span className="iris-header-badge">{caseState?.status || 'Historical sample'}</span><small>{caseState?.owner || 'Unassigned'}</small>{caseState && !caseState.owner && <button type="button" onClick={assignSelf}>Assign to me</button>}</div>
    </header>

    <div className="iris-review-body">
      <div className="iris-stream">
        {(view === 0 || view === 1 || view === 3) && <div className="iris-stream-search">{view === 0 && <div className="case-stream-filters" aria-label="Activity filter">{['All activity', 'Network flows'].map((label) => <button type="button" key={label} className={recordFilter === label ? 'selected' : ''} onClick={() => setRecordFilter(label)}>{label}</button>)}</div>}<input aria-label={`Search ${views[view].toLowerCase()}`} placeholder={`Search ${views[view].toLowerCase()}…`} value={query} onChange={(event) => setQuery(event.target.value)} /></div>}
        {incident && <div className="iris-stream-content">
          <div className="iris-stream-heading"><h2>{views[view]}</h2><small>{view === 0 ? `${incident.flow_count.toLocaleString()} traffic records` : view === 1 ? `${alerts.length} alerts` : view === 3 ? `${events.length} events` : ''}</small></div>

          {view === 0 && <><div className="iris-activity-list">{activityItems.map((item) => <button type="button" className="iris-activity" key={item.alert_id || item.flow_id} onClick={() => setSelectedEvidence(item.alert_id || item.flow_id)}><span className={`iris-activity-avatar${item.alert_id ? ' alert' : ''}`}><Icon name={item.alert_id ? 'alert' : 'flow'} size={18} /></span><span className="iris-activity-copy"><strong>{item.alert_id ? alertReason(item) : 'Network activity'}</strong><span>{item.alert_id ? `${item.flow_count.toLocaleString()} traffic records · ${item.type}` : `${item.source_ip} → ${item.destination_ip} · port ${item.destination_port}`}</span></span><time>{item.timestamp.slice(11, 16)}</time></button>)}{(matchingFlows.length + matchingAlerts.length) > activityItems.length && <p className="iris-list-note">Showing {activityItems.length} of {recordFilter === 'Alerts' ? matchingAlerts.length : recordFilter === 'Network flows' ? matchingFlows.length : matchingFlows.length + matchingAlerts.length} records</p>}{activityItems.length === 0 && <p className="iris-list-note">No matching records</p>}</div><CaseNotes incidentId={incident.incident_id} username={username} evidenceIds={[...incident.alert_ids, ...incident.evidence_sample_ids]} onEvidence={setSelectedEvidence} /></>}

          {view === 1 && <div className="iris-activity-list">{matchingAlerts.map((alert) => <button type="button" className="iris-activity" key={alert.alert_id} onClick={() => setSelectedEvidence(alert.alert_id)}><span className="iris-activity-avatar alert"><Icon name="alert" size={18} /></span><span className="iris-activity-copy"><strong>{alertReason(alert)}</strong><span>{alert.flow_count.toLocaleString()} traffic records · {alert.type}</span></span><time>{alert.timestamp.slice(11, 16)}</time></button>)}{matchingAlerts.length === 0 && <p className="iris-list-note">No matching alerts</p>}</div>}

          {view === 2 && <TriagePreview incidentId={incident.incident_id} alerts={alerts} flows={flows} onEvidence={setSelectedEvidence} />}
          {view === 3 && <Timeline events={matchingEvents} onEvidence={setSelectedEvidence} />}
          {view === 4 && <NextSteps incidentId={incident.incident_id} analystName={username} onEvidence={setSelectedEvidence} onReviewed={refreshQueue} />}
        </div>}
      </div>
    </div>

    {evidence && <div className="evidence-detail process-evidence" aria-live="polite"><div><strong>Record details</strong><button type="button" onClick={() => setSelectedEvidence(null)} aria-label="Close record details"><Icon name="close" size={18} /></button></div><dl><dt>Time</dt><dd>{evidence.timestamp.replace('T', ' ')}</dd><dt>From</dt><dd>{evidence.source_ip}{evidence.source_port ? `:${evidence.source_port}` : ''}</dd><dt>To</dt><dd>{evidence.destination_ip}{evidence.destination_port ? `:${evidence.destination_port}` : ''}</dd><dt>Record ID</dt><dd>{selectedEvidence}</dd>{evidence.rule_basis && <><dt>Detection details</dt><dd>{evidence.rule_basis}</dd></>}</dl><details><summary>Technical source</summary><p>{evidence.source_file}{evidence.source_row ? ` · row ${evidence.source_row}` : ''}</p>{evidenceEvent && <p>MITRE mapping: {typeof evidenceEvent.technique === 'string' ? evidenceEvent.technique : `${evidenceEvent.technique.id} · ${evidenceEvent.technique.name}`}</p>}</details></div>}
  </div>;
}
