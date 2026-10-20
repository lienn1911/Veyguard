import React, { useEffect, useState } from 'react';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

const alertTitle = (alert) => alert.type === 'PortScan' ? 'Many ports checked' : alert.type === 'DDoS' ? 'Distributed traffic surge' : 'Heavy network traffic';
const time = (value) => value.replace('T', ' ').slice(0, 16);
const dates = [...new Set(data.alerts.map((alert) => alert.timestamp.slice(0, 10)))].sort();
const caseNumber = new Map(data.incidents.map((incident, index) => [incident.incident_id, index + 1]));

export default function AlertQueue({ onOpenCase, selectedAlertId }) {
  const [selectedId, setSelectedId] = useState(selectedAlertId ?? null);
  const [query, setQuery] = useState('');
  const [type, setType] = useState('All');
  const [caseId, setCaseId] = useState('All');
  const [date, setDate] = useState('All');
  const [sort, setSort] = useState('newest');
  const [expandedCaseId, setExpandedCaseId] = useState(data.alerts.find((alert) => alert.alert_id === selectedAlertId)?.incident_id || null);

  useEffect(() => {
    if (!selectedAlertId) return;
    setSelectedId(selectedAlertId);
    setExpandedCaseId(data.alerts.find((alert) => alert.alert_id === selectedAlertId)?.incident_id);
  }, [selectedAlertId]);

  const search = query.trim().toLowerCase();
  const alerts = data.alerts.filter((alert) =>
    (type === 'All' || alert.type === type)
    && (caseId === 'All' || alert.incident_id === caseId)
    && (date === 'All' || alert.timestamp.startsWith(date))
    && `${alertTitle(alert)} ${alert.type} ${alert.timestamp} ${alert.source_ip} ${alert.destination_ip} ${alert.alert_id} ${alert.rule_basis} ${alert.incident_id}`.toLowerCase().includes(search)
  ).sort((a, b) => sort === 'records'
    ? b.flow_count - a.flow_count || b.timestamp.localeCompare(a.timestamp)
    : sort === 'oldest' ? a.timestamp.localeCompare(b.timestamp) : b.timestamp.localeCompare(a.timestamp));
  const groups = data.incidents.map((item) => ({ incident: item, alerts: alerts.filter((alert) => alert.incident_id === item.incident_id) })).filter((group) => group.alerts.length).sort((a, b) => sort === 'oldest' ? a.alerts[0].timestamp.localeCompare(b.alerts[0].timestamp) : b.alerts[0].timestamp.localeCompare(a.alerts[0].timestamp));
  const activeCaseId = expandedCaseId && groups.some((group) => group.incident.incident_id === expandedCaseId) ? expandedCaseId : null;
  const selected = alerts.find((alert) => alert.alert_id === selectedId);
  const incident = data.incidents.find((item) => item.incident_id === selected?.incident_id);
  const filtered = Boolean(query || type !== 'All' || caseId !== 'All' || date !== 'All');

  function clearFilters() {
    setQuery('');
    setType('All');
    setCaseId('All');
    setDate('All');
    setSort('newest');
  }

  return <section className="iris-alerts-page">
    <header className="iris-alerts-header"><div><h1>Alerts</h1><p>{groups.length} cases · {alerts.length} matching alerts</p></div><span className="iris-alert-count">{alerts.length} of {data.alerts.length}</span></header>
    <div className="alerts-workspace"><div className="alerts-controls">
      <div className="alerts-controls-main"><input aria-label="Search alerts" placeholder="Search alerts, IPs, or IDs…" value={query} onChange={(event) => setQuery(event.target.value)} /><label>Sort <select aria-label="Sort alerts" value={sort} onChange={(event) => setSort(event.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="records">Most records</option></select></label></div>
      <div className="alerts-controls-filters"><div className="iris-alert-filters" aria-label="Alert type">{['All', 'PortScan', 'DoS', 'DDoS'].map((label) => <button type="button" key={label} className={type === label ? 'selected' : ''} aria-pressed={type === label} onClick={() => setType(label)}>{label}</button>)}</div><label>Case <select aria-label="Filter by case" value={caseId} onChange={(event) => setCaseId(event.target.value)}><option value="All">All cases</option>{data.incidents.map((item) => <option key={item.incident_id} value={item.incident_id}>Case #{caseNumber.get(item.incident_id)} · {item.incident_id}</option>)}</select></label><label>Date <select aria-label="Filter by sample date" value={date} onChange={(event) => setDate(event.target.value)}><option value="All">All sample dates</option>{dates.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>{filtered && <button type="button" className="alerts-clear" onClick={clearFilters}>Clear filters</button>}</div>
    </div>
    <div className="iris-alert-split"><div className="iris-alert-queue"><div className="alerts-group-heading"><span>Grouped by case</span><span>{groups.length} groups</span></div>{groups.map((group) => <div className="alerts-group" key={group.incident.incident_id}><button type="button" className={`alerts-group-toggle${activeCaseId === group.incident.incident_id ? ' active' : ''}`} aria-expanded={activeCaseId === group.incident.incident_id} onClick={() => { if (activeCaseId === group.incident.incident_id) setExpandedCaseId(null); else { setExpandedCaseId(group.incident.incident_id); setSelectedId(group.alerts[0].alert_id); } }}><span className="alerts-group-caret" aria-hidden="true"><svg viewBox="0 0 20 20" fill="none"><path d="m7.5 4.5 5 5-5 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg></span><span className="alerts-group-copy"><strong>Case #{caseNumber.get(group.incident.incident_id)} · {alertTitle(group.alerts[0])}</strong><small>{time(group.incident.window_start)} · {group.incident.source_ip} → {group.incident.destination_ip}</small></span><span className="alerts-group-count">{group.alerts.length} alerts</span></button>{activeCaseId === group.incident.incident_id && <div className="alerts-group-items">{group.alerts.map((alert) => <button type="button" key={alert.alert_id} className={`alerts-group-item${alert.alert_id === selected?.alert_id ? ' selected' : ''}`} aria-pressed={alert.alert_id === selected?.alert_id} onClick={() => setSelectedId(alert.alert_id)}><time>{time(alert.timestamp)}</time><span>{alert.rule_basis}</span><strong>{alert.flow_count.toLocaleString()} records</strong></button>)}</div>}</div>)}{alerts.length === 0 && <p className="iris-list-note">No matching alerts. <button type="button" onClick={clearFilters}>Clear filters</button></p>}</div>
      <div className="iris-alert-detail">{selected ? <><div className="iris-alert-detail-head"><span>ALERT · {selected.alert_id}</span><h2>{alertTitle(selected)}</h2><p>{time(selected.timestamp)} · {selected.type}</p></div><div className="iris-alert-detail-grid"><div><span>Source</span><strong>{selected.source_ip}</strong></div><div><span>Destination</span><strong>{selected.destination_ip}</strong></div><div><span>Traffic records</span><strong>{selected.flow_count.toLocaleString()}</strong></div></div><section><h3>Why it was flagged</h3><p>{selected.rule_basis}</p></section><section><h3>Related case</h3><p>{incident ? `Case #${caseNumber.get(incident.incident_id)} · ${incident.source_ip} → ${incident.destination_ip}` : 'No case linked'}</p>{incident && <button type="button" className="iris-open-case" onClick={() => onOpenCase(incident.incident_id)}>Open case <Icon name="arrow" size={14} /></button>}</section><details><summary>Technical source</summary><p>{selected.source_file} · row {selected.source_row}</p></details></> : <div className="alert-empty-state"><span className="alert-empty-icon"><Icon name="alert" size={28} /></span><strong>Select an alert</strong><p>Open a case to see its alerts.</p></div>}</div></div></div>
  </section>;
}
