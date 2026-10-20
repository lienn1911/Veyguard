import React, { useState } from 'react';
import data from '../real-alerts.json';

const alertTitle = (alert) => alert.type === 'PortScan' ? 'Many ports checked' : 'Heavy network traffic';
const time = (value) => value.replace('T', ' ').slice(0, 16);

export default function AlertQueue({ onOpenCase }) {
  const [selectedId, setSelectedId] = useState(data.alerts[0]?.alert_id ?? null);
  const [query, setQuery] = useState('');
  const [type, setType] = useState('All');
  const alerts = data.alerts.filter((alert) => (type === 'All' || (type === 'DDoS reference' ? alert.ddos_reference : alert.type === type)) && `${alertTitle(alert)} ${alert.type} ${alert.source_ip} ${alert.destination_ip} ${alert.alert_id}`.toLowerCase().includes(query.toLowerCase()));
  const selected = data.alerts.find((alert) => alert.alert_id === selectedId);
  const incident = data.incidents.find((item) => item.incident_id === selected?.incident_id);

  return <section className="iris-alerts-page">
    <header className="iris-alerts-header"><div><h1>Alerts</h1></div><span className="iris-alert-count">{alerts.length} alerts</span></header>
    <div className="iris-alert-toolbar"><input aria-label="Search alerts" placeholder="Search alerts…" value={query} onChange={(event) => setQuery(event.target.value)} /><div className="iris-alert-filters" aria-label="Alert type">{['All', 'PortScan', 'DoS', 'DDoS reference'].map((label) => <button type="button" key={label} className={type === label ? 'selected' : ''} onClick={() => setType(label)}>{label}</button>)}</div></div>
    <div className="iris-alert-split"><div className="iris-alert-queue"><div className="iris-alert-queue-heading">Alert queue</div>{alerts.map((alert) => <button type="button" key={alert.alert_id} className={`iris-alert-row${alert.alert_id === selectedId ? ' selected' : ''}`} onClick={() => setSelectedId(alert.alert_id)}><span className="iris-alert-row-top"><strong>{alertTitle(alert)}</strong><time>{time(alert.timestamp)}</time></span><span>{alert.type} · {alert.flow_count.toLocaleString()} traffic records</span><small>{alert.source_ip} → {alert.destination_ip}</small></button>)}{alerts.length === 0 && <p className="iris-list-note">No matching alerts</p>}</div>
      <div className="iris-alert-detail">{selected ? <><div className="iris-alert-detail-head"><span>ALERT · {selected.alert_id}</span><h2>{alertTitle(selected)}</h2><p>{time(selected.timestamp)} · {selected.type}</p></div><div className="iris-alert-detail-grid"><div><span>Source</span><strong>{selected.source_ip}</strong></div><div><span>Destination</span><strong>{selected.destination_ip}</strong></div><div><span>Traffic records</span><strong>{selected.flow_count.toLocaleString()}</strong></div></div><section><h3>Why it was flagged</h3><p>{selected.rule_basis}</p></section><section><h3>Related case</h3><p>{incident ? `${incident.source_ip} → ${incident.destination_ip}` : 'No case linked'}</p>{incident && <button type="button" className="iris-open-case" onClick={() => onOpenCase(incident.incident_id)}>Open case →</button>}</section><details><summary>Technical source</summary><p>{selected.source_file} · row {selected.source_row}</p></details></> : <p className="iris-list-note">Select an alert</p>}</div></div>
  </section>;
}
