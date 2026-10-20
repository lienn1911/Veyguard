import React from 'react';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

const nameFor = (type) => type === 'PortScan' ? 'Many ports checked' : 'Heavy network traffic';

export default function Dashboard({ onReview, onReplay }) {
  const scans = data.incidents.filter((incident) => data.alerts.some((alert) => alert.incident_id === incident.incident_id && alert.type === 'PortScan')).length;
  const floods = data.incidents.length - scans;

  return <>
    <div className="page-heading dashboard-page-heading"><div><h1>Dashboard</h1><p>Historical network activity · CIC-IDS2017 sample</p></div>{onReplay && <button type="button" onClick={onReplay}>Replay alert</button>}</div>
    <section className="dashboard-metrics" aria-label="Cases in this preview">
      {[['Cases to review', data.incidents.length], ['Many ports checked', scans], ['Heavy traffic', floods]].map(([label, value]) => <div className="dashboard-metric" key={label}><span>{label}</span><strong>{value}</strong></div>)}
    </section>
    <div className="dashboard-grid"><section className="dashboard-panel"><div className="dashboard-panel-head"><h2>Cases to review</h2><button onClick={onReview}>View cases <Icon name="arrow" size={15} /></button></div>
      {data.incidents.map((incident) => { const alerts = data.alerts.filter((item) => item.incident_id === incident.incident_id); const type = alerts[0].type; return <div className="dashboard-flow" key={incident.incident_id}><span className={`alert-type ${type.toLowerCase()}`}>{nameFor(type)}</span><strong>{incident.source_ip} → {incident.destination_ip}</strong><span>{alerts.length} alerts</span></div>; })}
    </section><section className="dashboard-panel"><div className="dashboard-panel-head"><h2>About this preview</h2></div><div className="dashboard-scope"><strong>Past network activity, not live monitoring</strong><span>{data.incidents.length} example cases are available to explore.</span><p>Open a case to see the traffic, why an alert appeared, and what still needs a human decision.</p></div></section></div>
  </>;
}
