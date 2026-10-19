import React from 'react';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

export default function Dashboard({ onReview }) {
  const portScans = data.alerts.filter((alert) => alert.type === 'PortScan').length;
  const ddosReferences = data.alerts.filter((alert) => alert.ddos_reference).length;
  return <>
    <div className="page-heading"><h1>Dashboard</h1><p>CIC-IDS2017 rule-based preview</p></div>
    <section className="dashboard-metrics" aria-label="Dashboard summary">
      {[['Flow groups', data.incidents.length], ['PortScan matches', portScans], ['DDoS references', ddosReferences]].map(([label, value]) => <div className="dashboard-metric" key={label}><span>{label}</span><strong>{value}</strong></div>)}
    </section>
    <div className="dashboard-grid"><section className="dashboard-panel"><div className="dashboard-panel-head"><h2>Detected flow groups</h2><button onClick={onReview}>Open Alert Review <Icon name="arrow" size={15} /></button></div>
      {data.incidents.map((incident) => { const alert = data.alerts.find((item) => item.incident_id === incident.incident_id); return <div className="dashboard-flow" key={incident.incident_id}><span className={`alert-type ${alert.type.toLowerCase()}`}>{alert.type}</span><strong>{incident.source_ip} → {incident.destination_ip}{alert.ddos_reference && alert.type !== 'DDoS' ? ' · DDoS reference' : ''}</strong><span>{incident.flow_count.toLocaleString()} flows</span></div>; })}
    </section><section className="dashboard-panel"><div className="dashboard-panel-head"><h2>Dataset scope</h2></div><div className="dashboard-scope"><strong>{data.provenance.dataset}</strong><span>{data.evaluation.groups_scanned.toLocaleString()} source/destination minute groups scanned</span><span>{data.evaluation.rule_matches.toLocaleString()} rule matches across three source files</span><p>The review shows selected cases from full one-minute groups. Dataset labels are displayed separately from rule matches.</p></div></section></div>
  </>;
}
