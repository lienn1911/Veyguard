import React, { useState } from 'react';
import Alerts from '../modules/alerts.jsx';
import Timeline from '../modules/timeline.jsx';
import data from '../real-alerts.json';
import timelineData from '../real-timelines.json';

export default function AlertReview() {
  const [selectedId, setSelectedId] = useState(data.incidents[0]?.incident_id);
  const incident = data.incidents.find((item) => item.incident_id === selectedId);
  const alert = data.alerts.find((item) => item.incident_id === selectedId);
  const events = timelineData.timelines.find((item) => item.incident_id === selectedId)?.events || [];

  return (
    <>
      <div className="page-heading review-page-heading">
        <h1>Alert Review</h1>
      </div>
      <div className="review-layout">
        <Alerts incidents={data.incidents} alerts={data.alerts} selectedId={selectedId} onSelect={setSelectedId} />
        {incident && alert && <div className="review-detail">
          <div className="incident-heading"><div><span className="module-kicker">RULE MATCH</span><h2>{alert.type}</h2><code>{incident.incident_id}</code></div></div>
          <div className="incident-facts"><div><span>Source</span><strong>{incident.source_ip}</strong></div><div><span>Destination</span><strong>{incident.destination_ip}</strong></div><div><span>Window</span><strong>{incident.window_start.replace('T', ' ').slice(0, 16)}</strong></div><div><span>Flows</span><strong>{incident.flow_count.toLocaleString()}</strong></div></div>
          <div className="rule-detail"><div><span className="module-kicker">RULE BASIS</span><strong>{alert.rule_basis}</strong></div><div><span className="module-kicker">DATASET LABEL</span><strong>{Object.entries(alert.dataset_labels).map(([label, count]) => `${label} · ${count.toLocaleString()}`).join(' · ')}</strong></div>{alert.ddos_reference && alert.type !== 'DDoS' && <p>One visible source IP; distributed origin unverified.</p>}</div>
          <Timeline events={events} />
        </div>}
      </div>
    </>
  );
}
