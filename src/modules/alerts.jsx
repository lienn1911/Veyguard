import React from 'react';

export default function Alerts({ incidents, alerts, selectedId, onSelect }) {
  return (
    <section className="review-list" aria-label="Grouped alerts">
      <div className="review-heading"><h2>Alerts</h2><span>{String(incidents.length).padStart(2, '0')}</span></div>
      <div className="alert-items">
        {incidents.map((incident) => {
          const incidentAlerts = alerts.filter((item) => item.incident_id === incident.incident_id);
          const alert = incidentAlerts[0];
          const labels = [...new Set(incidentAlerts.flatMap((item) => Object.keys(item.dataset_labels)))];
          return <button key={incident.incident_id} className={`alert-item${selectedId === incident.incident_id ? ' selected' : ''}`} onClick={() => onSelect(incident.incident_id)}>
            <span className="alert-item-top"><span className={`alert-type ${alert.type.toLowerCase()}`}>{[...new Set(incidentAlerts.map((item) => item.type))].join(' / ')}</span><time>{incident.window_start.replace('T', ' ').slice(0, 16)}</time></span>
            <span className="alert-item-bottom">{incident.flow_count.toLocaleString()} flows · {incidentAlerts.length} alerts<span>{labels.join(', ')} label</span></span>
          </button>;
        })}
      </div>
    </section>
  );
}
