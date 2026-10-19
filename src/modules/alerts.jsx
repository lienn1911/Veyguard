import React from 'react';

export default function Alerts({ incidents, alerts, selectedId, onSelect }) {
  return (
    <section className="review-list" aria-label="Grouped alerts">
      <div className="review-heading"><h2>Alerts</h2><span>{String(incidents.length).padStart(2, '0')}</span></div>
      <div className="alert-items">
        {incidents.map((incident) => {
          const alert = alerts.find((item) => item.incident_id === incident.incident_id);
          return <button key={incident.incident_id} className={`alert-item${selectedId === incident.incident_id ? ' selected' : ''}`} onClick={() => onSelect(incident.incident_id)}>
            <span className="alert-item-top"><span className={`alert-type ${alert.type.toLowerCase()}`}>{alert.type}</span><time>{alert.timestamp.replace('T', ' ').slice(0, 16)}</time></span>
            <span className="alert-item-bottom">{incident.flow_count.toLocaleString()} flows<span>{Object.keys(alert.dataset_labels).join(', ')} label</span></span>
          </button>;
        })}
      </div>
    </section>
  );
}
