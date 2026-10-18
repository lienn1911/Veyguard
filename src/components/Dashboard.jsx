import React from 'react';
import Icon from './Icon.jsx';

const metrics = ['Alerts', 'Awaiting Review', 'Reviewed'];

export default function Dashboard({ onReview }) {
  return (
    <>
      <div className="page-heading">
        <h1>Dashboard</h1>
      </div>

      <section className="dashboard-metrics" aria-label="Dashboard summary">
        {metrics.map((label) => (
          <div className="dashboard-metric" key={label}>
            <span>{label}</span>
            <strong>—</strong>
          </div>
        ))}
      </section>

      <div className="dashboard-grid">
        <section className="dashboard-panel">
          <div className="dashboard-panel-head">
            <h2>Recent Alerts</h2>
            <button onClick={onReview}>
              Open Alert Review
              <Icon name="arrow" size={15} />
            </button>
          </div>
          <div className="dashboard-panel-empty">No alerts yet</div>
        </section>

        <section className="dashboard-panel">
          <div className="dashboard-panel-head">
            <h2>Review Activity</h2>
          </div>
          <div className="dashboard-panel-empty">No activity yet</div>
        </section>
      </div>
    </>
  );
}
