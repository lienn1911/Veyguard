import React, { useState } from 'react';

const tabs = ['Overview', 'Evidence', 'Timeline', 'Next Steps', 'Activity'];

export default function AlertReview() {
  const [activeTab, setActiveTab] = useState('Overview');

  return (
    <>
      <div className="page-heading">
        <h1>Alert Review</h1>
      </div>

      <div className="review-layout">
        <section className="review-list" aria-label="Alerts">
          <div className="review-heading">
            <h2>Alerts</h2>
            <span>00</span>
          </div>
          <div className="review-list-empty">No alerts yet</div>
        </section>

        <section className="review-detail" aria-label="Alert details">
          <div className="review-tabs" role="tablist" aria-label="Review sections">
            {tabs.map((tab) => (
              <button
                key={tab}
                id={`tab-${tab.replaceAll(' ', '-').toLowerCase()}`}
                role="tab"
                aria-selected={activeTab === tab}
                aria-controls="review-panel"
                className={activeTab === tab ? 'active' : ''}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </div>
          <div
            id="review-panel"
            className="review-empty"
            role="tabpanel"
            aria-labelledby={`tab-${activeTab.replaceAll(' ', '-').toLowerCase()}`}
          >
            <span className="empty-icon" aria-hidden="true">◎</span>
            <span>No alert selected</span>
          </div>
        </section>
      </div>
    </>
  );
}
