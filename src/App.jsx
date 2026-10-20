import React, { useEffect, useState } from 'react';
import AlertReview from './components/AlertReview.jsx';
import AlertQueue from './components/AlertQueue.jsx';
import Dashboard from './components/Dashboard.jsx';
import Sidebar from './components/Sidebar.jsx';
import AlertMascot from './components/AlertMascot.jsx';
import data from './real-alerts.json';

const featuredCase = data.incidents.find((incident) => data.alerts.some((alert) => alert.incident_id === incident.incident_id && alert.type === 'PortScan'));
const alertNotificationEnabled = false;

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('soc-sidebar-collapsed') === 'true');
  const [notification, setNotification] = useState(false);

  useEffect(() => {
    if (!alertNotificationEnabled || sessionStorage.getItem('soc-preview-notification')) return;
    const timer = window.setTimeout(() => {
      setNotification(true);
      sessionStorage.setItem('soc-preview-notification', 'shown');
    }, 800);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!notification) return;
    const timer = window.setTimeout(() => setNotification(false), 9000);
    return () => window.clearTimeout(timer);
  }, [notification]);

  function selectPage(nextPage) {
    setPage(nextPage);
    setSidebarOpen(false);
    setNotification(false);
  }

  function openCase(id) {
    setSelectedCaseId(id);
    selectPage('review');
  }

  function toggleSidebar() {
    setSidebarCollapsed((current) => {
      localStorage.setItem('soc-sidebar-collapsed', String(!current));
      return !current;
    });
  }

  return (
    <div className="shell">
      <Sidebar page={page} open={sidebarOpen} collapsed={sidebarCollapsed} onToggle={toggleSidebar} onSelect={selectPage} />

      {sidebarOpen && (
        <button
          className="mobile-scrim"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="content-area">
        <header className="topbar">
          <button
            className="menu-button"
            aria-label="Open navigation"
            onClick={() => setSidebarOpen(true)}
          >
            ☰
          </button>
          <strong className="topbar-brand">SOC Triage</strong>
          <nav className="topbar-links" aria-label="Case sections">
            {page === 'review' && <span>Case workspace</span>}
            {page === 'cases' && <span>Cases</span>}
            {page === 'alerts' && <span>Alerts</span>}
          </nav>
        </header>

        <main className={`main-content${page === 'review' || page === 'cases' || page === 'alerts' ? ' review-main-content' : ''}`}>
          {page === 'alerts' ? (
            <AlertQueue onOpenCase={openCase} />
          ) : page === 'review' || page === 'cases' ? (
            <AlertReview mode={page} selectedId={selectedCaseId} onSelectCase={openCase} onCases={() => selectPage('cases')} />
          ) : (
            <Dashboard onReview={() => selectPage('cases')} onReplay={alertNotificationEnabled ? () => setNotification(true) : undefined} />
          )}
        </main>
      </div>
      {alertNotificationEnabled && notification && featuredCase && <div className="alert-notification" role="status" aria-live="polite">
        <div className="alert-notification-avatar"><AlertMascot /></div>
        <div className="alert-notification-content"><div className="alert-notification-top"><span>SOC Triage · Dataset preview</span><button type="button" onClick={() => setNotification(false)} aria-label="Dismiss alert notification">×</button></div>
          <strong>PortScan alert detected</strong>
          <p>{featuredCase.source_ip} → {featuredCase.destination_ip}<br />{featuredCase.alert_ids.length} alerts grouped into one case</p>
          <button type="button" className="alert-notification-action" onClick={() => openCase(featuredCase.incident_id)}>Review case →</button>
        </div>
      </div>}
    </div>
  );
}
