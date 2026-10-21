import React, { useEffect, useRef, useState } from 'react';
import AlertReview from './components/AlertReview.jsx';
import AlertQueue from './components/AlertQueue.jsx';
import Dashboard from './components/Dashboard.jsx';
import Sidebar from './components/Sidebar.jsx';
import AlertMascot from './components/AlertMascot.jsx';
import data from './real-alerts.json';
import Icon from './components/Icon.jsx';
import Login from './components/Login.jsx';

const featuredCase = data.incidents.find((incident) => data.alerts.some((alert) => alert.incident_id === incident.incident_id && alert.type === 'PortScan'));
const alertNotificationEnabled = false;
const caseTitle = (incident) => incident.type === 'PortScan' ? 'Many ports checked' : incident.type === 'DDoS' ? 'Distributed traffic surge' : incident.type === 'DoS' ? 'Heavy network traffic' : incident.type === 'NeedsReview' ? 'Unclassified activity · needs review' : incident.type;

export default function App() {
  const [username, setUsername] = useState(() => sessionStorage.getItem('soc-demo-user'));
  const [page, setPage] = useState('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('soc-sidebar-collapsed') === 'true');
  const [notification, setNotification] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const searchInput = useRef(null);
  const searchTerm = searchQuery.trim().toLowerCase();
  const caseResults = searchTerm ? data.incidents.filter((incident) => `${caseTitle(incident)} ${incident.incident_id} ${incident.source_ip} ${incident.destination_ip} ${incident.type}`.toLowerCase().includes(searchTerm)).slice(0, 5) : [];
  const alertResults = searchTerm ? data.alerts.filter((alert) => `${alert.type} ${alert.alert_id} ${alert.source_ip} ${alert.destination_ip} ${alert.rule_basis}`.toLowerCase().includes(searchTerm)).slice(0, 5) : [];

  useEffect(() => {
    function onKeyDown(event) {
      if ((event.ctrlKey || event.metaKey) && event.key === '/') {
        event.preventDefault();
        setSearchOpen(true);
      } else if (event.key === 'Escape') {
        setSearchOpen(false);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    if (searchOpen) searchInput.current?.focus();
  }, [searchOpen]);

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
    setSearchOpen(false);
  }

  function openCase(id) {
    setSelectedCaseId(id);
    selectPage('review');
  }

  function openAlert(alert) {
    setSelectedAlertId(alert.alert_id);
    selectPage('alerts');
  }

  function toggleSidebar() {
    setSidebarCollapsed((current) => {
      localStorage.setItem('soc-sidebar-collapsed', String(!current));
      return !current;
    });
  }

  function login(nextUsername) {
    sessionStorage.setItem('soc-demo-user', nextUsername);
    localStorage.removeItem('soc-demo-user');
    setUsername(nextUsername);
    selectPage('dashboard');
  }

  function logout() {
    localStorage.removeItem('soc-demo-user');
    sessionStorage.removeItem('soc-demo-user');
    setUsername(null);
    setSidebarOpen(false);
    setPage('dashboard');
  }

  if (!username) return <Login onLogin={login} />;

  return (
    <div className="shell">
      <Sidebar page={page} open={sidebarOpen} collapsed={sidebarCollapsed} onSelect={selectPage} onLogout={logout} username={username} />

      {sidebarOpen && (
        <button
          className="mobile-scrim"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="content-area">
        <header className="topbar">
          <button className="desktop-menu" aria-label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'} onClick={() => window.matchMedia('(max-width: 760px)').matches ? setSidebarOpen(true) : toggleSidebar()}><Icon name="menu" size={20} /></button>
          <strong className={`topbar-brand${sidebarCollapsed ? ' icon-only' : ''}`}>{sidebarCollapsed ? <img className="topbar-brand-logo" src="/soc-desk-logo-focus.png" alt="SOC Desk" /> : 'SOC Desk'}</strong>
          <button className="topbar-search" onClick={() => setSearchOpen(true)}><Icon name="search" size={17} /> Search cases and alerts <span>(ctrl + /)</span></button>
          <button className="topbar-icon" aria-label="Alerts" onClick={() => selectPage('alerts')}><Icon name="bell" size={19} /><span className="topbar-tooltip" role="tooltip">Alerts</span></button>
        </header>

        {searchOpen && <div className="search-backdrop" onMouseDown={() => setSearchOpen(false)}><div className="search-panel" role="dialog" aria-modal="true" aria-label="Search cases and alerts" onMouseDown={(event) => event.stopPropagation()}><div className="search-panel-input"><Icon name="search" size={19} /><input ref={searchInput} aria-label="Search cases and alerts" placeholder="Search by case, alert, IP or ID" value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') { if (caseResults[0]) openCase(caseResults[0].incident_id); else if (alertResults[0]) openAlert(alertResults[0]); } }} /><button type="button" onClick={() => setSearchOpen(false)} aria-label="Close search"><Icon name="close" size={18} /></button></div><div className="search-results">{searchTerm ? <>{caseResults.length > 0 && <><h2>Cases</h2>{caseResults.map((incident) => <button type="button" key={incident.incident_id} onClick={() => openCase(incident.incident_id)}><strong>{caseTitle(incident)}</strong><span>{incident.source_ip} → {incident.destination_ip}</span></button>)}</>}{alertResults.length > 0 && <><h2>Alerts</h2>{alertResults.map((alert) => <button type="button" key={alert.alert_id} onClick={() => openAlert(alert)}><strong>{alert.type} · {alert.alert_id}</strong><span>{alert.source_ip} → {alert.destination_ip}</span></button>)}</>}{caseResults.length + alertResults.length === 0 && <p>No matching cases or alerts</p>}</> : <p>Search by IP address, alert type, or record ID.</p>}</div></div></div>}

        <main className={`main-content${page === 'review' || page === 'cases' || page === 'alerts' ? ' investigation-main-content' : ''}`}>
          {page === 'alerts' ? (
            <AlertQueue onOpenCase={openCase} selectedAlertId={selectedAlertId} />
          ) : page === 'review' || page === 'cases' ? (
            <AlertReview mode={page} selectedId={selectedCaseId} onSelectCase={openCase} onCases={() => selectPage('cases')} username={username} />
          ) : (
            <Dashboard onReview={(id) => id ? openCase(id) : selectPage('cases')} onAlerts={(alert) => alert ? openAlert(alert) : selectPage('alerts')} username={username} />
          )}
        </main>
      </div>
      {alertNotificationEnabled && notification && featuredCase && <div className="alert-notification" role="status" aria-live="polite">
        <div className="alert-notification-avatar"><AlertMascot /></div>
        <div className="alert-notification-content"><div className="alert-notification-top"><span>SOC Desk · Dataset preview</span><button type="button" onClick={() => setNotification(false)} aria-label="Dismiss alert notification"><Icon name="close" size={16} /></button></div>
          <strong>PortScan alert detected</strong>
          <p>{featuredCase.source_ip} → {featuredCase.destination_ip}<br />{featuredCase.alert_ids.length} alerts grouped into one case</p>
          <button type="button" className="alert-notification-action" onClick={() => openCase(featuredCase.incident_id)}>Review case <Icon name="arrow" size={14} /></button>
        </div>
      </div>}
    </div>
  );
}
