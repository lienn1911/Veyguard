import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import AlertReview from './components/AlertReview.jsx';
import AlertQueue from './components/AlertQueue.jsx';
import Dashboard from './components/Dashboard.jsx';
import Sidebar from './components/Sidebar.jsx';
import AlertMascot from './components/AlertMascot.jsx';
import data from './real-alerts.json';
import Icon from './components/Icon.jsx';
import Login from './components/Login.jsx';
import AuditLog from './components/AuditLog.jsx';
import AISettings from './components/AISettings.jsx';
import { apiFetch, setCsrfToken } from './apiFetch.js';

const featuredCase = data.incidents.find((incident) => data.alerts.some((alert) => alert.incident_id === incident.incident_id && alert.type === 'PortScan'));
const alertNotificationEnabled = false;
const caseTitle = (incident) => incident.type === 'PortScan' ? 'Many ports checked' : incident.type === 'DDoS' ? 'Distributed traffic surge' : incident.type === 'DoS' ? 'Heavy network traffic' : incident.type === 'NeedsReview' ? 'Unclassified activity · needs review' : incident.type;

export default function App() {
  const [username, setUsername] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginNotice, setLoginNotice] = useState('');
  const [logoutError, setLogoutError] = useState('');
  const [page, setPage] = useState('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('soc-sidebar-collapsed') === 'true');
  const [notification, setNotification] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const searchInput = useRef(null);
  const searchButton = useRef(null);
  const [searchPanelPosition, setSearchPanelPosition] = useState(null);
  const searchTerm = searchQuery.trim().toLowerCase();
  const caseResults = searchTerm ? data.incidents.filter((incident) => `${caseTitle(incident)} ${incident.incident_id} ${incident.source_ip} ${incident.destination_ip} ${incident.type}`.toLowerCase().includes(searchTerm)).slice(0, 5) : [];
  const alertResults = searchTerm ? data.alerts.filter((alert) => `${alert.type} ${alert.alert_id} ${alert.source_ip} ${alert.destination_ip} ${alert.rule_basis}`.toLowerCase().includes(searchTerm)).slice(0, 5) : [];

  useEffect(() => {
    fetch('/api/auth/session').then(async (response) => {
      const session = await response.json();
      if (!response.ok) throw new Error(session.error === 'Unknown endpoint' ? 'An old SOC Desk API is running. Restart start.cmd.' : session.error || 'Local API unavailable.');
      return session;
    }).then((session) => {
      if (session.authenticated) {
        setCsrfToken(session.csrf_token);
        setUsername(session.username);
      }
    }).catch((error) => setLoginNotice(error.message || 'Local API unavailable. Start SOC Desk with start.cmd.'))
      .finally(() => setAuthLoading(false));
  }, []);

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

  useLayoutEffect(() => {
    if (!searchOpen) return;
    function positionSearch() {
      const rect = searchButton.current?.getBoundingClientRect();
      if (!rect) return;
      const width = Math.min(Math.max(rect.width, 360), 520, window.innerWidth - 24);
      setSearchPanelPosition({
        top: Math.max(rect.bottom + 9, searchButton.current.closest('.topbar').getBoundingClientRect().bottom + 8),
        left: Math.max(12, Math.min(rect.right - width, window.innerWidth - width - 12)),
        width,
      });
    }
    positionSearch();
    window.addEventListener('resize', positionSearch);
    return () => window.removeEventListener('resize', positionSearch);
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

  function login(nextUsername, csrf) {
    setCsrfToken(csrf);
    setUsername(nextUsername);
    setLoginNotice('');
    selectPage('dashboard');
  }

  async function logout() {
    try {
      const response = await apiFetch('/api/auth/logout', { method: 'POST' });
      if (!response.ok) throw new Error('Sign out failed.');
    } catch {
      setLogoutError('Could not sign out. Check the local API and try again.');
      return;
    }
    setLogoutError('');
    setCsrfToken('');
    setUsername(null);
    setSidebarOpen(false);
    setPage('dashboard');
  }

  function passwordChanged() {
    setCsrfToken('');
    setUsername(null);
    setSidebarOpen(false);
    setLoginNotice('Password changed. Sign in with your new password.');
  }

  if (authLoading) return <main className="auth-loading">Checking your session…</main>;
  if (!username) return <Login onLogin={login} notice={loginNotice} />;

  return (
    <div className="shell">
      <Sidebar page={page} open={sidebarOpen} collapsed={sidebarCollapsed} onSelect={selectPage} onLogout={logout} logoutError={logoutError} onPasswordChanged={passwordChanged} username={username} />

      {sidebarOpen && (
        <button
          className="mobile-scrim"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="content-area">
        <header className={`topbar${searchOpen ? ' search-active' : ''}`}>
          <button className="desktop-menu" aria-label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'} onClick={() => window.matchMedia('(max-width: 760px)').matches ? setSidebarOpen(true) : toggleSidebar()}><Icon name="menu" size={20} /></button>
          <strong className={`topbar-brand${sidebarCollapsed ? ' icon-only' : ''}`}>{sidebarCollapsed ? <img className="topbar-brand-logo" src="/soc-desk-logo-focus.png" alt="SOC Desk" /> : 'SOC Desk'}</strong>
          <div ref={searchButton} className="topbar-search"><Icon name="search" size={17} /><input ref={searchInput} aria-label="Search cases and alerts" placeholder="Search cases and alerts" value={searchQuery} onFocus={() => setSearchOpen(true)} onChange={(event) => { setSearchQuery(event.target.value); setSearchOpen(true); }} onKeyDown={(event) => { if (event.key === 'Enter') { if (caseResults[0]) openCase(caseResults[0].incident_id); else if (alertResults[0]) openAlert(alertResults[0]); } }} /><span>(ctrl + /)</span></div>
          <button className="topbar-icon" aria-label="Alerts" onClick={() => selectPage('alerts')}><Icon name="bell" size={19} /><span className="topbar-tooltip" role="tooltip">Alerts</span></button>
        </header>

        {searchOpen && <div className="search-backdrop" onMouseDown={() => setSearchOpen(false)}><div className="search-panel" style={searchPanelPosition || undefined} role="region" aria-label="Search results" onMouseDown={(event) => event.stopPropagation()}><div className="search-results">{searchTerm ? <>{caseResults.length > 0 && <><h2>Cases</h2>{caseResults.map((incident) => <button type="button" key={incident.incident_id} onClick={() => openCase(incident.incident_id)}><strong>{caseTitle(incident)}</strong><span>{incident.source_ip} → {incident.destination_ip}</span></button>)}</>}{alertResults.length > 0 && <><h2>Alerts</h2>{alertResults.map((alert) => <button type="button" key={alert.alert_id} onClick={() => openAlert(alert)}><strong>{alert.type} · {alert.alert_id}</strong><span>{alert.source_ip} → {alert.destination_ip}</span></button>)}</>}{caseResults.length + alertResults.length === 0 && <p>No matching cases or alerts</p>}</> : <p>Search by IP address, alert type, or record ID.</p>}</div></div></div>}

        <main className={`main-content${page === 'review' || page === 'cases' || page === 'alerts' ? ' investigation-main-content' : ''}`}>
          {(page === 'cases' || page === 'alerts') && <nav className={`investigation-switch${page === 'alerts' ? ' show-alerts' : ''}`} aria-label="Investigation views"><button type="button" className={page === 'cases' ? 'active' : ''} aria-current={page === 'cases' ? 'page' : undefined} onClick={() => selectPage('cases')}>Cases</button><button type="button" className={page === 'alerts' ? 'active' : ''} aria-current={page === 'alerts' ? 'page' : undefined} onClick={() => selectPage('alerts')}>Alerts</button></nav>}
          {page === 'audit' ? (
            <AuditLog mode="live" />
          ) : page === 'settings' ? (
            <AISettings />
          ) : page === 'alerts' ? (
            <AlertQueue onOpenCase={openCase} selectedAlertId={selectedAlertId} />
          ) : page === 'review' || page === 'cases' ? (
            <AlertReview mode={page} selectedId={selectedCaseId} onSelectCase={openCase} onCases={() => selectPage('cases')} onAudit={() => selectPage('audit')} username={username} />
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
