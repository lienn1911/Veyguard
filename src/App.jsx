import React, { useCallback, useEffect, useState } from 'react';
import AlertReview from './components/AlertReview.jsx';
import AuditLog from './components/AuditLog.jsx';
import Dashboard from './components/Dashboard.jsx';
import Sidebar from './components/Sidebar.jsx';
import Icon from './components/Icon.jsx';
import { getDataset, getHealth, getIncidents } from './lib/api.js';
import { bundledDataset, bundledIncidents } from './lib/bundled.js';

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [auditToken, setAuditToken] = useState(0);
  const [state, setState] = useState({
    status: 'loading',
    health: null,
    dataset: null,
    incidents: [],
    error: null,
  });

  const refresh = useCallback(async () => {
    try {
      const [health, dataset, incidentPayload] = await Promise.all([
        getHealth(),
        getDataset(),
        getIncidents(),
      ]);
      const incidents = incidentPayload.incidents || [];
      setState({
        status: health?.ai?.mode || 'live',
        health,
        dataset,
        incidents,
        error: null,
      });
      setSelectedId((current) => current || incidents[0]?.incident_id || null);
    } catch (error) {
      // The API is not running: fall back to the committed Module 1/3 output.
      // Everything stays visibly labelled as the bundled preview, and AI triage
      // is disabled because no backend can validate a verdict.
      const incidents = bundledIncidents();
      setState({
        status: 'offline',
        health: null,
        dataset: bundledDataset(),
        incidents,
        error: error.message,
      });
      setSelectedId((current) => current || incidents[0]?.incident_id || null);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const selectPage = useCallback((nextPage) => {
    setPage(nextPage);
    setSidebarOpen(false);
  }, []);

  const openIncident = useCallback(
    (incidentId) => {
      setSelectedId(incidentId);
      selectPage('review');
    },
    [selectPage],
  );

  const handleDataChanged = useCallback(() => {
    setAuditToken((token) => token + 1);
    refresh();
  }, [refresh]);

  return (
    <div className="app">
      <Sidebar
        page={page}
        open={sidebarOpen}
        onSelect={selectPage}
        status={{ mode: state.status, ai: state.health?.ai }}
        incidentCount={state.incidents.length}
      />

      {sidebarOpen ? (
        <button
          type="button"
          className="scrim"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <div className="main">
        <header className="topbar">
          <button type="button" className="icon-btn" aria-label="Open navigation" onClick={() => setSidebarOpen(true)}>
            <Icon name="incidents" size={18} />
          </button>
          <span className="topbar-title">SOC Triage</span>
          <span className={`env-dot env-${state.status}`} aria-hidden="true" />
        </header>

        {state.status === 'loading' ? (
          <div className="loading-screen">
            <span className="spinner large" aria-hidden="true" />
            <p>Loading incidents…</p>
          </div>
        ) : (
          <main className="content">
            {state.status === 'offline' ? (
              <div className="banner info">
                <Icon name="database" size={15} />
                <span>
                  Backend offline — showing the committed Module 1/3 output. AI triage needs
                  <span className="mono"> python -m services.api</span>.
                </span>
              </div>
            ) : null}

            {page === 'dashboard' ? (
              <Dashboard
                dataset={state.dataset}
                incidents={state.incidents}
                mode={state.status}
                onOpen={openIncident}
                onReview={() => selectPage('review')}
                onRefresh={refresh}
              />
            ) : null}

            {page === 'review' ? (
              <AlertReview
                incidents={state.incidents}
                mode={state.status}
                health={state.health}
                selectedId={selectedId}
                onSelect={setSelectedId}
                onDataChanged={handleDataChanged}
              />
            ) : null}

            {page === 'audit' ? <AuditLog mode={state.status} refreshToken={auditToken} /> : null}
          </main>
        )}
      </div>
    </div>
  );
}
