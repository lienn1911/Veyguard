import React, { useState } from 'react';
import AlertReview from './components/AlertReview.jsx';
import Dashboard from './components/Dashboard.jsx';
import Sidebar from './components/Sidebar.jsx';

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  function selectPage(nextPage) {
    setPage(nextPage);
    setSidebarOpen(false);
  }

  return (
    <div className="shell">
      <Sidebar page={page} open={sidebarOpen} onSelect={selectPage} />

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
        </header>

        <main className="main-content">
          {page === 'review' ? (
            <AlertReview />
          ) : (
            <Dashboard onReview={() => selectPage('review')} />
          )}
        </main>
      </div>
    </div>
  );
}
