import React, { useState } from 'react';
import Icon from '../components/Icon.jsx';

/**
 * Module 4 surface.
 *
 * The approval control only exists when the backend exposes a working endpoint.
 * With Module 4 unimplemented the panel says so and offers no approve button -
 * a frontend-only "Approved" badge would be a fake audit record.
 */
export default function Recommendations({ state, incidentId, onApprove }) {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const available = Boolean(state?.available);
  const items = state?.items || [];

  async function approve(recommendation) {
    setBusy(recommendation.id);
    setError(null);
    try {
      await onApprove(recommendation.id);
    } catch (problem) {
      setError(problem.message || 'Approval was refused by the backend.');
    } finally {
      setBusy(null);
    }
  }

  if (!available) {
    return (
      <section className="panel module-pending" aria-label="Recommendations">
        <div className="section-head">
          <div>
            <p className="eyebrow">Module 4</p>
            <h3>Next-step recommendations</h3>
          </div>
          <span className="chip chip-muted">Not connected</span>
        </div>
        <div className="pending-body">
          <Icon name="lock" size={20} />
          <div>
            <strong>No recommendations are available yet.</strong>
            <p>
              Module 4 (recommendations, human approval and audit logging) has not been wired into
              this API. The interface intentionally shows nothing rather than simulated steps, and
              approval stays disabled because no backend endpoint could record it.
            </p>
            <p className="mono small">{state?.detail || 'services/recommendations.py is empty.'}</p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="panel" aria-label="Recommendations">
      <div className="section-head">
        <div>
          <p className="eyebrow">Module 4</p>
          <h3>Next-step recommendations</h3>
        </div>
        <span className="chip chip-muted">{items.length} proposed</span>
      </div>
      <ul className="recommendation-list">
        {items.map((item) => (
          <li key={item.id}>
            <div>
              <strong>{item.title}</strong>
              <p>{item.detail}</p>
            </div>
            <button
              type="button"
              className="btn btn-quiet"
              disabled={busy === item.id || item.status === 'approved'}
              onClick={() => approve(item)}
            >
              {item.status === 'approved' ? 'Approved' : busy === item.id ? 'Approving…' : 'Approve'}
            </button>
          </li>
        ))}
      </ul>
      {error ? <p className="form-error">{error}</p> : null}
    </section>
  );
}
