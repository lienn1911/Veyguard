import React from 'react';
import Icon from '../components/Icon.jsx';

/**
 * Safe-closure guardrail surface (Module 5 integration).
 *
 * Shows which rules are actually enforced and by whom, so a reviewer can tell
 * the difference between "Module 5 validated this" and "Module 2's local rules
 * applied because Module 5 is not connected".
 */
export default function Guardrail({ guardrail, status }) {
  const connected = status?.connected;
  const source = guardrail?.source || (connected ? 'module5' : 'module2-local');
  const prohibited = guardrail?.prohibited_actions || [
    'close_incident',
    'dismiss_incident',
    'downgrade_severity',
  ];

  return (
    <section className="panel guardrail-panel" aria-label="Safe closure guardrail">
      <div className="section-head">
        <div>
          <p className="eyebrow">Module 5</p>
          <h3>Safe-closure guardrail</h3>
        </div>
        <span className={`chip ${connected ? 'chip-ok' : 'chip-warn'}`}>
          {connected ? 'Module 5 connected' : 'Local fallback'}
        </span>
      </div>

      <ul className="guardrail-rules">
        <li>
          <Icon name="lock" size={13} />
          <span>
            The agent cannot close, dismiss, or downgrade an incident, and cannot execute
            remediation.
          </span>
        </li>
        <li>
          <Icon name="user" size={13} />
          <span>
            A Likely Benign proposal for PortScan, DoS or DDoS requires explicit analyst
            confirmation.
          </span>
        </li>
        <li>
          <Icon name="shield" size={13} />
          <span>
            Verdicts are proposals; the analyst decision is stored separately in the backend.
          </span>
        </li>
      </ul>

      <p className="panel-note">
        Enforced by <span className="mono">{source}</span>. Prohibited actions:{' '}
        <span className="mono">{prohibited.slice(0, 4).join(', ')}</span>
        {prohibited.length > 4 ? '…' : ''}
      </p>
      {status && !connected ? (
        <p className="panel-note muted small">
          {status.detail}. Module 2's local rules apply until the Module 5 module exposes a
          compatible entry point.
        </p>
      ) : null}
    </section>
  );
}
