import React from 'react';
import Icon from './Icon.jsx';
import { formatNumber, formatTimestamp } from '../lib/format.js';

function FlowDetail({ flow, onClose }) {
  if (!flow) return null;
  const rows = [
    ['Flow ID', flow.flow_id],
    ['Timestamp', formatTimestamp(flow.timestamp)],
    ['Source', `${flow.source_ip}:${flow.source_port}`],
    ['Destination', `${flow.destination_ip}:${flow.destination_port}`],
    ['Packets', formatNumber(flow.packet_count)],
    ['Source file', flow.source_file],
    ['CSV row', flow.source_row],
    ['Original flow id', flow.original_flow_id],
  ];
  return (
    <div className="evidence-detail">
      <div className="evidence-detail-head">
        <span className="credential-label">
          <Icon name="hash" size={13} /> Evidence record
        </span>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close evidence detail">
          <Icon name="close" size={14} />
        </button>
      </div>
      <dl className="facts facts-tight">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd className="mono">{value === '' || value === null || value === undefined ? '—' : value}</dd>
          </div>
        ))}
      </dl>
      {flow.reference_label ? (
        <p className="reference-label">
          <Icon name="info" size={12} />
          Dataset reference: <strong>{flow.reference_label}</strong> — evaluation only, never shown
          to the agent.
        </p>
      ) : null}
    </div>
  );
}

function AlertDetail({ alert, onClose }) {
  if (!alert) return null;
  return (
    <div className="evidence-detail">
      <div className="evidence-detail-head">
        <span className="credential-label">
          <Icon name="alert" size={13} /> Detection alert
        </span>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close alert detail">
          <Icon name="close" size={14} />
        </button>
      </div>
      <dl className="facts facts-tight">
        <div>
          <dt>Alert ID</dt>
          <dd className="mono">{alert.alert_id}</dd>
        </div>
        <div>
          <dt>Rule</dt>
          <dd>{alert.type}</dd>
        </div>
        <div>
          <dt>Aggregated flows</dt>
          <dd>{formatNumber(alert.flow_count)}</dd>
        </div>
        <div>
          <dt>Timestamp</dt>
          <dd className="mono">{formatTimestamp(alert.timestamp)}</dd>
        </div>
      </dl>
      <p className="panel-note">{alert.rule_basis}</p>
    </div>
  );
}

export default function EvidencePanel({ evidence, focusId, onFocus }) {
  const flows = evidence?.flows || [];
  const alert = evidence?.alert;
  const focusedFlow = flows.find((flow) => flow.flow_id === focusId);
  const focusedAlert = alert && alert.alert_id === focusId ? alert : null;

  return (
    <section className="panel evidence" aria-label="Evidence">
      <div className="section-head">
        <div>
          <p className="eyebrow">Evidence</p>
          <h3>Sampled flow records</h3>
        </div>
        <span className="chip chip-muted">
          {evidence?.counts?.registered_evidence ?? flows.length} IDs
        </span>
      </div>

      {alert ? (
        <button type="button" className="evidence-alert" onClick={() => onFocus(alert.alert_id)}>
          <span className={`tag tag-${String(alert.type).toLowerCase()}`}>{alert.type}</span>
          <span className="mono">{alert.alert_id}</span>
          <span className="muted">{alert.rule_basis}</span>
        </button>
      ) : null}

      {focusedFlow ? <FlowDetail flow={focusedFlow} onClose={() => onFocus(null)} /> : null}
      {focusedAlert ? <AlertDetail alert={focusedAlert} onClose={() => onFocus(null)} /> : null}

      <div className="table-wrap">
        <table className="table table-compact">
          <thead>
            <tr>
              <th>Evidence ID</th>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th className="num">Packets</th>
              <th className="num">CSV row</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((flow) => (
              <tr
                key={flow.flow_id}
                className={`row-clickable${focusId === flow.flow_id ? ' is-focused' : ''}`}
                onClick={() => onFocus(flow.flow_id)}
              >
                <td className="mono">{flow.flow_id}</td>
                <td className="mono muted">{formatTimestamp(flow.timestamp)}</td>
                <td className="mono">
                  {flow.source_ip}:{flow.source_port}
                </td>
                <td className="mono">
                  {flow.destination_ip}:{flow.destination_port}
                </td>
                <td className="num">{formatNumber(flow.packet_count)}</td>
                <td className="num muted">{flow.source_row}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {flows.length === 0 ? <p className="muted small">No sampled flow records.</p> : null}
      </div>

      <p className="panel-note">
        Evidence IDs are the only references the agent may cite. Aggregated counts come from
        Module 1's one-minute grouping; these rows are the retained sample.
      </p>
    </section>
  );
}
