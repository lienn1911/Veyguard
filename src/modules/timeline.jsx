import React from 'react';
import Icon from '../components/Icon.jsx';
import { formatNumber, formatTime } from '../lib/format.js';

function techniqueLabel(technique) {
  if (!technique || technique === 'Unmapped') return { id: 'Unmapped', name: null };
  if (typeof technique === 'string') return { id: technique, name: null };
  return { id: technique.id, name: technique.name };
}

export default function Timeline({ events = [], totalFlows, onInspect }) {
  const flows = events.filter((event) => event.record_type === 'flow').length;

  return (
    <section className="timeline" aria-label="Incident timeline">
      <div className="section-head">
        <div>
          <p className="eyebrow">Module 3</p>
          <h3>Timeline</h3>
        </div>
        <span className="chip chip-muted">
          {flows} sampled flows · {formatNumber(totalFlows)} total
        </span>
      </div>

      {events.length === 0 ? (
        <div className="empty small">
          <Icon name="clock" size={18} />
          <p>No timeline events were reconstructed for this incident.</p>
        </div>
      ) : (
        <ol className="timeline-list">
          {events.map((event) => {
            const technique = techniqueLabel(event.technique);
            const unmapped = technique.id === 'Unmapped';
            return (
              <li key={`${event.record_type}-${event.evidence_id}`}>
                <time className="mono">{formatTime(event.timestamp)}</time>
                <span className={`tl-dot tl-${event.record_type}`} aria-hidden="true" />
                <div className="tl-body">
                  <div className="tl-title">
                    <strong>
                      {event.record_type === 'alert' ? 'Detection rule matched' : event.title}
                    </strong>
                    <span className={`tag tag-${event.record_type}`}>{event.record_type}</span>
                  </div>
                  <div className="tl-meta">
                    <button
                      type="button"
                      className="chip chip-evidence mono"
                      onClick={() => onInspect && onInspect(event.evidence_id)}
                    >
                      <Icon name="hash" size={11} />
                      {event.evidence_id}
                    </button>
                    <span className={`chip ${unmapped ? 'chip-muted' : 'chip-mitre'}`}>
                      <Icon name={unmapped ? 'info' : 'target'} size={11} />
                      {unmapped ? 'Unmapped technique' : `${technique.id} · ${technique.name}`}
                    </span>
                    {event.source_file ? (
                      <span className="chip chip-muted" title={event.source_file}>
                        CSV row {event.source_row}
                      </span>
                    ) : null}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}

      <p className="panel-note">
        Events are ordered deterministically from recorded evidence. Techniques marked Unmapped were
        not mapped by Module 3; the interface does not infer them.
      </p>
    </section>
  );
}
