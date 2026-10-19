import React from 'react';

export default function Timeline({ events }) {
  return <section className="timeline-section" aria-label="Incident timeline">
    <div className="timeline-head"><h3>Timeline</h3><p>{events.filter((event) => event.record_type === 'flow').length} sampled flows</p></div>
    <ol className="event-list">{events.map((event) => <li key={`${event.record_type}-${event.evidence_id}`}>
      <time dateTime={event.timestamp}>{event.timestamp.slice(11, 16)}</time>
      <div className="event-line"><strong>{event.record_type === 'flow' ? event.title.replace(/^.* → /, 'Flow → ') : 'Rule matched'}</strong><div className="event-meta"><code>{event.evidence_id}</code><span>{typeof event.technique === 'string' ? event.technique : `${event.technique.id} · ${event.technique.name}`}</span>{event.source_file && <span title={event.source_file}>CSV row {event.source_row}</span>}</div></div>
    </li>)}</ol>
  </section>;
}
