import React, { useState } from 'react';

export default function Timeline({ events, onEvidence }) {
  const [showAll, setShowAll] = useState(false);
  const preview = events.filter((event, index) => event.record_type === 'alert' || index < 4);
  const visible = showAll ? events : preview.slice(0, 8);
  const alertCount = events.filter((event) => event.record_type === 'alert').length;
  const exampleCount = events.length - alertCount;

  return <section className="timeline-section" aria-label="Event order">
    <div className="process-panel-head"><h3>Timeline</h3><p>{alertCount} alerts · {exampleCount} example records</p></div>
    <ol className={`event-list${showAll ? ' all-events' : ''}`}>{visible.map((event) => <li key={`${event.record_type}-${event.evidence_id}`}><time dateTime={event.timestamp}>{event.timestamp.slice(11, 16)}</time><div className="event-line"><strong>{event.record_type === 'alert' ? 'Alert raised' : 'Network activity recorded'}</strong><div className="event-meta"><button type="button" className="evidence-link" onClick={() => onEvidence(event.evidence_id)} aria-label={`View record ${event.evidence_id}`}>View record</button></div></div></li>)}</ol>
    {events.length > visible.length && <button className="process-next secondary" type="button" onClick={() => setShowAll(true)}>Show all {events.length} events</button>}
    {showAll && <button className="process-next secondary" type="button" onClick={() => setShowAll(false)}>Show fewer</button>}
  </section>;
}
