import React, { useState } from 'react';

const minuteOf = (timestamp) => timestamp.slice(0, 16);
const count = (value) => new Intl.NumberFormat('en-US').format(value);
const compact = (value) => new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);

function alertWindows(alerts, events) {
  const visibleMinutes = new Set(events.map((event) => minuteOf(event.timestamp)));
  const windows = new Map();
  for (const alert of alerts.filter((item) => visibleMinutes.has(minuteOf(item.timestamp)))) {
    const key = minuteOf(alert.timestamp);
    if (!windows.has(key)) windows.set(key, { key, alerts: [], records: 0 });
    const window = windows.get(key);
    window.alerts.push(alert);
    window.records += alert.flow_count;
  }
  return [...windows.values()].sort((a, b) => a.key.localeCompare(b.key));
}

export default function Timeline({ events, allEvents = events, alerts = [], flows = [], onEvidence, onSelectMinute, evidencePanel }) {
  const [selectedKey, setSelectedKey] = useState(null);
  const [hoveredKey, setHoveredKey] = useState(null);
  const windows = alertWindows(alerts, events);
  const peak = windows.reduce((best, item) => !best || item.records > best.records ? item : best, null);
  const selected = windows.find((item) => item.key === selectedKey) || null;
  const focus = windows.find((item) => item.key === hoveredKey) || selected;
  const samples = selected ? allEvents.filter((event) => event.record_type === 'flow' && minuteOf(event.timestamp) === selected.key) : [];
  const flowById = new Map(flows.map((flow) => [flow.flow_id, flow]));
  const techniques = selected ? [...new Map(allEvents.filter((event) => selected.alerts.some((alert) => alert.alert_id === event.evidence_id) && event.technique && typeof event.technique === 'object').map((event) => [event.technique.id, event.technique])).values()] : [];

  if (!windows.length) return <section className="traffic-timeline-empty">No alert minutes are available for this case.</section>;

  const width = Math.max(720, windows.length * 52);
  const height = 276;
  const left = 84;
  const right = width - 28;
  const top = 28;
  const bottom = 218;
  const maxValue = Math.ceil((peak?.records || 1) / 1000) * 1000 || 1;
  const times = windows.map((item) => Date.parse(`${item.key}:00Z`));
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const points = windows.map((item, index) => ({
    ...item,
    x: minTime === maxTime ? (left + right) / 2 : left + ((times[index] - minTime) / (maxTime - minTime)) * (right - left),
    y: bottom - (item.records / maxValue) * (bottom - top),
  }));
  const segments = points.reduce((groups, point, index) => {
    if (index === 0 || times[index] - times[index - 1] > 60_000) groups.push([]);
    groups.at(-1).push(point);
    return groups;
  }, []);
  const guide = points.find((item) => item.key === focus?.key);
  const labels = [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])];

  return <section className="traffic-timeline" aria-label="Interactive alert history graph">
    <div className="traffic-timeline-chart-scroll"><div className="traffic-timeline-chart" style={{ width, height }}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        <defs><linearGradient id="traffic-history-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#815cc2" stopOpacity=".24" /><stop offset="100%" stopColor="#815cc2" stopOpacity=".02" /></linearGradient></defs>
        {[0, .5, 1].map((fraction) => { const y = bottom - fraction * (bottom - top); return <g key={fraction}><line x1={left} x2={right} y1={y} y2={y} stroke="#e9e1f1" strokeDasharray="4 5" /><text x={left - 24} y={y + 4} textAnchor="end" fill="#8b7a9d" fontSize="11">{compact(Math.round(maxValue * fraction))}</text></g>; })}
        {segments.filter((segment) => segment.length > 1).map((segment) => { const line = segment.map((point) => `${point.x},${point.y}`).join(' '); return <g key={segment[0].key}><polygon points={`${segment[0].x},${bottom} ${line} ${segment.at(-1).x},${bottom}`} fill="url(#traffic-history-fill)" /><polyline points={line} fill="none" stroke="#7653b7" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" /></g>; })}
        {guide && <line x1={guide.x} x2={guide.x} y1={top} y2={bottom} stroke="#a88bd0" strokeWidth="1" strokeDasharray="3 4" />}
        {labels.map((index) => <text key={index} x={points[index].x} y="252" textAnchor={index === 0 && points.length > 1 ? 'start' : index === points.length - 1 && points.length > 1 ? 'end' : 'middle'} fill="#887796" fontSize="11">{points[index].key.slice(11)}</text>)}
      </svg>
      {points.map((point) => <button type="button" key={point.key} className={`traffic-timeline-point${selected?.key === point.key ? ' selected' : ''}`} style={{ left: point.x, top: point.y }} aria-label={`${point.key.replace('T', ' ')}, ${count(point.records)} rule-matched traffic records; show details`} aria-pressed={selected?.key === point.key} title={`${point.key.replace('T', ' ')} · ${count(point.records)} records`} onMouseEnter={() => setHoveredKey(point.key)} onMouseLeave={() => setHoveredKey(null)} onFocus={() => setHoveredKey(point.key)} onBlur={() => setHoveredKey(null)} onClick={() => { setSelectedKey(point.key); onSelectMinute?.(); }} />)}
    </div></div>
    {selected && <div className="traffic-timeline-detail" aria-live="polite"><div className="traffic-timeline-detail-head"><h4>{selected.key.replace('T', ' ')}</h4><strong>{count(selected.records)} traffic records</strong></div>
      <div className="traffic-timeline-facts"><span>{selected.alerts.length} {selected.alerts.length === 1 ? 'alert' : 'alerts'}</span><span>{samples.length} linked flow {samples.length === 1 ? 'record' : 'records'}</span>{techniques.map((item) => <span key={item.id}>MITRE {item.id} · {item.name}</span>)}</div>
      <div className="traffic-timeline-records"><h5>Why it was flagged</h5>{selected.alerts.map((alert) => <div className="traffic-timeline-alert" key={alert.alert_id}><div><strong>{alert.type} · {alert.source_ip} → {alert.destination_ip}</strong><p>{alert.rule_basis}</p><small>{alert.alert_id}</small></div><button type="button" onClick={() => onEvidence(alert.alert_id)}>View alert evidence</button></div>)}</div>
      {evidencePanel}
      {samples.length > 0 && <div className="traffic-timeline-samples"><div className="traffic-timeline-section-head"><h5>Network flow evidence <span>{samples.length} records</span></h5><p>Linked source records for this minute. The traffic total above counts all rule-matched flows.</p></div><div>{samples.map((event) => { const flow = flowById.get(event.evidence_id); return <button type="button" key={event.evidence_id} onClick={() => onEvidence(event.evidence_id)}><span><strong>{flow ? `${flow.source_ip}${flow.source_port ? `:${flow.source_port}` : ''} → ${flow.destination_ip}${flow.destination_port ? `:${flow.destination_port}` : ''}` : event.title}</strong><small>{flow?.source_file}{flow?.source_row ? ` · row ${flow.source_row}` : ''}</small></span><small>{event.evidence_id}</small></button>; })}</div></div>}
    </div>}
  </section>;
}
