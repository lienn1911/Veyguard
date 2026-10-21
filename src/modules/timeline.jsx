import React, { useState } from 'react';

const minuteOf = (timestamp) => timestamp.slice(0, 16);
const count = (value) => new Intl.NumberFormat('en-US').format(value);
const compact = (value) => new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
export const attackReferences = {
  PortScan: { id: 'T1046', name: 'Network Service Discovery' },
  DDoS: { id: 'T1498', name: 'Network Denial of Service' },
};

export function ruleCriteria(type, rules) {
  if (type === 'DoS') return `Project rule: at least ${count(rules.dos_min_flows)} flows and ${count(rules.dos_min_packets)} packets in one minute, at most ${rules.dos_max_destination_ports} destination ports, and at least ${rules.dos_min_source_ports} source ports.`;
  if (type === 'PortScan') return `Project rule: at least ${rules.portscan_min_flows} flows and ${rules.portscan_min_destination_ports} destination ports in one minute, plus either ${rules.portscan_min_source_port_ratio}× as many source ports or at least ${rules.portscan_high_density_min_destination_ports} destination ports with ${rules.portscan_high_density_min_source_ports} source ports.`;
  return null;
}

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

export default function Timeline({ events, alerts = [], selectedMinute, onSelectMinute }) {
  const [localSelectedKey, setLocalSelectedKey] = useState(null);
  const [hoveredKey, setHoveredKey] = useState(null);
  const windows = alertWindows(alerts, events);
  const peak = windows.reduce((best, item) => !best || item.records > best.records ? item : best, null);
  const selected = windows.find((item) => item.key === (selectedMinute === undefined ? localSelectedKey : selectedMinute)) || null;
  const focus = windows.find((item) => item.key === hoveredKey) || selected;

  if (!windows.length) return <section className="traffic-timeline-empty">No alert minutes are available for this case.</section>;

  const width = Math.max(720, windows.length * 52);
  const height = 292;
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
  const guide = points.find((item) => item.key === focus?.key);
  const labels = [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])];
  const spansMultipleDays = windows[0].key.slice(0, 10) !== windows.at(-1).key.slice(0, 10);

  return <section className="traffic-timeline" aria-label="Interactive alert history graph. Horizontal axis: detection time in UTC. Vertical axis: rule-matched flow records per minute.">
    <p className="traffic-timeline-caption">Rule-matched traffic by alert minute. Gaps mean no alert minute is plotted; this is not a chart of all network traffic.</p>
    <div className="traffic-timeline-chart-scroll"><div className="traffic-timeline-chart" style={{ width, height }}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        {[0, .5, 1].map((fraction) => { const y = bottom - fraction * (bottom - top); return <g key={fraction}><line x1={left} x2={right} y1={y} y2={y} stroke="#e9e1f1" strokeDasharray="4 5" /><text x={left - 24} y={y + 4} textAnchor="end" fill="#8b7a9d" fontSize="11">{compact(Math.round(maxValue * fraction))}</text></g>; })}
        <text x="17" y={(top + bottom) / 2} transform={`rotate(-90 17 ${(top + bottom) / 2})`} textAnchor="middle" fill="#705f87" fontSize="11" fontWeight="600">Matched flows per minute</text>
        {points.map((point) => <rect key={point.key} x={point.x - 12} y={point.y} width="24" height={Math.max(2, bottom - point.y)} rx="4" fill={selected?.key === point.key ? '#563592' : '#9572c8'} opacity={selected?.key === point.key ? '1' : '.82'} />)}
        {guide && <line x1={guide.x} x2={guide.x} y1={top} y2={bottom} stroke="#a88bd0" strokeWidth="1" strokeDasharray="3 4" />}
        {labels.map((index) => <text key={index} x={points[index].x} y="252" textAnchor={index === 0 && points.length > 1 ? 'start' : index === points.length - 1 && points.length > 1 ? 'end' : 'middle'} fill="#887796" fontSize="11">{spansMultipleDays ? points[index].key.replace('T', ' ') : points[index].key.slice(11)}</text>)}
        <text x={(left + right) / 2} y="280" textAnchor="middle" fill="#705f87" fontSize="11" fontWeight="600">Alert time (UTC){spansMultipleDays ? '' : ` · ${windows[0].key.slice(0, 10)}`}</text>
      </svg>
      {points.map((point) => <button type="button" key={point.key} className={`traffic-timeline-point${selected?.key === point.key ? ' selected' : ''}`} style={{ left: point.x, top: point.y, height: Math.max(12, bottom - point.y) }} aria-label={`${point.key.replace('T', ' ')}, ${count(point.records)} rule-matched traffic records; show details`} aria-pressed={selected?.key === point.key} title={`${point.key.replace('T', ' ')} · ${count(point.records)} records`} onMouseEnter={() => setHoveredKey(point.key)} onMouseLeave={() => setHoveredKey(null)} onFocus={() => setHoveredKey(point.key)} onBlur={() => setHoveredKey(null)} onClick={() => { setLocalSelectedKey(point.key); onSelectMinute?.(point.key); }} />)}
    </div></div>
    <div className="traffic-event-history" aria-label="Alert timeline">
      <h3>Alert timeline</h3>
      <ol>{windows.map((window) => <li key={window.key}><span className="traffic-event-time">{window.key.replace('T', ' ')} UTC</span><span className="traffic-event-node" aria-hidden="true" /><button type="button" onClick={() => onSelectMinute?.(window.key)}><span><strong>{window.alerts.length} {window.alerts.length === 1 ? 'alert' : 'alerts'}</strong><span className="traffic-event-types">{[...new Set(window.alerts.map((alert) => alert.type))].join(', ')}</span></span><span className="traffic-event-count">{count(window.records)} matched flows <span aria-hidden="true">›</span></span></button></li>)}</ol>
    </div>
    {selected && <div className="traffic-timeline-detail" aria-live="polite"><div className="traffic-timeline-detail-head"><h4>{selected.key.replace('T', ' ')}</h4><strong>{count(selected.records)} traffic records</strong></div>
      <div className="traffic-timeline-summary"><div className="traffic-timeline-facts"><span>{selected.alerts.length} {selected.alerts.length === 1 ? 'alert' : 'alerts'}</span>{[...new Set(selected.alerts.map((alert) => alert.type))].map((type) => <span className={`alert-type-chip ${type.toLowerCase()}`} key={type}>{type}</span>)}</div></div>
    </div>}
  </section>;
}
