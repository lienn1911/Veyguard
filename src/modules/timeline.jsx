import React, { useState } from 'react';

const minuteOf = (value) => value?.slice(0, 16);
const readable = (value) => value?.replace('T', ' ') || '—';
const count = (value) => new Intl.NumberFormat('en-US').format(value);
const compact = (value) => new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);

export const attackReferences = {
  PortScan: { id: 'T1046', name: 'Network Service Discovery' },
  DDoS: { id: 'T1498', name: 'Network Denial of Service' },
};

export function ruleCriteria(type, rules) {
  if (type === 'DoS') return `Project rule: at least ${count(rules.dos_min_flows)} flows and ${count(rules.dos_min_packets)} packets in one minute, at most ${rules.dos_max_destination_ports} destination ports, and at least ${rules.dos_min_source_ports} source ports.`;
  if (type === 'PortScan') return `Project rule: at least ${rules.portscan_min_flows} flows and ${rules.portscan_min_destination_ports} destination ports in one minute, plus either ${rules.portscan_min_source_port_ratio}× as many source ports or at least ${rules.portscan_high_density_min_destination_ports} destination ports with ${rules.portscan_high_density_min_source_ports} source ports.`;
  if (type === 'BruteForce') return `Project rule: at least ${count(rules.bruteforce_min_flows_to_login_port)} connections from one source to one destination's FTP (21) or SSH (22) port in one minute. Flow records do not show login success or failure.`;
  if (type === 'NeedsReview') return `Review candidate: at least ${count(rules.unclassified_min_flows)} flows and ${count(rules.unclassified_min_packets)} packets in one minute without a known attack rule match.`;
  return null;
}

export function buildTimelineMinutes({ incident, alerts = [], events = [] }) {
  const alertsByMinute = new Map();
  const samplesByMinute = new Map();
  for (const alert of alerts) {
    const key = minuteOf(alert.timestamp);
    if (!alertsByMinute.has(key)) alertsByMinute.set(key, []);
    alertsByMinute.get(key).push(alert);
  }
  for (const event of events.filter((item) => item.record_type === 'flow')) {
    const key = minuteOf(event.timestamp);
    if (!samplesByMinute.has(key)) samplesByMinute.set(key, []);
    samplesByMinute.get(key).push(event);
  }
  const keys = [...alertsByMinute.keys()].sort();
  const first = minuteOf(incident?.window_start) || keys[0];
  const last = minuteOf(incident?.window_end) || keys.at(-1);
  if (!first || !last) return [];
  const start = Date.parse(`${first}:00Z`);
  const end = Date.parse(`${last}:00Z`);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return [];
  const minutes = [];
  for (let time = start; time <= end; time += 60000) {
    const key = new Date(time).toISOString().slice(0, 16);
    const minuteAlerts = alertsByMinute.get(key) || [];
    minutes.push({ key, alerts: minuteAlerts, samples: samplesByMinute.get(key) || [], records: minuteAlerts.reduce((sum, item) => sum + (Number(item.flow_count) || 0), 0) });
  }
  return minutes;
}

export default function Timeline({ incident, events = [], alerts = [], selectedMinute, onSelectMinute, onEvidence }) {
  const [localSelectedKey, setLocalSelectedKey] = useState(null);
  const minutes = buildTimelineMinutes({ incident, alerts, events });
  const alertMinutes = minutes.filter((item) => item.alerts.length);
  const peak = alertMinutes.reduce((best, item) => !best || item.records > best.records ? item : best, null);
  const selected = minutes.find((item) => item.key === (localSelectedKey || selectedMinute || peak?.key)) || null;
  const totalMatches = alertMinutes.reduce((sum, item) => sum + item.records, 0);
  const sampleCount = events.filter((item) => item.record_type === 'flow').length;
  const gapCount = minutes.length - alertMinutes.length;
  if (!minutes.length) return <section className="traffic-timeline-empty">No dated events are available for this case.</section>;

  const width = Math.max(720, minutes.length * 52);
  const height = 292;
  const left = 84;
  const right = width - 28;
  const top = 28;
  const bottom = 218;
  const maxValue = Math.ceil((peak?.records || 1) / 1000) * 1000 || 1;
  const points = minutes.map((item, index) => ({ ...item,
    x: minutes.length === 1 ? (left + right) / 2 : left + (index / (minutes.length - 1)) * (right - left),
    y: bottom - (item.records / maxValue) * (bottom - top),
  }));
  const selectedPoint = points.find((item) => item.key === selected?.key);
  const labels = [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])];
  const multipleDays = minutes[0].key.slice(0, 10) !== minutes.at(-1).key.slice(0, 10);

  return <section className="traffic-timeline" aria-label="Case event timeline">
    <div className="timeline-meaning"><div><span>CASE CHRONOLOGY</span><h3>How this case developed</h3><p>First rule match at {readable(alertMinutes[0]?.key)} UTC. The busiest matched minute was {readable(peak?.key)} UTC with {count(peak?.records || 0)} rule-matched flows. {gapCount ? `${gapCount} ${gapCount === 1 ? 'minute has' : 'minutes have'} no exported rule match; that does not mean there was no traffic.` : 'Every minute in this case window has a rule match.'}</p></div><div className="timeline-meaning-stats"><div><strong>{alertMinutes.length} / {minutes.length}</strong><small>alert minutes / case minutes</small></div><div><strong>{count(totalMatches)}</strong><small>rule-matched flows</small></div><div><strong>{count(sampleCount)}</strong><small>linked sample records</small></div></div></div>
    <p className="traffic-timeline-caption">The chart covers the complete case time window. Bars show aggregated rule matches, while linked flow records are samples. Blank minutes have no exported rule match; full network traffic is not available in this preview.</p>
    <div className="traffic-timeline-chart-scroll"><div className="traffic-timeline-chart" style={{ width, height }}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        {[0, .5, 1].map((fraction) => { const y = bottom - fraction * (bottom - top); return <g key={fraction}><line x1={left} x2={right} y1={y} y2={y} stroke="#e9e1f1" strokeDasharray="4 5" /><text x={left - 24} y={y + 4} textAnchor="end" fill="#8b7a9d" fontSize="11">{compact(Math.round(maxValue * fraction))}</text></g>; })}
        <text x="17" y={(top + bottom) / 2} transform={`rotate(-90 17 ${(top + bottom) / 2})`} textAnchor="middle" fill="#705f87" fontSize="11" fontWeight="600">Matched flows per minute</text>
        {points.map((point) => point.alerts.length ? <rect key={point.key} x={point.x - 12} y={point.y} width="24" height={Math.max(2, bottom - point.y)} rx="4" fill={selected?.key === point.key ? '#563592' : '#9572c8'} opacity={selected?.key === point.key ? '1' : '.82'} /> : <circle key={point.key} cx={point.x} cy={bottom} r="4" fill="#fff" stroke="#cbbbdc" strokeWidth="2" />)}
        {selectedPoint && <line x1={selectedPoint.x} x2={selectedPoint.x} y1={top} y2={bottom} stroke="#a88bd0" strokeWidth="1" strokeDasharray="3 4" />}
        {labels.map((index) => <text key={index} x={points[index].x} y="252" textAnchor={index === 0 && points.length > 1 ? 'start' : index === points.length - 1 && points.length > 1 ? 'end' : 'middle'} fill="#887796" fontSize="11">{multipleDays ? readable(points[index].key) : points[index].key.slice(11)}</text>)}
        <text x={(left + right) / 2} y="280" textAnchor="middle" fill="#705f87" fontSize="11" fontWeight="600">Case time (UTC){multipleDays ? '' : ` · ${minutes[0].key.slice(0, 10)}`}</text>
      </svg>
      {points.map((point) => <button type="button" key={point.key} className={`traffic-timeline-point${selected?.key === point.key ? ' selected' : ''}${point.alerts.length ? '' : ' gap'}`} style={{ left: point.x, top: point.alerts.length ? point.y : bottom, height: point.alerts.length ? Math.max(12, bottom - point.y) : 14 }} aria-label={`${readable(point.key)} UTC: ${point.alerts.length ? `${count(point.records)} matched flows, ${point.alerts.length} alerts` : 'no exported rule match'}; show details`} aria-pressed={selected?.key === point.key} onClick={() => setLocalSelectedKey(point.key)} />)}
    </div></div>
    <div className="traffic-event-history" aria-label="Full case-minute timeline"><h3>Case timeline</h3><ol>{minutes.map((minute) => <li key={minute.key}><span className="traffic-event-time">{readable(minute.key)} UTC</span><span className="traffic-event-node" aria-hidden="true" /><button type="button" className={minute.alerts.length ? '' : 'gap'} aria-pressed={selected?.key === minute.key} onClick={() => setLocalSelectedKey(minute.key)}><span><strong>{minute.alerts.length ? `${minute.alerts.length} ${minute.alerts.length === 1 ? 'alert' : 'alerts'}` : 'No rule match'}</strong>{minute.alerts.length > 0 && <span className="traffic-event-types">{[...new Set(minute.alerts.map((alert) => alert.type))].join(', ')}</span>}</span><span className="traffic-event-count">{minute.alerts.length ? `${count(minute.records)} matched flows` : 'Traffic unknown'} <span aria-hidden="true">›</span></span></button></li>)}</ol></div>
    {selected && <div className="traffic-timeline-detail" aria-live="polite"><div className="traffic-timeline-detail-head"><h4>{readable(selected.key)} UTC</h4><strong>{selected.alerts.length ? `${count(selected.records)} matched flows` : 'No exported rule match'}</strong></div>{selected.alerts.length ? <><div className="traffic-timeline-summary"><div className="traffic-timeline-facts"><span>{selected.alerts.length} {selected.alerts.length === 1 ? 'alert' : 'alerts'}</span><span>{selected.samples.length} linked sample {selected.samples.length === 1 ? 'record' : 'records'}</span>{[...new Set(selected.alerts.map((alert) => alert.type))].map((type) => <span className={`alert-type-chip ${type.toLowerCase()}`} key={type}>{type}</span>)}</div><button type="button" onClick={() => onSelectMinute?.(selected.key)}>Inspect this minute’s evidence</button></div><div className="timeline-minute-evidence"><h5>Why this minute matters</h5>{selected.alerts.map((alert) => <div key={alert.alert_id}><p><strong>{alert.type} rule matched</strong> · {count(alert.flow_count)} flows</p><p>{alert.rule_basis || 'Detection details unavailable.'}</p><button type="button" onClick={() => onEvidence?.(alert.alert_id)}>{alert.alert_id} · Open alert evidence</button></div>)}{selected.samples.length > 0 && <p className="timeline-sample-note">{selected.samples.length} sampled flow records are linked to this minute. Open Evidence to inspect them; the samples are not the full flow set.</p>}</div></> : <p className="timeline-minute-gap">No rule match was exported for this minute. The preview cannot tell whether ordinary or suspicious traffic occurred here.</p>}</div>}
  </section>;
}
