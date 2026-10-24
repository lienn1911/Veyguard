import React, { useEffect, useState } from 'react';

const minuteOf = (value) => value?.slice(0, 16);
const count = (value) => new Intl.NumberFormat('en-US').format(value);
const ruleLabel = (type) => type === 'NeedsReview' ? 'Review threshold' : `${type} rule`;

export const attackReferences = {
  PortScan: { id: 'T1046', name: 'Network Service Discovery' },
  DDoS: { id: 'T1498', name: 'Network Denial of Service' },
};

export function ruleCriteria(type, rules) {
  if (!rules) return null;
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

export default function Timeline({ incident, alerts = [], rawContext, selectedMinute, onSelectMinute, evidenceContent }) {
  const [visibleCount, setVisibleCount] = useState(12);
  const alertMinutes = buildTimelineMinutes({ incident, alerts });
  const hasRawCounts = Boolean(rawContext?.minutes?.length);
  const rows = hasRawCounts
    ? rawContext.minutes.map((item) => ({ key: item.minute, flows: item.flows }))
    : alertMinutes.map((item) => ({ key: item.key, flows: item.records }));
  useEffect(() => { setVisibleCount(12); }, [incident?.incident_id]);
  useEffect(() => {
    if (!selectedMinute) return;
    const index = rows.findIndex((item) => item.key === selectedMinute);
    if (index >= 0) setVisibleCount((current) => Math.max(current, index + 1));
  }, [selectedMinute, rows.length]);
  if (!rows.length) return <section className="traffic-timeline-empty">No dated events are available for this case.</section>;

  const activeKey = selectedMinute;
  const sameDay = rows[0].key.slice(0, 10) === rows.at(-1).key.slice(0, 10);
  const dateRange = sameDay ? rows[0].key.slice(0, 10) : `${rows[0].key.slice(0, 10)} – ${rows.at(-1).key.slice(0, 10)}`;
  const timeRange = `${rows[0].key.slice(11)} – ${rows.at(-1).key.slice(11)} UTC`;

  return <section className="traffic-timeline case-minute-timeline" aria-label="Case event timeline">
    <div className="incident-section-heading timeline-heading"><div><h2 id="incident-timeline">Timeline</h2><p className="case-step-purpose">Select a minute to see why it was flagged and view its records.</p></div><p className="case-minute-range"><strong>{dateRange}</strong><time>{timeRange}</time></p></div>
    <ol className="case-minute-list">{rows.slice(0, visibleCount).map((item) => {
      const minuteAlerts = alerts.filter((alert) => minuteOf(alert.timestamp) === item.key);
      const expanded = activeKey === item.key;
      const empty = item.flows === 0 && minuteAlerts.length === 0;
      const tone = minuteAlerts.some((alert) => alert.type !== 'NeedsReview') ? 'rule-alert' : minuteAlerts.length ? 'review-alert' : '';
      const label = minuteAlerts.length ? minuteAlerts.map((alert) => ruleLabel(alert.type)).join(', ') : 'No rule flagged';
      return <li key={item.key} className={`${expanded ? 'expanded ' : ''}${tone}${empty ? ' empty' : ''}`}>
        <time dateTime={`${item.key}:00`}>{item.key.slice(11)}</time><span className="case-minute-node" aria-hidden="true" />
        <div className="case-minute-card">{empty
          ? <div className="case-minute-toggle"><strong>0 records</strong><span>No rule flagged</span></div>
          : <button type="button" className="case-minute-toggle" aria-expanded={expanded} onClick={() => onSelectMinute?.(expanded ? null : item.key)}><strong>{count(item.flows)} {hasRawCounts ? 'records' : 'flagged flows'}</strong><span className={tone ? 'case-minute-status' : ''}>{label}</span><span className="case-minute-chevron" aria-hidden="true">{expanded ? '−' : '+'}</span></button>}
          {expanded && <div className="case-minute-detail">{evidenceContent}</div>}
        </div>
      </li>;
    })}</ol>
    {visibleCount < rows.length && <button type="button" className="case-minute-more" onClick={() => setVisibleCount((current) => Math.min(current + 12, rows.length))}>Show next minutes · {rows.length - visibleCount} remaining</button>}
  </section>;
}
