import React, { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

const alertTitle = (alert) => alert.type === 'PortScan' ? 'Many ports checked' : alert.type === 'DDoS' ? 'Distributed traffic surge' : alert.type === 'DoS' ? 'Heavy network traffic' : alert.type === 'NeedsReview' ? 'Unclassified activity · needs review' : alert.type;
const time = (value) => value.replace('T', ' ').slice(0, 16);
const dates = [...new Set(data.alerts.map((alert) => alert.timestamp.slice(0, 10)))].sort();
const alertTypes = ['All', ...new Set(data.alerts.map((alert) => alert.type))];
const caseNumber = new Map(data.incidents.map((incident, index) => [incident.incident_id, index + 1]));
const dateCounts = data.alerts.reduce((counts, alert) => {
  const day = alert.timestamp.slice(0, 10);
  counts.set(day, (counts.get(day) || 0) + 1);
  return counts;
}, new Map());
const calendarMonths = new Intl.DateTimeFormat('en', { month: 'long', year: 'numeric', timeZone: 'UTC' });
const calendarMonthName = new Intl.DateTimeFormat('en', { month: 'long', timeZone: 'UTC' });

function FilterDropdown({ label, value, options, onChange, className = '' }) {
  const [open, setOpen] = useState(false);
  const root = useRef(null);
  const selected = options.find((option) => option.value === value);

  useEffect(() => {
    if (!open) return undefined;
    const closeOutside = (event) => {
      if (!root.current?.contains(event.target)) setOpen(false);
    };
    const closeEscape = (event) => {
      if (event.key === 'Escape') {
        setOpen(false);
        root.current?.querySelector('.alerts-dropdown-trigger')?.focus();
      }
    };
    document.addEventListener('pointerdown', closeOutside);
    document.addEventListener('keydown', closeEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOutside);
      document.removeEventListener('keydown', closeEscape);
    };
  }, [open]);

  return <div className={`alerts-dropdown ${className}${open ? ' open' : ''}`} ref={root}>
    <span className="alerts-dropdown-label">{label}</span>
    <div className="alerts-dropdown-control">
      <button type="button" className="alerts-dropdown-trigger" aria-label={`${label}: ${selected?.label}`} aria-expanded={open} aria-haspopup="listbox" onClick={() => setOpen(!open)}>
        <span>{selected?.label}</span><svg aria-hidden="true" viewBox="0 0 16 16"><path d="m4 6 4 4 4-4" /></svg>
      </button>
      {open && <div className="alerts-dropdown-menu" role="listbox" aria-label={label}>
        {options.map((option) => <button type="button" role="option" aria-selected={option.value === value} className={`alerts-dropdown-option${option.value === value ? ' selected' : ''}`} key={option.value} onClick={() => { onChange(option.value); setOpen(false); root.current?.querySelector('.alerts-dropdown-trigger')?.focus(); }}><span>{option.label}</span>{option.value === value && <span className="alerts-dropdown-check" aria-hidden="true">✓</span>}</button>)}
      </div>}
    </div>
  </div>;
}

function DateCalendar({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const [month, setMonth] = useState(() => {
    const initial = value === 'All' ? dates.at(-1) : value;
    return initial ? new Date(`${initial.slice(0, 7)}-01T00:00:00Z`) : new Date();
  });
  const root = useRef(null);
  const year = month.getUTCFullYear();
  const monthIndex = month.getUTCMonth();
  const leadingDays = (new Date(Date.UTC(year, monthIndex, 1)).getUTCDay() + 6) % 7;
  const daysInMonth = new Date(Date.UTC(year, monthIndex + 1, 0)).getUTCDate();
  const cells = Array.from({ length: leadingDays + daysInMonth }, (_, index) => index < leadingDays ? null : index - leadingDays + 1);
  const firstYear = Math.min(Number(dates[0]?.slice(0, 4)) || year, year) - 5;
  const lastYear = Math.max(new Date().getFullYear(), year) + 5;
  const years = Array.from({ length: lastYear - firstYear + 1 }, (_, index) => firstYear + index);

  useEffect(() => {
    if (!open) return undefined;
    const closeOutside = (event) => {
      if (!root.current?.contains(event.target)) setOpen(false);
    };
    const closeEscape = (event) => {
      if (event.key === 'Escape') {
        setOpen(false);
        root.current?.querySelector('.alerts-dropdown-trigger')?.focus();
      }
    };
    document.addEventListener('pointerdown', closeOutside);
    document.addEventListener('keydown', closeEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOutside);
      document.removeEventListener('keydown', closeEscape);
    };
  }, [open]);

  function moveMonth(offset) {
    setMonth(new Date(Date.UTC(year, monthIndex + offset, 1)));
  }

  return <div className={`alerts-dropdown alerts-date-picker${open ? ' open' : ''}`} ref={root}>
    <span className="alerts-dropdown-label">Date</span>
    <div className="alerts-dropdown-control">
      <button type="button" className="alerts-dropdown-trigger" aria-label={`Date: ${value === 'All' ? 'All sample dates' : value}`} aria-expanded={open} aria-haspopup="dialog" onClick={() => setOpen(!open)}>
        <span>{value === 'All' ? 'All sample dates' : value}</span><svg aria-hidden="true" viewBox="0 0 16 16"><path d="m4 6 4 4 4-4" /></svg>
      </button>
      {open && <div className="alerts-calendar" role="dialog" aria-label="Choose alert date">
        <div className="alerts-calendar-heading">
          <button type="button" className="alerts-calendar-arrow" aria-label="Previous month" onClick={() => moveMonth(-1)}><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m12 5-5 5 5 5" /></svg></button>
          <div className="alerts-calendar-title"><strong>{calendarMonthName.format(month)}</strong><select aria-label="Calendar year" value={year} onChange={(event) => setMonth(new Date(Date.UTC(Number(event.target.value), monthIndex, 1)))}>{years.map((option) => <option key={option} value={option}>{option}</option>)}</select></div>
          <button type="button" className="alerts-calendar-arrow" aria-label="Next month" onClick={() => moveMonth(1)}><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m8 5 5 5-5 5" /></svg></button>
        </div>
        <div className="alerts-calendar-grid" role="group" aria-label={calendarMonths.format(month)}>
          {['M', 'T', 'W', 'T', 'F', 'S', 'S'].map((day, index) => <span className="alerts-calendar-weekday" key={index}>{day}</span>)}
          {cells.map((day, index) => {
            if (!day) return <span key={`blank-${index}`} />;
            const dateValue = `${year}-${String(monthIndex + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
            const count = dateCounts.get(dateValue) || 0;
            return <button type="button" key={dateValue} className={`alerts-calendar-day${value === dateValue ? ' selected' : ''}${count ? ' has-alerts' : ''}`} aria-label={`${dateValue}${count ? `, ${count} alerts` : ', no alerts'}`} aria-pressed={value === dateValue} onClick={() => { onChange(dateValue); setOpen(false); root.current?.querySelector('.alerts-dropdown-trigger')?.focus(); }}>{day}{count > 0 && <span className="alerts-calendar-dot" aria-hidden="true" />}</button>;
          })}
        </div>
      </div>}
    </div>
  </div>;
}

export default function AlertQueue({ onOpenCase, selectedAlertId }) {
  const [selectedId, setSelectedId] = useState(selectedAlertId ?? null);
  const [query, setQuery] = useState('');
  const [type, setType] = useState('All');
  const [caseId, setCaseId] = useState('All');
  const [date, setDate] = useState('All');
  const [sort, setSort] = useState('newest');
  const [viewMode, setViewMode] = useState('alerts');
  const [expandedCaseId, setExpandedCaseId] = useState(data.alerts.find((alert) => alert.alert_id === selectedAlertId)?.incident_id || null);

  useEffect(() => {
    if (!selectedAlertId) return;
    setSelectedId(selectedAlertId);
    setExpandedCaseId(data.alerts.find((alert) => alert.alert_id === selectedAlertId)?.incident_id);
  }, [selectedAlertId]);

  const search = query.trim().toLowerCase();
  const alerts = data.alerts.filter((alert) =>
    (type === 'All' || alert.type === type)
    && (caseId === 'All' || alert.incident_id === caseId)
    && (date === 'All' || alert.timestamp.startsWith(date))
    && `${alertTitle(alert)} ${alert.type} ${alert.timestamp} ${alert.source_ip} ${alert.destination_ip} ${alert.alert_id} ${alert.rule_basis} ${alert.incident_id}`.toLowerCase().includes(search)
  ).sort((a, b) => sort === 'records'
    ? b.flow_count - a.flow_count || b.timestamp.localeCompare(a.timestamp)
    : sort === 'oldest' ? a.timestamp.localeCompare(b.timestamp) : b.timestamp.localeCompare(a.timestamp));
  const groups = data.incidents.map((item) => ({ incident: item, alerts: alerts.filter((alert) => alert.incident_id === item.incident_id) })).filter((group) => group.alerts.length).sort((a, b) => sort === 'oldest' ? a.alerts[0].timestamp.localeCompare(b.alerts[0].timestamp) : b.alerts[0].timestamp.localeCompare(a.alerts[0].timestamp));
  const activeCaseId = expandedCaseId && groups.some((group) => group.incident.incident_id === expandedCaseId) ? expandedCaseId : null;
  const selected = alerts.find((alert) => alert.alert_id === selectedId);
  const incident = data.incidents.find((item) => item.incident_id === selected?.incident_id);
  const filtered = Boolean(query || type !== 'All' || caseId !== 'All' || date !== 'All');

  function clearFilters() {
    setQuery('');
    setType('All');
    setCaseId('All');
    setDate('All');
    setSort('newest');
  }

  return <section className="iris-alerts-page">
    <header className="iris-alerts-header"><div><h1>Alerts</h1><p>{alerts.length} matching alerts · {groups.length} linked cases</p></div></header>
    <div className="alerts-workspace"><div className="alerts-controls">
      <div className="alerts-controls-main"><input aria-label="Search alerts" placeholder="Search alerts, IPs, or IDs…" value={query} onChange={(event) => setQuery(event.target.value)} /><FilterDropdown label="Sort" value={sort} onChange={setSort} options={[{ value: 'newest', label: 'Newest first' }, { value: 'oldest', label: 'Oldest first' }, { value: 'records', label: 'Most records' }]} /></div>
      <div className="alerts-controls-filters"><div className="iris-alert-filters" aria-label="Alert type">{alertTypes.map((label) => <button type="button" key={label} className={type === label ? 'selected' : ''} aria-pressed={type === label} onClick={() => setType(label)}>{label === 'NeedsReview' ? 'Needs review' : label}</button>)}</div><FilterDropdown label="Case" className="case-dropdown" value={caseId} onChange={setCaseId} options={[{ value: 'All', label: 'All cases' }, ...data.incidents.map((item) => ({ value: item.incident_id, label: `Case #${caseNumber.get(item.incident_id)} · ${item.incident_id}` }))]} /><DateCalendar value={date} onChange={setDate} />{filtered && <button type="button" className="alerts-clear" onClick={clearFilters}>Clear filters</button>}</div>
    </div>
    <div className="iris-alert-split"><div className="iris-alert-queue">
      <div className="alerts-group-heading"><span>{viewMode === 'alerts' ? `${alerts.length} alerts` : `${groups.length} case groups`}</span><div className="alerts-view-switch" aria-label="Alert list view"><button type="button" className={viewMode === 'alerts' ? 'selected' : ''} aria-pressed={viewMode === 'alerts'} onClick={() => setViewMode('alerts')}>Alerts</button><button type="button" className={viewMode === 'grouped' ? 'selected' : ''} aria-pressed={viewMode === 'grouped'} onClick={() => setViewMode('grouped')}>By case</button></div></div>
      {viewMode === 'alerts' ? <div className="alerts-individual-list">{alerts.map((alert) => <button type="button" className={`alert-individual-row${selected?.alert_id === alert.alert_id ? ' selected' : ''}`} key={alert.alert_id} aria-pressed={selected?.alert_id === alert.alert_id} onClick={() => setSelectedId(alert.alert_id)}><span className={`alert-type-chip ${alert.type.toLowerCase()}`}>{alert.type}</span><span className="alert-individual-copy"><strong>{alertTitle(alert)}</strong><small>{alert.source_ip} → {alert.destination_ip} · Case #{caseNumber.get(alert.incident_id)}</small></span><span className="alert-individual-meta"><time>{time(alert.timestamp)}</time><small>{alert.flow_count.toLocaleString()} records</small></span></button>)}{alerts.length === 0 && <p className="iris-list-note">No matching alerts. <button type="button" onClick={clearFilters}>Clear filters</button></p>}</div> : <>{groups.map((group) => <div className="alerts-group" key={group.incident.incident_id}><button type="button" className={`alerts-group-toggle${activeCaseId === group.incident.incident_id ? ' active' : ''}`} aria-expanded={activeCaseId === group.incident.incident_id} onClick={() => { if (activeCaseId === group.incident.incident_id) setExpandedCaseId(null); else { setExpandedCaseId(group.incident.incident_id); setSelectedId(group.alerts[0].alert_id); } }}><span className="alerts-group-caret" aria-hidden="true"><svg viewBox="0 0 20 20" fill="none"><path d="m7.5 4.5 5 5-5 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg></span><span className="alerts-group-copy"><strong>Case #{caseNumber.get(group.incident.incident_id)} · {alertTitle(group.alerts[0])}</strong><small>{time(group.incident.window_start)} · {group.incident.source_ip} → {group.incident.destination_ip}</small></span><span className="alerts-group-count">{group.alerts.length} alerts</span></button>{activeCaseId === group.incident.incident_id && <div className="alerts-group-items">{group.alerts.map((alert) => <button type="button" key={alert.alert_id} className={`alerts-group-item${alert.alert_id === selected?.alert_id ? ' selected' : ''}`} aria-pressed={alert.alert_id === selected?.alert_id} onClick={() => setSelectedId(alert.alert_id)}><time>{time(alert.timestamp)}</time><span>{alert.rule_basis}</span><strong>{alert.flow_count.toLocaleString()} records</strong></button>)}</div>}</div>)}{alerts.length === 0 && <p className="iris-list-note">No matching alerts. <button type="button" onClick={clearFilters}>Clear filters</button></p>}</>}
    </div>
      <div className="iris-alert-detail">{selected ? <><div className="iris-alert-detail-head"><span>ALERT · {selected.alert_id}</span><h2>{alertTitle(selected)}</h2><p>{time(selected.timestamp)} · {selected.type}</p></div><div className="iris-alert-detail-grid"><div><span>Source</span><strong>{selected.source_ip}</strong></div><div><span>Destination</span><strong>{selected.destination_ip}</strong></div><div><span>Traffic records</span><strong>{selected.flow_count.toLocaleString()}</strong></div></div><section><h3>Why it was flagged</h3><p>{selected.rule_basis}</p></section><section><h3>Related case</h3><p>{incident ? `Case #${caseNumber.get(incident.incident_id)} · ${incident.source_ip} → ${incident.destination_ip}` : 'No case linked'}</p>{incident && <button type="button" className="iris-open-case" onClick={() => onOpenCase(incident.incident_id)}>Open case <Icon name="arrow" size={14} /></button>}</section><details><summary>Technical source</summary><p>{selected.source_file} · row {selected.source_row}</p></details></> : <div className="alert-empty-state"><span className="alert-empty-icon"><Icon name="alert" size={28} /></span><strong>Select an alert</strong><p>{viewMode === 'alerts' ? 'Choose an alert to see its details.' : 'Open a case to see its alerts.'}</p></div>}</div></div></div>
  </section>;
}
