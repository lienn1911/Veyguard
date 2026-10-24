import React, { useEffect, useState } from 'react';

const labels = {
  CASE_REVIEW_PRIORITY_SET: 'Review priority changed',
  ANALYST_DECISION: 'Investigation step reviewed',
  CASE_NOTE_DRAFTED: 'Case note drafted',
  ANALYST_NOTE_ADDED: 'Analyst note added',
  INVESTIGATION_STEP_COMPLETED: 'Approved step completed',
  CASE_RECORD_SAVED: 'Case summary saved',
  'analyst.decision': 'AI proposal reviewed',
  'triage.started': 'AI investigation started',
  'triage.tool_call': 'Evidence tool used',
  'triage.completed': 'AI assessment completed',
  'triage.rejected': 'AI proposal rejected by validation',
  'triage.error': 'AI investigation failed',
};

function eventDetail(event) {
  if (event.action === 'CASE_REVIEW_PRIORITY_SET') return `${event.previous_level} → ${event.level || 'Rule suggestion'} · ${event.reason}`;
  if (event.action === 'triage.started') return [event.provider, event.model].filter(Boolean).join(' · ');
  if (event.action === 'triage.tool_call') return `${event.tool || 'Tool'} · ${event.blocked ? 'Blocked' : event.ok ? 'Completed' : event.error_code || 'Failed'}`;
  if (event.action === 'triage.completed') return [event.verdict, typeof event.confidence === 'number' ? `${Math.round(event.confidence * 100)}% confidence` : null].filter(Boolean).join(' · ');
  if (event.action === 'triage.rejected') return (event.issues || []).slice(0, 2).join(' ');
  if (event.action === 'triage.error') return [event.code, event.message].filter(Boolean).join(' · ');
  if (event.action === 'analyst.decision') return [event.decision, event.note].filter(Boolean).join(' · ');
  if (event.action === 'CASE_RECORD_SAVED') return [event.ai_verdict || 'No AI verdict', `${event.approved_checks} approved`, `${event.rejected_checks} rejected`].join(' · ');
  return [event.decision, event.note].filter(Boolean).join(' · ');
}

export default function CaseAuditSummary({ incidentId, refreshToken, showAll = false, aiOnly = false }) {
  const [activity, setActivity] = useState({ status: 'loading', events: [] });

  useEffect(() => {
    let active = true;
    setActivity({ status: 'loading', events: [] });
    fetch(`/api/cases/${encodeURIComponent(incidentId)}/audit`)
      .then((response) => {
        if (!response.ok) throw new Error('Activity unavailable');
        return response.json();
      })
      .then((result) => {
        if (active) {
          const events = aiOnly ? (result.events || []).filter((event) => event.action?.startsWith('triage.') || event.action === 'analyst.decision') : result.events || [];
          setActivity({ status: 'ready', events: aiOnly ? events : (showAll ? events : events.slice(-4)).reverse() });
        }
      })
      .catch(() => {
        if (active) setActivity({ status: 'error', events: [] });
      });
    return () => { active = false; };
  }, [incidentId, refreshToken, showAll, aiOnly]);

  return <section className="case-audit-summary" aria-label={aiOnly ? 'AI audit trail for this case' : 'Recent case activity'}>
    <h3>{aiOnly ? 'How the agent investigated' : showAll ? 'Activity' : 'Recent activity'}</h3>
    {activity.status === 'loading' && <p>Loading activity…</p>}
    {activity.status === 'error' && <p>Activity is unavailable while the local API is offline.</p>}
    {activity.status === 'ready' && activity.events.length === 0 && <p>{aiOnly ? 'No AI activity recorded for this case yet.' : 'No case activity recorded yet.'}</p>}
    {activity.events.length > 0 && <ol>{activity.events.map((event, index) => <li key={`${event.time}-${event.action}-${index}`}><strong>{labels[event.action] || event.action.replaceAll(/[._]/g, ' ')}</strong><time>{event.time?.slice(0, 16).replace('T', ' ')} UTC{event.actor?.startsWith('analyst:') ? ` · ${event.actor.slice(8)}` : ''}</time>{eventDetail(event) && <small>{eventDetail(event)}</small>}</li>)}</ol>}
  </section>;
}
