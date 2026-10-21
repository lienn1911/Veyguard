import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

function shortDateTime(value) {
  const [date, time = ''] = value.split('T');
  const [year, month, day] = date.split('-');
  return `${day}/${month}/${year} · ${time.slice(0, 5)}`;
}

export default function Dashboard({ onReview, onAlerts, username }) {
  const incidents = data.incidents;
  const [tasks, setTasks] = useState([]);
  const [taskError, setTaskError] = useState('');
  const [taskLoading, setTaskLoading] = useState(true);
  const [completing, setCompleting] = useState(null);
  const [awaitingApproval, setAwaitingApproval] = useState(null);
  const [aiReady, setAiReady] = useState(null);
  const [aiReadyIds, setAiReadyIds] = useState([]);
  const [caseQueue, setCaseQueue] = useState(null);

  useEffect(() => {
    let active = true;
    fetch('/api/tasks')
      .then((response) => { if (!response.ok) throw new Error('Tasks unavailable'); return response.json(); })
      .then((result) => { if (active) setTasks(result.tasks || []); })
      .catch(() => { if (active) setTaskError('Task service unavailable'); })
      .finally(() => { if (active) setTaskLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    fetch('/api/cases/queue')
      .then((response) => { if (!response.ok) throw new Error('Queue unavailable'); return response.json(); })
      .then((result) => { if (active) { setCaseQueue(result.cases || {}); setAwaitingApproval(Object.values(result.cases || {}).filter((item) => !item.review_complete).length); } })
      .catch(() => { if (active) setAwaitingApproval(null); });
    Promise.all(incidents.map(async (incident) => {
      try {
        const response = await fetch(`/api/cases/${encodeURIComponent(incident.incident_id)}/ai-assessment`);
        return response.ok ? await response.json() : null;
      } catch {
        return null;
      }
    })).then((results) => { if (active) { const readyIds = incidents.filter((_, index) => results[index]?.status === 'ready' && results[index]?.assessment && (!results[index]?.decision || results[index].decision.status === 'pending')).map((item) => item.incident_id); setAiReadyIds(readyIds); setAiReady(results.every((result) => result === null) ? null : readyIds.length); } });
    return () => { active = false; };
  }, [incidents]);

  async function finishTask(task) {
    setCompleting(task.id);
    setTaskError('');
    try {
      const response = await apiFetch(`/api/tasks/${encodeURIComponent(task.id)}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: username }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not complete task');
      setTasks(result.tasks);
    } catch (error) {
      setTaskError(error.message);
    } finally {
      setCompleting(null);
    }
  }

  const attentionCases = caseQueue ? incidents.filter((incident) => aiReadyIds.includes(incident.incident_id) || !caseQueue[incident.incident_id]?.review_complete).sort((a, b) => Number(aiReadyIds.includes(b.incident_id)) - Number(aiReadyIds.includes(a.incident_id))).slice(0, 3) : [];

  return <div className="iris-home">
    <section className="welcome-strip">
      <div className="welcome-stats">
        <button onClick={() => onReview()}><strong>{awaitingApproval ?? '—'}</strong><span className="blue"><Icon name="layers" size={15} /> AWAITING APPROVAL</span></button>
        <div><strong>{taskLoading || taskError ? '—' : tasks.length}</strong><span className="green"><Icon name="check" size={15} /> APPROVED STEPS</span></div>
        <button onClick={() => onReview()}><strong>{aiReady ?? '—'}</strong><span className="blue"><Icon name="alert" size={15} /> AI READY FOR REVIEW</span></button>
      </div>
    </section>
    <section className="home-card home-attention-card">
      <header><h2><span className="blue"><Icon name="layers" size={20} /></span>Needs attention</h2><div className="home-attention-links"><button type="button" onClick={() => onAlerts()}>Browse alerts <Icon name="arrow" size={15} /></button><button type="button" onClick={() => onReview()}>All cases <Icon name="arrow" size={15} /></button></div></header>
      <div className="home-card-body">
        {!caseQueue && <p className="home-attention-empty">Case status is unavailable until the local API is running.</p>}
        {caseQueue && attentionCases.length === 0 && <p className="home-attention-empty">No cases currently need review.</p>}
        {attentionCases.map((incident) => <button className="home-case home-overview-row" key={incident.incident_id} onClick={() => onReview(incident.incident_id)}><span className="home-row-index">#{incidents.indexOf(incident) + 1}</span><span className="home-row-content"><strong>{incident.source_ip} → {incident.destination_ip}</strong><small>{shortDateTime(incident.window_start)} · {incident.alert_ids.length} alerts</small></span><span className="home-row-trailing">{aiReadyIds.includes(incident.incident_id) ? 'AI ready for review' : 'Review next steps'}</span></button>)}
      </div>
    </section>
    {(tasks.length > 0 || taskError) && <section className="home-card tasks-card"><header><h2><span className="green"><Icon name="check" size={20} /></span>Pending investigation steps</h2></header>{taskError && <p className="task-error" role="alert">{taskError}</p>}{tasks.length > 0 && <div className="home-card-body">{tasks.map((task) => <div className="home-task" key={task.id}><button type="button" onClick={() => onReview(task.incident_id)}><strong>{task.text}</strong><small>Open case →</small></button><button type="button" className="task-done" disabled={completing === task.id} onClick={() => finishTask(task)}>{completing === task.id ? 'Saving…' : 'Mark done'}</button></div>)}</div>}</section>}
  </div>;
}
