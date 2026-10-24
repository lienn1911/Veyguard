import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';
import { PriorityBadge } from './ReviewPriority.jsx';
import { priorityRank } from '../lib/reviewPriority.js';

const incidents = data.incidents || [];

function shortDateTime(value) {
  if (!value) return 'Unknown time';
  const [date, time = ''] = value.split('T');
  const [year, month, day] = date.split('-');
  return year && month && day ? `${day}/${month}/${year} · ${time.slice(0, 5)}` : value;
}


function validatedVerdict(result) {
  // Only display verdicts from completed AI assessments.
  if (result?.status !== 'ready') {
    return null;
  }

  const verdict = result.assessment?.verdict;

  const allowed = [
    'Likely Attack',
    'Likely Benign',
    'Needs Review'
  ];

  return allowed.includes(verdict) ? verdict : null;
}


export default function Dashboard({ onReview, username }) {
  const [tasks, setTasks] = useState([]);
  const [taskError, setTaskError] = useState('');
  const [taskLoading, setTaskLoading] = useState(true);
  const [completing, setCompleting] = useState(null);
  const [caseQueue, setCaseQueue] = useState(null);
  const [assessments, setAssessments] = useState({});
  const [assessmentLoaded, setAssessmentLoaded] = useState(false);

  useEffect(() => {
    let active = true;
    fetch('/api/tasks')
      .then((response) => {
        if (!response.ok) throw new Error('Tasks unavailable');
        return response.json();
      })
      .then((result) => { if (active) setTasks(result.tasks || []); })
      .catch(() => { if (active) setTaskError('Task service unavailable'); })
      .finally(() => { if (active) setTaskLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    fetch('/api/cases/queue')
      .then((response) => {
        if (!response.ok) throw new Error('Case queue unavailable');
        return response.json();
      })
      .then((result) => { if (active) setCaseQueue(result.cases || {}); })
      .catch(() => { if (active) setCaseQueue(null); });

    Promise.all(incidents.map(async (incident) => {
      try {
        const response = await fetch(`/api/cases/${encodeURIComponent(incident.incident_id)}/ai-assessment`);
        return response.ok ? await response.json() : null;
      } catch {
        return null;
      }
    })).then((results) => {
      if (!active) return;
      const byId = {};
      incidents.forEach((incident, index) => { byId[incident.incident_id] = results[index]; });
      setAssessments(byId);
      setAssessmentLoaded(true);
    });
    return () => { active = false; };
  }, []);

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
      setTasks(result.tasks || []);
    } catch (error) {
      setTaskError(error.message);
    } finally {
      setCompleting(null);
    }
  }

  // Queue status != pending approval. Don't mislabel all unreviewed cases as approvals.
  const approvalRecords = caseQueue ? Object.values(caseQueue) : [];
  const approvalsKnown = caseQueue && approvalRecords.every((record) =>
    record && Object.prototype.hasOwnProperty.call(record, 'pending_approval'));
  const approvalCount = approvalsKnown
    ? approvalRecords.filter((record) => record.pending_approval === true).length
    : null;

  const activeIncidents = caseQueue
    ? incidents.filter(
        (incident) =>
          caseQueue[incident.incident_id]?.case_status === 'Open'
      )
    : [];

  const activeVerdicts = activeIncidents.map((incident) =>
    validatedVerdict(assessments[incident.incident_id])
  );

  const countsReady = caseQueue !== null && assessmentLoaded;

  const likelyAttack = countsReady
    ? activeVerdicts.filter((v) => v === 'Likely Attack').length
    : null;

  const needsReview = countsReady
    ? activeVerdicts.filter((v) => v === 'Needs Review').length
    : null;

  const priorityCases = caseQueue
    ? incidents
        .filter((incident) =>
          caseQueue[incident.incident_id]?.case_status !== 'Resolved'
        )
        .map((incident) => ({
          incident,
          activity: caseQueue[incident.incident_id]?.review_priority,
          verdict: validatedVerdict(
            assessments[incident.incident_id]
          )
        }))
        .sort((a, b) =>
          priorityRank(b.activity) - priorityRank(a.activity) ||
          (Date.parse(a.incident.window_start) || 0) -
          (Date.parse(b.incident.window_start) || 0)
        )

    : [];

  return (
    <div className="iris-home"><header className="ui-page-heading"><h1>Home</h1></header>
      <section className="welcome-strip">
        <div className="welcome-stats">
          <button type="button" onClick={() => onReview()}>
            <strong>{approvalCount ?? '—'}</strong>
            <span className="blue"><Icon name="layers" size={15} /> Decisions needed</span>
          </button>
          <button type="button" onClick={() => onReview()}>
            <strong>{likelyAttack ?? '—'}</strong>
            <span className="blue"><Icon name="alert" size={15} /> Likely attack</span>
          </button>
          <button type="button" onClick={() => onReview()}>
            <strong>{needsReview ?? '—'}</strong>
            <span className="blue"><Icon name="alert" size={15} /> Needs review</span>
          </button>
        </div>
      </section>

      <div className="home-workspace">
      <section className="home-card home-attention-card" aria-labelledby="home-cases-title">
      <header>
        <div className="priority-header-left">
          <Icon name="layers" size={20} />

          <div className="priority-heading">
            <h2 id="home-cases-title">Cases to review</h2>

          </div>
        </div>

        <div className="home-attention-links">
          <button type="button" onClick={() => onReview()}>
            All cases <Icon name="arrow" size={15} />
          </button>
        </div>
      </header>
        <div className="home-card-body home-scroll-panel" tabIndex={0} role="region" aria-label="Cases to review list">
          {!caseQueue && <p className="home-attention-empty">Case queue unavailable. Check the local API.</p>}
          {caseQueue && priorityCases.length === 0 && <p className="home-attention-empty">No unresolved cases in the queue.</p>}
          {priorityCases.map(({ incident, activity }, index) => (
            <button
              type="button"
              className="home-case priority-row"
              key={incident.incident_id}
              onClick={() => onReview(incident.incident_id)}
            >
              {/* Case number */}
              <span className="priority-index">
                {index + 1}
              </span>

              {/* Left side: Incident information */}
              <span className="priority-info">
                <strong>
                  {incident.incident_id}
                </strong>

                <span className="priority-ip">
                  {incident.source_ip} → {incident.destination_ip}
                </span>

                <small>
                  {shortDateTime(incident.window_start)} · {(incident.alert_ids || []).length} alerts
                </small>


              </span>

              <span className="home-review-priority"><PriorityBadge priority={activity} /></span>
            </button>
          ))}
          </div>
        </section>

      <section className="home-card tasks-card" aria-labelledby="home-tasks-title">
        <header><h2 id="home-tasks-title"><Icon name="check" size={18} />Approved steps to complete</h2></header>
        <div className="home-card-body home-scroll-panel" tabIndex={0} role="region" aria-label="Pending investigation steps list">
          <p className="home-task-purpose">Steps approved by an analyst. Carry out each investigation, then mark it done.</p>
          {taskError && <p className="task-error" role="alert">{taskError}</p>}
          {taskLoading && <p className="home-panel-empty" role="status">Loading investigation steps…</p>}
          {!taskLoading && !taskError && tasks.length === 0 && <p className="home-panel-empty">No pending steps. You're up to date.</p>}
          {tasks.map((task) => (
            <div className="home-task" key={task.id}>
              <button type="button" onClick={() => onReview(task.incident_id)}>
                <strong>{task.text}</strong>
              </button>
              <button type="button" className="task-done" disabled={completing === task.id} onClick={() => finishTask(task)}>
                {completing === task.id ? 'Saving…' : 'Mark done'}
              </button>
            </div>
          ))}
        </div>
      </section>
      </div>
      </div>
  );
}
