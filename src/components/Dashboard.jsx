import React, { useEffect, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

const incidents = data.incidents || [];
const alerts = data.alerts || [];
const alertsById = new Map(alerts.map((alert) => [alert.alert_id, alert]));

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


function activityPriority(incident) {
  // A simple, transparent WORKFLOW ordering, NOT a security risk rating.
  // Use actual incident and related alert activity; never use dataset ground-truth labels.
  const count = Number(incident.flow_count) || 0;
  const first = Date.parse(incident.window_start);
  const last = Date.parse(incident.window_end);
  const minutes = Number.isFinite(first) && Number.isFinite(last)
    ? Math.max(1, (last - first) / 60000)
    : null;
  const rate = minutes === null ? null : count / minutes;
  const relatedAlerts = (incident.alert_ids || []).map((id) => alertsById.get(id)).filter(Boolean);
  const alertCount = relatedAlerts.length;
  const sourceCount = Array.isArray(incident.source_ips) ? incident.source_ips.length : null;
  const uniquePorts = relatedAlerts.length
    ? Math.max(...relatedAlerts.map((a) => Number(a.destination_port_count) || 0))
    : null;

  let score = 0;
  const reasons = [];
  if (rate !== null && rate >= 10000) { score += 2; reasons.push('Dense network activity'); }
  else if (rate !== null && rate >= 5000) { score += 1; reasons.push('Elevated network activity'); }
  if (alertCount >= 10) { score += 2; reasons.push(`${alertCount} related alerts`); }
  else if (alertCount >= 3) { score += 1; reasons.push(`${alertCount} related alerts`); }
  if (sourceCount !== null && sourceCount >= 3) { score += 2; reasons.push(`${sourceCount} source IPs`); }
  if (uniquePorts !== null && uniquePorts >= 250) { score += 2; reasons.push(`${uniquePorts} destination ports`); }
  else if (uniquePorts !== null && uniquePorts >= 100) { score += 1; reasons.push(`${uniquePorts} destination ports`); }
  return { score, reason: reasons.join(' · ') || 'Waiting for investigation' };
}

function getPriorityLabel(score) {
  if (score >= 5) return "High Priority";
  if (score >= 3) return "Moderate Priority";
  return "Low Priority";
}

export default function Dashboard({ onReview, onAlerts, username }) {
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


  const verdicts = incidents.map((incident) =>
    validatedVerdict(assessments[incident.incident_id])
  );

  const hasAiResults =
    assessmentLoaded &&
    verdicts.some((verdict) => verdict !== null);

  const likelyAttack = hasAiResults
    ? verdicts.filter((v) => v === 'Likely Attack').length
    : null;

  const needsReview = hasAiResults
    ? verdicts.filter((v) => v === 'Needs Review').length
    : null;

  const priorityCases = caseQueue
    ? incidents
        .filter((incident) =>
          caseQueue[incident.incident_id]?.case_status !== 'Resolved'
        )
        .map((incident) => ({
          incident,
          activity: activityPriority(incident),
          verdict: validatedVerdict(
            assessments[incident.incident_id]
          )
        }))
        .sort((a, b) =>
          b.activity.score - a.activity.score ||
          (Date.parse(a.incident.window_start) || 0) -
          (Date.parse(b.incident.window_start) || 0)
        )
        .slice(0, 5)
    : [];

  return (
    <div className="iris-home">
      <section className="welcome-strip">
        <div className="welcome-stats">
          <button type="button" onClick={() => onReview()}>
            <strong>{approvalCount ?? '—'}</strong>
            <span className="blue"><Icon name="layers" size={15} /> AWAITING APPROVAL</span>
          </button>
          <button type="button" onClick={() => onReview()}>
            <strong>{likelyAttack ?? '—'}</strong>
            <span className="blue"><Icon name="alert" size={15} /> LIKELY ATTACK</span>
          </button>
          <button type="button" onClick={() => onReview()}>
            <strong>{needsReview ?? '—'}</strong>
            <span className="blue"><Icon name="alert" size={15} /> NEEDS REVIEW</span>
          </button>
        </div>
      </section>

      <section className="home-card home-attention-card">
      <header>
        <div className="priority-header-left">
          <Icon name="layers" size={20} />

          <div className="priority-heading">
            <h2>Investigation Priority Queue</h2>
            <p>
              Ranked by observed network activity, not incident severity.
            </p>
          </div>
        </div>

        <div className="home-attention-links">
          <button type="button" onClick={() => onReview()}>
            All cases <Icon name="arrow" size={15} />
          </button>
        </div>
      </header>
        <div className="home-card-body">
          {!caseQueue && <p className="home-attention-empty">Case queue unavailable. Check the local API.</p>}
          {caseQueue && priorityCases.length === 0 && <p className="home-attention-empty">No unresolved cases in the queue.</p>}
          {priorityCases.map(({ incident, activity, verdict }, index) => (
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
                  {incident.type || 'Incident'} · Case #{incidents.indexOf(incident) + 1}
                </strong>

                <span className="priority-ip">
                  {incident.source_ip} → {incident.destination_ip}
                </span>

                <small>
                  {shortDateTime(incident.window_start)} · {(incident.alert_ids || []).length} alerts
                </small>

                <small className="priority-reason">
                  {activity.reason}
                </small>
              </span>

              {/* Right side: Queue score and AI verdict */}
              <span className="priority-score">
                <strong>
                  {getPriorityLabel(activity.score)}
                </strong>
                  <small className="priority-verdict">
                  {verdict || 'Not assessed'}
                </small>
              </span>
            </button>
          ))}
          </div>
        </section>

      {(tasks.length > 0 || taskError) && (
        <section className="home-card tasks-card">
          <header><h2><span className="green"><Icon name="check" size={20} /></span>Pending investigation steps</h2></header>
          {taskError && <p className="task-error" role="alert">{taskError}</p>}
          {tasks.length > 0 && (
            <div className="home-card-body">
              {tasks.map((task) => (
                <div className="home-task" key={task.id}>
                  <button type="button" onClick={() => onReview(task.incident_id)}>
                    <strong>{task.text}</strong><small>Open case →</small>
                  </button>
                  <button type="button" className="task-done" disabled={completing === task.id} onClick={() => finishTask(task)}>
                    {completing === task.id ? 'Saving…' : 'Mark done'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
      </div>
  );
}
