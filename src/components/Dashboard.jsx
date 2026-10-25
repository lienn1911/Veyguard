import React, { useEffect, useState } from 'react';
import Icon from './Icon.jsx';
import data from '../real-alerts.json';

const incidents = data.incidents || [];
const reviewStates = [
  { key: 'pending', label: 'Awaiting review' },
  { key: 'partial', label: 'Partially reviewed' },
  { key: 'complete', label: 'Review complete' },
];

function validatedVerdict(result) {
  if (result?.status !== 'ready') return null;
  const verdict = result.assessment?.verdict;
  return ['Likely Attack', 'Likely Benign', 'Needs Review'].includes(verdict) ? verdict : null;
}

function activityLabel(event) {
  const decision = event.payload?.decision;
  if (event.event === 'analyst.decision')
    return decision === 'confirmed'
      ? 'Agreed with AI conclusion'
      : decision === 'rejected'
        ? 'Disagreed with AI conclusion'
        : 'Reviewed AI conclusion';
  if (event.event === 'ANALYST_DECISION')
    return String(decision).toLowerCase() === 'approved'
      ? 'Approved a next step'
      : 'Rejected a next step';
  return (
    {
      CASE_RECORD_SAVED: 'Saved triage report',
      ANALYST_NOTE_ADDED: 'Added investigation note',
      CASE_REVIEW_PRIORITY_SET: 'Changed review priority',
    }[event.event] || 'Case updated'
  );
}

function activityTime(value) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

export default function Dashboard({ onReview }) {
  const [caseQueue, setCaseQueue] = useState(null);
  const [assessments, setAssessments] = useState({});
  const [assessmentLoaded, setAssessmentLoaded] = useState(false);
  const [activity, setActivity] = useState(null);
  const [activityError, setActivityError] = useState(false);

  useEffect(() => {
    let active = true;
    async function load() {
      await Promise.allSettled([
        fetch('/api/cases/queue')
          .then(async (response) => {
            if (!response.ok) throw new Error('Case queue unavailable');
            const result = await response.json();
            if (active) setCaseQueue(result.cases || {});
          })
          .catch(() => {
            if (active) setCaseQueue(null);
          }),
        fetch('/api/activity/recent')
          .then(async (response) => {
            if (!response.ok) throw new Error('Recent activity unavailable');
            const result = await response.json();
            if (active) {
              setActivity(result.events || []);
              setActivityError(false);
            }
          })
          .catch(() => {
            if (active) setActivityError(true);
          }),
        Promise.all(
          incidents.map(async (incident) => {
            try {
              const response = await fetch(
                `/api/cases/${encodeURIComponent(incident.incident_id)}/ai-assessment`,
              );
              return [incident.incident_id, response.ok ? await response.json() : null];
            } catch {
              return [incident.incident_id, null];
            }
          }),
        ).then((results) => {
          if (active) {
            setAssessments(Object.fromEntries(results));
            setAssessmentLoaded(true);
          }
        }),
      ]);
    }
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const states = incidents.map(
    (incident) => caseQueue?.[incident.incident_id]?.review_progress?.state,
  );
  const progressKnown =
    caseQueue !== null && states.every((state) => reviewStates.some((item) => item.key === state));
  const counts = Object.fromEntries(
    reviewStates.map((item) => [item.key, states.filter((state) => state === item.key).length]),
  );
  const total = incidents.length;
  const pending = progressKnown ? counts.pending + counts.partial : null;
  const openCases = caseQueue
    ? incidents.filter((incident) => caseQueue[incident.incident_id]?.case_status === 'Open')
    : [];
  const verdicts = openCases.map((incident) => validatedVerdict(assessments[incident.incident_id]));
  const aiCountsKnown = caseQueue !== null && assessmentLoaded;

  return (
    <div className="iris-home">
      <header className="ui-page-heading">
        <h1>Home</h1>
      </header>
      <section className="welcome-strip">
        <div className="home-review-summary">
          <button type="button" className="home-pending-review" onClick={() => onReview()}>
            <strong>{pending ?? '—'}</strong>
            <span>Pending review</span>
          </button>
          <div className="home-summary-card home-likely-attack">
            <strong>
              {aiCountsKnown ? verdicts.filter((value) => value === 'Likely Attack').length : '—'}
            </strong>
            <span>Likely attack</span>
          </div>
          <div className="home-summary-card home-needs-review">
            <strong>
              {aiCountsKnown ? verdicts.filter((value) => value === 'Needs Review').length : '—'}
            </strong>
            <span>Needs review</span>
          </div>
        </div>
      </section>
      <div className="home-workspace home-overview-workspace">
        <section className="home-card" aria-labelledby="home-progress-title">
          <header>
            <h2 id="home-progress-title">
              <Icon name="checklist" size={19} />
              Review progress
            </h2>
          </header>
          <div className="home-progress-body">
            {!progressKnown ? (
              <p className="home-panel-empty">Review status unavailable.</p>
            ) : (
              <>
                <p className="home-progress-total">
                  <strong>{counts.complete}</strong>
                  <span>/ {total} reviewed</span>
                </p>
                <div
                  className="home-progress-track"
                  role="img"
                  aria-label={reviewStates
                    .map((item) => `${item.label}: ${counts[item.key]}`)
                    .join(', ')}
                >
                  {total
                    ? reviewStates
                        .filter((item) => counts[item.key])
                        .map((item) => (
                          <span
                            key={item.key}
                            className={`home-progress-segment state-${item.key}`}
                            style={{ width: `${(counts[item.key] / total) * 100}%` }}
                          />
                        ))
                    : null}
                </div>
                <dl className="home-progress-legend">
                  {reviewStates.map((item) => (
                    <div key={item.key}>
                      <dt>
                        <span
                          className={`home-progress-dot state-${item.key}`}
                          aria-hidden="true"
                        />
                        {item.label}
                      </dt>
                      <dd>{counts[item.key]}</dd>
                    </div>
                  ))}
                </dl>
              </>
            )}
          </div>
        </section>
        <section className="home-card" aria-labelledby="home-activity-title">
          <header>
            <h2 id="home-activity-title">
              <Icon name="audit" size={19} />
              Recent activity
            </h2>
          </header>
          <div
            className="home-card-body home-scroll-panel"
            role="region"
            aria-label="Recent activity"
            tabIndex={0}
          >
            {activityError ? (
              <p className="home-panel-empty" role="status">
                Recent activity unavailable.
              </p>
            ) : activity === null ? (
              <p className="home-panel-empty" role="status">
                Loading activity…
              </p>
            ) : activity.length === 0 ? (
              <p className="home-panel-empty">No review activity yet.</p>
            ) : (
              <ol className="home-recent-activity">
                {activity.map((event) => (
                  <li key={event.event_id}>
                    <button type="button" onClick={() => onReview(event.incident_id)}>
                      <strong>{activityLabel(event)}</strong>
                      <span className="home-activity-case">{event.incident_id}</span>
                      <small>
                        {(event.actor || 'System').replace(/^analyst:/, '')}
                        <time dateTime={event.ts}>{activityTime(event.ts)}</time>
                      </small>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
