import React, { useCallback, useEffect, useState } from 'react';
import Icon from '../components/Icon.jsx';
import EvidencePanel from '../components/EvidencePanel.jsx';
import Alerts from '../modules/alerts.jsx';
import Triage from '../modules/triage.jsx';
import Timeline from '../modules/timeline.jsx';
import Recommendations from '../modules/recommendations.jsx';
import Guardrail from '../modules/guardrails.jsx';
import { getIncident, runTriage, submitDecision, approveRecommendation } from '../lib/api.js';
import { bundledIncident } from '../lib/bundled.js';
import {
  categoryClass,
  formatNumber,
  formatTimestamp,
  verdictClass,
} from '../lib/format.js';

const TABS = [
  { id: 'timeline', label: 'Timeline' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'recommendations', label: 'Recommendations' },
];

export default function AlertReview({ incidents, mode, health, selectedId, onSelect, onDataChanged }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState(null);
  const [tab, setTab] = useState('timeline');
  const [focusId, setFocusId] = useState(null);

  const load = useCallback(
    async (incidentId) => {
      if (!incidentId) {
        setDetail(null);
        return;
      }
      setLoading(true);
      setNotice(null);
      try {
        if (mode === 'offline') {
          setDetail(bundledIncident(incidentId));
        } else {
          setDetail(await getIncident(incidentId));
        }
      } catch (error) {
        setNotice(error.message);
      } finally {
        setLoading(false);
      }
    },
    [mode],
  );

  useEffect(() => {
    load(selectedId);
    setTab('timeline');
    setFocusId(null);
  }, [selectedId, load]);

  async function handleRun() {
    if (!selectedId) return;
    setRunning(true);
    setNotice(null);
    try {
      const payload = await runTriage(selectedId);
      const triage = payload.triage;
      setDetail((previous) =>
        previous
          ? { ...previous, triage, decision: triage?.decision ?? previous.decision }
          : previous,
      );
      onDataChanged();
    } catch (error) {
      setNotice(error.message);
    } finally {
      setRunning(false);
    }
  }

  async function handleDecide(body) {
    const payload = await submitDecision(selectedId, body);
    setDetail((previous) =>
      previous ? { ...previous, decision: payload.decision, triage: payload.triage } : previous,
    );
    onDataChanged();
  }

  async function handleApprove(recommendationId) {
    await approveRecommendation(selectedId, recommendationId);
    await load(selectedId);
  }

  function inspect(evidenceId) {
    if (!evidenceId) return;
    setFocusId(evidenceId);
    setTab('evidence');
  }

  const incident = detail?.incident;
  const triage = detail?.triage;

  return (
    <section className="page review-page">
      <header className="page-head">
        <div>
          <p className="eyebrow">Module 1 · 2 · 3</p>
          <h1>Incidents</h1>
          <p className="page-sub">
            Select a case to inspect its evidence, run the triage agent, and record an analyst
            decision.
          </p>
        </div>
      </header>

      {notice ? (
        <div className="banner warn">
          <Icon name="alert" size={15} />
          <span>{notice}</span>
          <button type="button" className="icon-btn" onClick={() => setNotice(null)} aria-label="Dismiss">
            <Icon name="close" size={13} />
          </button>
        </div>
      ) : null}

      <div className="review-grid">
        <Alerts incidents={incidents} selectedId={selectedId} onSelect={onSelect} />

        <div className="detail-pane">
          {loading && !detail ? <div className="panel skeleton" aria-label="Loading incident" /> : null}

          {!incident && !loading ? (
            <div className="panel empty tall">
              <Icon name="incidents" size={22} />
              <p>Select an incident to view its evidence and triage.</p>
            </div>
          ) : null}

          {incident ? (
            <>
              <section className="panel incident-head">
                <div className="incident-title">
                  <div>
                    <span className={`tag tag-${categoryClass(incident.category)}`}>
                      {incident.category}
                    </span>
                    <h2 className="mono">{incident.incident_id}</h2>
                    <p className="route mono">
                      {incident.source_ip}
                      <Icon name="arrow" size={13} />
                      {incident.destination_ip}
                    </p>
                  </div>
                  {triage?.verdict ? (
                    <div className="incident-verdict">
                      <span className={`verdict verdict-${verdictClass(triage.verdict)}`}>
                        {triage.verdict}
                      </span>
                      <small>
                        {triage.status === 'rejected'
                          ? 'fallback — proposal rejected'
                          : triage.status === 'error'
                            ? 'no verdict — investigation failed'
                            : 'proposed by agent'}
                      </small>
                    </div>
                  ) : (
                    <div className="incident-verdict">
                      <span className="chip chip-muted">Not triaged</span>
                    </div>
                  )}
                </div>

                <dl className="facts facts-inline">
                  <div>
                    <dt>Window</dt>
                    <dd className="mono">{formatTimestamp(incident.window_start)}</dd>
                  </div>
                  <div>
                    <dt>Aggregated flows</dt>
                    <dd>{formatNumber(incident.flow_count)}</dd>
                  </div>
                  <div>
                    <dt>Ports (dst / src)</dt>
                    <dd>
                      {formatNumber(incident.destination_port_count)} /{' '}
                      {formatNumber(incident.source_port_count)}
                    </dd>
                  </div>
                  <div>
                    <dt>Source file</dt>
                    <dd className="mono small">{incident.source_file}</dd>
                  </div>
                  <div>
                    <dt>Dataset label</dt>
                    <dd>
                      <span className="reference" title={incident.reference_label?.note}>
                        {Object.keys(incident.reference_label?.values || {}).join(', ') || '—'}
                      </span>
                    </dd>
                  </div>
                </dl>
                <p className="rule-basis">
                  <span className="eyebrow">Rule basis</span>
                  {incident.rule_basis}
                </p>
              </section>

              <div className="detail-body">
                <div className="detail-main">
                  <div className="tabs" role="tablist" aria-label="Incident detail">
                    {TABS.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        role="tab"
                        aria-selected={tab === item.id}
                        className={`tab${tab === item.id ? ' is-active' : ''}`}
                        onClick={() => setTab(item.id)}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>

                  {tab === 'timeline' ? (
                    <div className="panel panel-flush">
                      <Timeline
                        events={detail.timeline?.events || []}
                        totalFlows={incident.flow_count}
                        onInspect={inspect}
                      />
                    </div>
                  ) : null}

                  {tab === 'evidence' ? (
                    <EvidencePanel evidence={detail.evidence} focusId={focusId} onFocus={setFocusId} />
                  ) : null}

                  {tab === 'recommendations' ? (
                    <Recommendations
                      state={detail.recommendations}
                      incidentId={incident.incident_id}
                      onApprove={handleApprove}
                    />
                  ) : null}
                </div>

                <div className="detail-rail">
                  <Triage
                    incident={incident}
                    triage={triage}
                    decision={detail.decision}
                    mode={mode}
                    ready={Boolean(health?.ai?.ready)}
                    blockedReason={health?.ai?.blocked_reason}
                    onRun={handleRun}
                    running={running}
                    onDecide={handleDecide}
                    onInspect={inspect}
                  />
                  <Guardrail guardrail={triage?.guardrail} status={health?.guardrail} />
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}
