import React from 'react';

export function TriagePreview({ alerts, flows }) {
  return <section className="process-panel">
    <div className="process-panel-head"><h3>AI assessment</h3></div>
    <div className="workflow-status"><span>AI assessment</span><strong>Not available yet</strong></div>
    <div className="workflow-preview-grid"><div><span>Inputs</span><strong>{alerts.length} alerts · {flows.length} example records</strong></div><div><span>Result</span><strong>Pending teammate integration</strong><small>Conclusion must link to evidence</small></div></div>
  </section>;
}

export function NextStepsPreview() {
  return <section className="process-panel">
    <div className="process-panel-head"><h3>Next steps</h3></div>
    <div className="workflow-preview-grid three"><div><span>Suggested checks</span><strong>Waiting for AI</strong></div><div><span>Human approval</span><strong>Required</strong></div><div><span>Written summary</span><strong>After approval</strong></div></div>
    <div className="workflow-guardrail"><strong>Human control</strong><p>AI cannot close, dismiss, or lower the priority of a case.</p></div>
    <div className="workflow-audit"><span>Activity history</span><strong>No decisions yet</strong></div>
  </section>;
}
