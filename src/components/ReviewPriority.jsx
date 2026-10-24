import React, { useEffect, useState } from 'react';
import SelectField from './SelectField.jsx';
import { apiFetch } from '../apiFetch.js';

export function PriorityBadge({ priority }) {
  const level = priority?.level || 'Not assessed';
  const explanation = priority?.source === 'analyst'
    ? `Set by ${priority.analyst}: ${priority.reason}`
    : `Rule suggestion: ${(priority?.reasons || ['Activity measurements unavailable']).join(' · ')}`;
  return <span className={`review-priority-badge ${level.toLowerCase().replaceAll(' ', '-')}`} title={explanation}>{level}</span>;
}

export default function ReviewPriority({ incidentId, priority, analystName, onSaved }) {
  const [level, setLevel] = useState('automatic');
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { setLevel(priority?.source === 'analyst' ? priority.level : 'automatic'); setReason(''); setError(''); }, [incidentId, priority?.source, priority?.level]);
  async function save() {
    setSaving(true); setError('');
    try {
      const response = await apiFetch(`/api/cases/${encodeURIComponent(incidentId)}/priority`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ level, reason, analyst: analystName, confirmed: true }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Priority could not be saved');
      await onSaved();
      setReason('');
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
    } catch (failure) { setError(failure.message); }
    finally { setSaving(false); }
  }
  return <details className="review-priority-editor" key={incidentId}>
    <summary><span>Review priority</span><PriorityBadge priority={priority} /><span className="review-priority-more">Details and adjust</span></summary>
    <div className="review-priority-body">
      <p className="review-priority-context">Investigation order based on activity, not a security risk rating. AI results do not automatically lower it.</p>
      {priority?.source === 'analyst' && <p>Set by {priority.analyst}: {priority.reason}</p>}
      <p>Rule suggestion: {priority?.suggested?.level || priority?.level || 'Not assessed'}</p>
      <ul>{(priority?.reasons || ['Activity measurements unavailable']).map((text) => <li key={text}>{text}</li>)}</ul>
      <div className="review-priority-fields">
        <SelectField label="Set priority" value={level} onChange={setLevel} disabled={saving} options={[
          { value: 'automatic', label: 'Use rule suggestion' }, ...['High', 'Medium', 'Low'].map((value) => ({ value, label: value })),
        ]} />
        <label className="review-priority-reason">Reason for change<textarea value={reason} onChange={(event) => setReason(event.target.value)} maxLength={1000} rows={2} placeholder="Explain the urgency using case evidence" disabled={saving} /></label>
      </div>
      {error && <p role="alert" className="review-error">{error}</p>}
      <button type="button" className="review-priority-save" disabled={saving || reason.trim().length < 10 || !priority} onClick={save}>{saving ? 'Saving…' : 'Save priority'}</button>
    </div>
  </details>;
}
