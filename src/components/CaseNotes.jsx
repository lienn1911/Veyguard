import React, { useEffect, useRef, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from './Icon.jsx';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/notes`;

export default function CaseNotes({ incidentId, username, evidenceIds, onEvidence }) {
  const [notes, setNotes] = useState([]);
  const [text, setText] = useState('');
  const [evidenceId, setEvidenceId] = useState(evidenceIds[0] || '');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [evidenceQuery, setEvidenceQuery] = useState('');
  const pickerRef = useRef(null);
  const matchingEvidenceIds = evidenceIds.filter((id) => id.toLowerCase().includes(evidenceQuery.trim().toLowerCase()));

  useEffect(() => {
    let active = true;
    setNotes([]);
    setText('');
    setEvidenceId(evidenceIds[0] || '');
    setPickerOpen(false);
    setEvidenceQuery('');
    setError('');
    fetch(endpoint(incidentId))
      .then((response) => { if (!response.ok) throw new Error('Notes unavailable'); return response.json(); })
      .then((result) => { if (active) setNotes(result.notes || []); })
      .catch(() => { if (active) setError('Notes unavailable. Restart the local service.'); });
    return () => { active = false; };
  }, [incidentId]);

  useEffect(() => {
    if (!pickerOpen) return;
    const closeOutside = (event) => { if (!pickerRef.current?.contains(event.target)) setPickerOpen(false); };
    document.addEventListener('pointerdown', closeOutside);
    return () => document.removeEventListener('pointerdown', closeOutside);
  }, [pickerOpen]);

  async function save(event) {
    event.preventDefault();
    setSaving(true);
    setError('');
    try {
      const response = await apiFetch(endpoint(incidentId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: username, evidence_id: evidenceId, text }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not save note');
      setNotes((current) => [...current, result.note]);
      setText('');
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
    } catch (failure) {
      setError(failure.message);
    } finally {
      setSaving(false);
    }
  }

  return <section className="case-notes" aria-label="Analyst notes">
    <h3>Analyst notes</h3>
    {notes.map((note) => <div className="case-note-entry" key={note.id}><div><strong>{note.analyst}</strong><time>{note.time.slice(0, 16).replace('T', ' ')} UTC</time></div><p>{note.text}</p><button type="button" onClick={() => onEvidence(note.evidence_id)}>{note.evidence_id}</button></div>)}
    <form onSubmit={save}><textarea aria-label="Analyst note" placeholder="Add a finding linked to evidence" value={text} maxLength={2000} onChange={(event) => setText(event.target.value)} /><div><div className="case-note-evidence-picker" ref={pickerRef} onKeyDown={(event) => { if (event.key === 'Escape') setPickerOpen(false); }}><button type="button" className="case-note-evidence-trigger" aria-label={`Supporting evidence: ${evidenceId}`} aria-expanded={pickerOpen} aria-controls="case-note-evidence-options" onClick={() => { setPickerOpen((open) => !open); setEvidenceQuery(''); }}><span>{evidenceId || 'Choose evidence'}</span><span className="case-note-evidence-chevron"><Icon name="arrow" size={14} /></span></button>{pickerOpen && <div className="case-note-evidence-menu" id="case-note-evidence-options"><input autoFocus aria-label="Filter evidence IDs" placeholder="Search evidence ID…" value={evidenceQuery} onChange={(event) => setEvidenceQuery(event.target.value)} /><div className="case-note-evidence-options">{matchingEvidenceIds.map((id) => <button type="button" key={id} className={id === evidenceId ? 'selected' : ''} onClick={() => { setEvidenceId(id); setPickerOpen(false); }}>{id}</button>)}{matchingEvidenceIds.length === 0 && <p>No matching evidence</p>}</div></div>}</div><button type="submit" disabled={!text.trim() || !evidenceId || saving}>{saving ? 'Saving…' : 'Add note'}</button></div></form>
    {error && <p className="case-note-error" role="alert">{error}</p>}
  </section>;
}
