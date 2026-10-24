import React, { useEffect, useRef, useState } from 'react';
import { apiFetch } from '../apiFetch.js';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/notes`;
export default function CaseNotes({ incidentId, username, evidenceIds, onEvidence, open, onClose, selectedEvidence }) {
  const [notes, setNotes] = useState([]);
  const [text, setText] = useState('');
  const [evidenceId, setEvidenceId] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState('');
  const [pickerOpen, setPickerOpen] = useState(false);
  const [evidenceQuery, setEvidenceQuery] = useState('');
  const pickerRef = useRef(null);
  const searchRef = useRef(null);
  useEffect(() => {
    if (!pickerOpen) return;
    searchRef.current?.focus();
    const close = (event) => { if (!pickerRef.current?.contains(event.target)) setPickerOpen(false); };
    document.addEventListener('pointerdown', close);
    return () => document.removeEventListener('pointerdown', close);
  }, [pickerOpen]);
  useEffect(() => { if (!open) setPickerOpen(false); }, [open]);
  useEffect(() => {
    let active = true;
    setNotes([]); setText(''); setEvidenceId(''); setError(''); setStatus('Loading notes…');
    fetch(endpoint(incidentId)).then(async (response) => {
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not load notes');
      if (active) { setNotes(result.notes || []); setStatus(''); }
    }).catch((failure) => { if (active) { setError(failure.message); setStatus(''); } });
    return () => { active = false; };
  }, [incidentId]);
  async function save(event) {
    event.preventDefault();
    if (saving || !text.trim()) return;
    setSaving(true); setError(''); setStatus('');
    try {
      const response = await apiFetch(endpoint(incidentId), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ analyst: username, evidence_id: evidenceId || null, text: text.trim() }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not save note');
      setNotes((previous) => [...previous, result.note]); setText(''); setStatus('Note saved');
      window.dispatchEvent(new CustomEvent('case-notes-updated', { detail: incidentId }));
      window.dispatchEvent(new CustomEvent('case-activity-updated', { detail: incidentId }));
    } catch (failure) { setError(failure.message); }
    finally { setSaving(false); }
  }
  return <aside className="case-notes-drawer" hidden={!open} aria-label="Investigation notes" onKeyDown={(event) => { if (event.key === 'Escape') onClose(); }}>
    <header><div><h2>Investigation notes</h2><span>{incidentId}</span></div><button type="button" onClick={onClose} aria-label="Close notes">×</button></header>
    <div className="case-notes-drawer-body"><form onSubmit={save}>
      <label htmlFor="case-investigation-note">New note</label>
      <textarea id="case-investigation-note" placeholder="Record what you checked and what you found…" value={text} maxLength={2000} onChange={(event) => { setText(event.target.value); setStatus(''); }} />
      <label id="case-note-evidence-label">Evidence · optional</label>
      <div className="notes-evidence-picker" ref={pickerRef} onKeyDown={(event) => { if (event.key === 'Escape' && pickerOpen) { event.stopPropagation(); setPickerOpen(false); pickerRef.current?.querySelector('button')?.focus(); } }}>
        <button type="button" className="notes-evidence-trigger" aria-labelledby="case-note-evidence-label case-note-evidence-value" aria-expanded={pickerOpen} aria-haspopup="listbox" aria-controls="notes-evidence-options" onClick={() => { setEvidenceQuery(''); setPickerOpen((value) => !value); }}><span id="case-note-evidence-value">{evidenceId || 'General case note'}</span><svg className="notes-picker-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg></button>
        {pickerOpen && <div className="notes-evidence-popover"><input ref={searchRef} type="search" aria-label="Search evidence" placeholder="Search evidence ID…" value={evidenceQuery} onChange={(event) => setEvidenceQuery(event.target.value)} /><div className="notes-evidence-options" id="notes-evidence-options" role="listbox" aria-labelledby="case-note-evidence-label">
          {(!evidenceQuery || 'general case note'.includes(evidenceQuery.toLowerCase())) && <button type="button" role="option" aria-selected={!evidenceId} onClick={() => { setEvidenceId(''); setPickerOpen(false); }}>General case note</button>}
          {evidenceIds.filter((id) => id.toLowerCase().includes(evidenceQuery.trim().toLowerCase())).map((id) => <button type="button" key={id} role="option" aria-selected={id === evidenceId} onClick={() => { setEvidenceId(id); setPickerOpen(false); }}>{id}</button>)}
          {evidenceQuery && !'general case note'.includes(evidenceQuery.toLowerCase()) && !evidenceIds.some((id) => id.toLowerCase().includes(evidenceQuery.trim().toLowerCase())) && <p>No matching evidence</p>}
        </div></div>}
      </div>
      {selectedEvidence && evidenceIds.includes(selectedEvidence) && evidenceId !== selectedEvidence && <button className="link-current-evidence" type="button" onClick={() => setEvidenceId(selectedEvidence)}>Link currently viewed evidence</button>}
      <footer><small>{text.length}/2000{ text.trim() ? ' · Unsaved' : ''}</small><button type="submit" disabled={saving || !text.trim()}>{saving ? 'Saving…' : 'Save note'}</button></footer>
    </form>
    {error && <p className="review-error" role="alert">{error}</p>}{status && <p className="case-notes-status" role="status">{status}</p>}
    <h3>Saved notes · {notes.length}</h3>
    {notes.length ? [...notes].reverse().map((note) => <article className="investigation-note-entry" key={note.id}><div><strong>{note.analyst}</strong><time>{note.time?.slice(0, 16).replace('T', ' ')} UTC</time></div><p>{note.text}</p>{note.evidence_id && <button type="button" onClick={() => onEvidence(note.evidence_id)}>{note.evidence_id}</button>}</article>) : <p className="case-notes-empty">No investigation notes yet.</p>}
    </div>
  </aside>;
}
