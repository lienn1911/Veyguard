import React, { useEffect, useState } from 'react';

const endpoint = (id) => `/api/cases/${encodeURIComponent(id)}/notes`;

export default function CaseNotes({ incidentId, username, evidenceIds, onEvidence }) {
  const [notes, setNotes] = useState([]);
  const [text, setText] = useState('');
  const [evidenceId, setEvidenceId] = useState(evidenceIds[0] || '');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    setNotes([]);
    setText('');
    setEvidenceId(evidenceIds[0] || '');
    setError('');
    fetch(endpoint(incidentId))
      .then((response) => { if (!response.ok) throw new Error('Notes unavailable'); return response.json(); })
      .then((result) => { if (active) setNotes(result.notes || []); })
      .catch(() => { if (active) setError('Notes unavailable. Restart the local service.'); });
    return () => { active = false; };
  }, [incidentId]);

  async function save(event) {
    event.preventDefault();
    setSaving(true);
    setError('');
    try {
      const response = await fetch(endpoint(incidentId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: username, evidence_id: evidenceId, text }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not save note');
      setNotes((current) => [...current, result.note]);
      setText('');
    } catch (failure) {
      setError(failure.message);
    } finally {
      setSaving(false);
    }
  }

  return <section className="case-notes" aria-label="Analyst notes">
    <h3>Analyst notes</h3>
    {notes.map((note) => <div className="case-note-entry" key={note.id}><div><strong>{note.analyst}</strong><time>{note.time.slice(0, 16).replace('T', ' ')} UTC</time></div><p>{note.text}</p><button type="button" onClick={() => onEvidence(note.evidence_id)}>{note.evidence_id}</button></div>)}
    <form onSubmit={save}><textarea aria-label="Analyst note" placeholder="Add a finding linked to evidence" value={text} maxLength={2000} onChange={(event) => setText(event.target.value)} /><div><select aria-label="Supporting evidence" value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)}>{evidenceIds.map((id) => <option key={id} value={id}>{id}</option>)}</select><button type="submit" disabled={!text.trim() || !evidenceId || saving}>{saving ? 'Saving…' : 'Add note'}</button></div></form>
    {error && <p className="case-note-error" role="alert">{error}</p>}
  </section>;
}
