import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from services.recommendations import DB_PATH, init_db
from services.unified_audit import append_in_transaction


def list_notes(incident_id, db_path=DB_PATH):
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as db:
        rows = db.execute(
            'SELECT id, analyst_id, evidence_id, text, created_at FROM case_notes WHERE incident_id = ? ORDER BY id',
            (incident_id,),
        ).fetchall()
    return [
        {'id': note_id, 'analyst': analyst, 'evidence_id': evidence_id, 'text': text, 'time': timestamp}
        for note_id, analyst, evidence_id, text, timestamp in rows
    ]


def add_note(data, incident_id, analyst, evidence_id, text, db_path=DB_PATH):
    incident = next((item for item in data['incidents'] if item['incident_id'] == incident_id), None)
    if incident is None:
        raise ValueError('Unknown case')
    valid_evidence = set(incident['alert_ids']) | set(incident['evidence_sample_ids'])
    if not isinstance(evidence_id, str) or evidence_id not in valid_evidence:
        raise ValueError('Select evidence from this case')
    if not isinstance(analyst, str) or not analyst.strip() or len(analyst.strip()) > 80:
        raise ValueError('Analyst name is required')
    if not isinstance(text, str) or not text.strip() or len(text.strip()) > 2000:
        raise ValueError('Note must be between 1 and 2000 characters')
    init_db(db_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    with closing(sqlite3.connect(db_path)) as db, db:
        cursor = db.execute(
            'INSERT INTO case_notes (incident_id, analyst_id, evidence_id, text, created_at) VALUES (?, ?, ?, ?, ?)',
            (incident_id, analyst.strip(), evidence_id, text.strip(), timestamp),
        )
        note_id = cursor.lastrowid
        append_in_transaction(db, 'ANALYST_NOTE_ADDED', incident_id=incident_id, actor=f'analyst:{analyst.strip()}',
                              payload={'note_id': note_id, 'analyst_id': analyst.strip(), 'evidence_id': evidence_id})
    return {'id': note_id, 'analyst': analyst.strip(), 'evidence_id': evidence_id,
            'text': text.strip(), 'time': timestamp}
