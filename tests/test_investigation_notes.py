import json
import sqlite3
import pytest
from services import api
from services.case_notes import add_note, list_notes
from services.unified_audit import entries, verify


def dataset():
    return json.loads(api.DATA.read_text(encoding='utf-8'))


def test_general_note_persists_without_creating_approval(tmp_path):
    data=dataset();case=data['incidents'][0]['incident_id'];db=tmp_path/'notes.db'
    note=add_note(data,case,'Tester',None,'Check whether scanning was authorized.',db_path=db)
    assert list_notes(case,db_path=db)==[note]
    assert note['evidence_id']==''
    with sqlite3.connect(db) as connection:
        assert connection.execute('SELECT COUNT(*) FROM decisions').fetchone()[0]==0
    audit=entries(db,incident_id=case)
    assert audit[-1]['event']=='ANALYST_NOTE_ADDED'
    assert audit[-1]['payload']['text']==note['text']
    assert verify(db)['ok']


def test_note_cannot_link_to_foreign_evidence(tmp_path):
    data=dataset();case=data['incidents'][0]['incident_id']
    with pytest.raises(ValueError,match='Select evidence'):
        add_note(data,case,'Tester','ALT-NOT-IN-CASE','Finding',db_path=tmp_path/'notes.db')


def test_report_freezes_notes_at_save(tmp_path,monkeypatch):
    data=dataset();case=data['incidents'][0]['incident_id'];db=tmp_path/'notes.db'
    monkeypatch.setattr(api,'DB_PATH',db)
    monkeypatch.setattr(api,'ai_assessment',lambda _: {'status':'pending','assessment':None})
    first=add_note(data,case,'Tester',None,'First finding',db_path=db)
    assert api.case_record(data,case)['record']['investigation_notes']==[first]
    saved=api.save_case_record(data,case,'Tester')
    add_note(data,case,'Tester',data['incidents'][0]['alert_ids'][0],'Later finding',db_path=db)
    assert len(list_notes(case,db_path=db))==2
    assert api.case_record(data,case)['record']['investigation_notes']==saved['record']['investigation_notes']==[first]
