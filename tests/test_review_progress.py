from services.api import review_progress


def test_no_ai_or_saved_report_is_not_reviewed():
    assert review_progress(False, 'confirmed', [], {})['state'] == 'pending'


def test_ai_review_alone_is_partial_when_steps_remain():
    result = review_progress(True, 'confirmed', ['a', 'b'], {})
    assert result['state'] == 'partial'
    assert (result['reviewed'], result['total']) == (1, 3)


def test_one_step_does_not_complete_review():
    assert review_progress(True, 'pending', ['a', 'b'], {'a': 'APPROVED'})['state'] == 'partial'


def test_rejections_also_count_as_reviewed():
    assert review_progress(True, 'rejected', ['a', 'b'], {'a': 'APPROVED', 'b': 'REJECTED'})['state'] == 'complete'


def test_old_step_decisions_do_not_complete_current_plan():
    result = review_progress(True, 'confirmed', ['new'], {'old': 'APPROVED'})
    assert result['state'] == 'partial'
    assert result['steps_reviewed'] == 0


def test_no_proposed_steps_only_requires_ai_review():
    assert review_progress(True, 'confirmed', [], {})['state'] == 'complete'


def test_unavailable_ai_cannot_be_complete_with_step_decisions():
    assert review_progress(False, 'confirmed', ['a'], {'a': 'APPROVED'})['state'] == 'partial'


def test_saved_report_is_findable_without_marking_case_reviewed(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from services import api, recommendations
    from services.unified_audit import append
    data = json.loads(api.DATA.read_text(encoding='utf-8'))
    incident_id = data['incidents'][0]['incident_id']
    db = tmp_path / 'reviews.db'
    monkeypatch.setattr(api, 'DB_PATH', db)
    monkeypatch.setattr(api, 'init_db', lambda: recommendations.init_db(db))
    monkeypatch.setattr(api, 'ai_service', lambda: SimpleNamespace(
        settings=SimpleNamespace(is_mock=False, provider='test', model='test'), latest=lambda _id: {}))
    event = append(db, 'CASE_RECORD_SAVED', incident_id=incident_id, actor='analyst:Tester', payload={'case_summary': 'Stored report'})
    item = api.case_queue(data)[incident_id]
    assert item['saved_report']['event_id'] == event['event_id']
    assert item['saved_report']['saved_by'] == 'analyst:Tester'
    assert item['review_progress']['state'] == 'pending'
    assert api.case_record(data, incident_id)['record']['case_summary'] == 'Stored report'
