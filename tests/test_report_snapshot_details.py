import json
from services import api
from services.unified_audit import append


def test_report_freezes_ai_work_reviewer_and_activity(tmp_path, monkeypatch):
    db=tmp_path/'report.db';monkeypatch.setattr(api,'DB_PATH',db)
    data=json.loads(api.DATA.read_text(encoding='utf-8'));case=data['incidents'][0]['incident_id']
    check=api.generate_recommendations(data,case)[0]
    payload={'status':'ready','investigation':{'tool_calls':[{'tool':'get_network_flows','ok':True}]},
      'run_metadata':{'duration_ms':1234},'validation':{'ok':True},
      'decision':{'status':'confirmed','analyst':'IsolatedTester','at':'2026-10-24T12:00:00Z','note':'Reviewed the linked evidence.'},
      'assessment':{'run_id':'RUN-ISOLATED','summary':'Flow evidence requires further review.','verdict':'Needs Review',
        'findings':[{'observation':'Read the linked sample.','evidence_ids':check['evidence_ids'][:1]}],
        'next_steps':[{'action':check['action'],'reason':'Inspect the linked evidence.','evidence_ids':check['evidence_ids'][:1]}]}}
    monkeypatch.setattr(api,'ai_assessment',lambda _:payload)
    append(db,'triage.tool_call',incident_id=case,actor='system:test-fixture',payload={'tool':'get_network_flows'})
    saved=api.save_case_record(data,case,'IsolatedTester')['record']
    assert saved['ai_run_metadata']['duration_ms']==1234
    assert saved['analyst_review']['analyst']=='IsolatedTester'
    assert saved['investigation_steps'][0]['text']==check['description']
    assert saved['activity'][0]['event']=='triage.tool_call'
    payload['run_metadata']['duration_ms']=9999
    append(db,'TEST_LATER_ACTIVITY',incident_id=case,actor='system:test-fixture')
    frozen=api.case_record(data,case)['record']
    assert frozen['ai_run_metadata']['duration_ms']==1234
    assert not any(e['event']=='TEST_LATER_ACTIVITY' for e in frozen['activity'])
