from threading import RLock, Event, Thread
from types import SimpleNamespace
from services.auto_analysis import AutoAnalysis


def coordinator(status):
    obj=object.__new__(AutoAnalysis)
    obj.lock=RLock(); obj.wake=Event(); obj.running=None
    obj.assessment=lambda _:status
    calls=[]
    obj.service=lambda:SimpleNamespace(investigate=lambda case: calls.append(case) or {'status':'ok'})
    return obj,calls


def test_open_reuses_results_and_does_not_retry_failures():
    for status in ({'status':'ready'}, {'status':'unavailable','error':{'code':'PROVIDER_RATE_LIMITED'}}, {'status':'not_configured'}):
        obj,calls=coordinator(status)
        obj.investigate('case',only_if_needed=True)
        assert calls==[]


def test_open_runs_missing_or_stale_evidence_once():
    for status in ({'status':'pending'}, {'status':'unavailable','error':{'code':'EVIDENCE_INTEGRITY_FAILED'}}):
        obj,calls=coordinator(status)
        assert obj.investigate('case',only_if_needed=True)['status']=='ok'
        status.clear();status.update(status='ready')
        obj.investigate('case',only_if_needed=True)
        assert calls==['case']


def test_concurrent_open_does_not_duplicate_the_model_request():
    obj,calls=coordinator({'status':'pending'})
    entered=Event();finish=Event()
    def run(case):
        calls.append(case); entered.set(); assert finish.wait(5)
        return {'status':'ok'}
    obj.service=lambda:SimpleNamespace(investigate=run)
    thread=Thread(target=lambda:obj.investigate('case',only_if_needed=True))
    thread.start(); assert entered.wait(5)
    try:
        assert obj.investigate('case',only_if_needed=True)['status']=='busy'
        assert obj.investigate('other',only_if_needed=True)['status']=='busy'
    finally:
        finish.set();thread.join(5)
    assert calls==['case']
    assert obj.running is None
