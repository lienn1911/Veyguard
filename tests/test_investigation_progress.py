from services.providers.base import ProviderRateLimited
from tests.conftest import answer_turn, investigation_turn
from tests.test_agent_loop import make_proposal


def test_live_progress_tracks_real_stages_and_finishes_only_after_success(service_factory, dataset, incidents_by_category):
    case = incidents_by_category['PortScan']
    service, provider = service_factory([investigation_turn(case), answer_turn(make_proposal(dataset, case, 'Needs Review'))])
    observed = []
    update = service._set_progress
    def capture(*args, **kwargs):
        update(*args, **kwargs)
        observed.append(service.progress(case))
    service._set_progress = capture
    complete = provider.complete
    def during_model_call(*args, **kwargs):
        assert service.progress(case)['running'] is True
        assert service.progress(case)['percent'] < 100
        assert service.progress('unrelated-case') is None
        return complete(*args, **kwargs)
    provider.complete = during_model_call
    result = service.investigate(case)
    assert result['status'] == 'ok'
    assert {'evidence','analyse','validate','save','complete'} <= {p['stage'] for p in observed}
    assert [p['percent'] for p in observed] == sorted(p['percent'] for p in observed)
    assert service.progress(case)['percent'] == 100
    assert service.progress(case)['running'] is False


def test_rate_limit_never_reports_complete_and_retry_resets_progress(service_factory, incidents_by_category):
    case = incidents_by_category['PortScan']
    service, provider = service_factory([ProviderRateLimited('Test quota exhausted')])
    service._set_progress(case, 'complete', 100, 'Previous completed run', running=False)
    original = provider.complete
    def check_reset(*args, **kwargs):
        assert service.progress(case)['percent'] == 30
        return original(*args, **kwargs)
    provider.complete = check_reset
    result = service.investigate(case)
    assert result['status'] != 'ok'
    assert service.progress(case)['stage'] == 'failed'
    assert service.progress(case)['percent'] < 100
    assert service.progress(case)['running'] is False
