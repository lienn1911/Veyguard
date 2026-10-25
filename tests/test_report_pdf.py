from copy import deepcopy
from services.report_pdf import build_report_pdf


def test_pdf_export_is_read_only_and_handles_review_markup():
    state = {
        "status": "saved",
        "event_id": "RECORD-1",
        "saved_at": "2026-10-24T10:00:00Z",
        "record": {
            "ai_summary": "Read-only finding <tag> & evidence.",
            "analyst_review": {"status": "rejected", "note": "中文备注 <review> & reason"},
            "activity": [],
        },
    }
    before = deepcopy(state)
    pdf = build_report_pdf("INC-TEST", {"type": "PortScan"}, [], [], state)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000
    assert state == before


def test_pdf_paginates_long_notes_and_evidence_without_truncation_errors():
    state = {
        "status": "ready",
        "record": {
            "ai_summary": "A finding. " * 100,
            "analyst_review": {"note": "Detailed review rationale. " * 300},
            "investigation_steps": [{"text": "Check evidence", "decision": "approved"}],
        },
    }
    flows = [{"flow_id": f"FLOW-{i}", "timestamp": "2017-07-07 15:08:00"} for i in range(150)]
    pdf = build_report_pdf("INC-LONG", {"flow_count": 10000}, [], flows, state)
    assert pdf.startswith(b"%PDF-")
    assert pdf.count(b"/Type /Page\n") > 1
