"""Evidence and category checks for agent-suggested ATT&CK mappings."""

import unittest

from services.validation import check_numeric_claims, validate_proposal


ALERT = "ALT-PORTSCAN-1"
CASE = "INC-MAPPING-1"


def check(technique_id: str, evidence_id: str = ALERT, alert_type: str = "PortScan"):
    payload = {
        "incident_id": CASE,
        "verdict": "Needs Review",
        "confidence": "low",
        "reason": "The retrieved alert needs analyst review before a conclusion.",
        "evidence_ids": [ALERT],
        "findings": [],
        "technique_mappings": [
            {
                "evidence_id": evidence_id,
                "technique_id": technique_id,
                "reason": "The cited alert supports this tentative mapping only.",
            }
        ],
        "next_steps": [],
        "limitations": "",
    }
    return validate_proposal(
        payload,
        incident_id=CASE,
        evidence_ids={ALERT: "alert"},
        evidence_numbers=set(),
        tool_call_count=1,
        seen_evidence_ids={ALERT},
        alert_types_by_id={ALERT: alert_type},
    )


class TechniqueMappingTests(unittest.TestCase):
    def test_port_identifier_is_not_mistaken_for_a_count(self):
        self.assertEqual(
            check_numeric_claims("Traffic reached 443 destination port.", set(), set()), []
        )
        self.assertTrue(
            check_numeric_claims("Traffic reached 443 destination ports.", set(), set())
        )

    def test_matching_alert_and_technique_are_accepted(self):
        report = check("T1046")
        self.assertTrue(report.ok, report.issue_messages())
        self.assertEqual(report.proposal["technique_mappings"][0]["evidence_id"], ALERT)

    def test_unrelated_evidence_and_incompatible_technique_are_rejected(self):
        self.assertFalse(check("T1046", evidence_id="ALT-OTHER").ok)
        self.assertFalse(check("T1498").ok)
        self.assertFalse(check("T1046", alert_type="BruteForce").ok)


if __name__ == "__main__":
    unittest.main()
