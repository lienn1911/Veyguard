"""Read-only access to the Module 1 / Module 3 artefacts.

The datasets (``src/real-alerts.json``, ``src/real-timelines.json``) are produced
by teammates' scripts. This module never writes to them and never mutates the
loaded objects: every accessor returns copies.

Two views exist on purpose:

``agent_*``   the view handed to the LLM. Dataset ground-truth labels are
              removed, so a verdict can only come from observable flow
              features and Module 1's own rule output.
``analyst_*`` the view rendered in the UI, where the CIC-IDS2017 reference label
              is shown separately and explicitly marked as evaluation data.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

#: Fields that leak the ground-truth label and must never reach a provider.
LABEL_FIELDS = ("dataset_label", "dataset_labels", "ddos_reference", "reference_label")

# Explicit model-facing schema: adding fields to the stored alert must not
# silently expose dataset provenance, labels, or analyst-only annotations.
AGENT_ALERT_FIELDS = (
    "alert_id", "incident_id", "type", "timestamp", "source_ip",
    "destination_ip", "flow_count", "destination_port_count",
    "source_port_count", "source_count", "evidence_sample_ids", "rule_basis",
)

#: Attack categories that trigger the Module 5 human-confirmation rule.
ATTACK_CATEGORIES = ("PortScan", "DoS", "DDoS")


class DatasetError(RuntimeError):
    """Raised when the Module 1/3 artefacts are missing or inconsistent."""


class IncidentNotFound(LookupError):
    """Raised when an incident id is not present in the Module 1 artefacts."""

    def __init__(self, incident_id: str):
        super().__init__(incident_id)
        self.incident_id = incident_id

    def __str__(self) -> str:
        return f"No incident {self.incident_id!r} exists in the dataset."


@dataclass(frozen=True)
class IncidentRecord:
    incident: dict
    alert: dict
    timeline: dict | None

    @property
    def category(self) -> str:
        return str(self.alert.get("type") or "Unknown")

    @property
    def incident_id(self) -> str:
        return str(self.incident.get("incident_id"))


def _read_json(path: Path) -> dict:
    if not path.exists():
        raise DatasetError(
            f"Dataset not found: {path}. Run the Module 1/3 scripts first "
            "(see README) or set ALERTS_PATH / TIMELINES_PATH."
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DatasetError(f"{path} is not valid JSON: {exc}") from exc


def strip_labels(record: dict) -> dict:
    return {key: value for key, value in record.items() if key not in LABEL_FIELDS}


class Dataset:
    """In-memory index over the alert and timeline artefacts."""

    def __init__(self, alerts_payload: dict, timelines_payload: dict | None = None):
        self._alerts_payload = alerts_payload
        self._timelines_payload = timelines_payload or {"timelines": []}

        self.flows: dict[str, dict] = {
            flow["flow_id"]: flow for flow in alerts_payload.get("flows", []) if "flow_id" in flow
        }
        self.alerts: dict[str, dict] = {
            alert["alert_id"]: alert
            for alert in alerts_payload.get("alerts", [])
            if "alert_id" in alert
        }
        self.incidents: dict[str, dict] = {
            incident["incident_id"]: incident
            for incident in alerts_payload.get("incidents", [])
            if "incident_id" in incident
        }
        self._alert_by_incident = {}
        for alert in self.alerts.values():
            if "incident_id" in alert:
                self._alert_by_incident.setdefault(alert["incident_id"], alert)
        self._timeline_by_incident = {
            timeline["incident_id"]: timeline
            for timeline in self._timelines_payload.get("timelines", [])
            if "incident_id" in timeline
        }

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, alerts_path: Path, timelines_path: Path | None = None) -> "Dataset":
        timelines = _read_json(timelines_path) if timelines_path and timelines_path.exists() else None
        return cls(_read_json(alerts_path), timelines)

    # --------------------------------------------------------------- lookups
    def incident_ids(self) -> list[str]:
        return list(self.incidents)

    def record(self, incident_id: str) -> IncidentRecord | None:
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None
        alert = self._alert_by_incident.get(incident_id)
        if alert is None:
            return None
        return IncidentRecord(incident, alert, self._timeline_by_incident.get(incident_id))

    def require(self, incident_id: str) -> IncidentRecord:
        record = self.record(incident_id)
        if record is None:
            raise IncidentNotFound(incident_id)
        return record

    def timeline(self, incident_id: str) -> dict:
        return copy.deepcopy(
            self._timeline_by_incident.get(incident_id) or {"incident_id": incident_id, "events": []}
        )

    # -------------------------------------------------------------- evidence
    def evidence_ids(self, incident_id: str) -> dict[str, str]:
        """Map every citable evidence id for an incident to its record type."""
        record = self.record(incident_id)
        if record is None:
            return {}
        mapping: dict[str, str] = {}
        for flow_id in record.alert.get("evidence_sample_ids") or []:
            if flow_id in self.flows:
                mapping[flow_id] = "flow"
        for flow_id in record.incident.get("evidence_sample_ids") or []:
            if flow_id in self.flows:
                mapping.setdefault(flow_id, "flow")
        for alert_id in record.incident.get("alert_ids") or []:
            if alert_id in self.alerts:
                mapping[alert_id] = "alert"
        if record.alert.get("alert_id"):
            mapping.setdefault(record.alert["alert_id"], "alert")
        return mapping

    def evidence_flows(self, incident_id: str) -> list[dict]:
        record = self.record(incident_id)
        if record is None:
            return []
        ids = [flow_id for flow_id in record.incident.get('evidence_sample_ids') or [] if flow_id in self.flows]
        return [self.flows[flow_id] for flow_id in ids]

    # ------------------------------------------------------------ agent view
    def agent_incident_details(self, incident_id: str) -> dict:
        record = self.require(incident_id)
        incident, alert = record.incident, record.alert
        return {
            "incident_id": incident_id,
            "window_start": incident.get("window_start"),
            "window_seconds": (self._alerts_payload.get("rules") or {}).get("window_seconds", 60),
            "source_ip": incident.get("source_ip"),
            "destination_ip": incident.get("destination_ip"),
            "source_ips": list(incident.get('source_ips') or [incident.get('source_ip')]),
            "destination_ips": list(incident.get('destination_ips') or [incident.get('destination_ip')]),
            "aggregated_flow_count": incident.get("flow_count"),
            "alert_ids": list(incident.get("alert_ids") or []),
            "evidence_sample_size": len(incident.get("evidence_sample_ids") or []),
            "data_scope_note": (
                "Aggregated counts come from Module 1 over the full one-minute window. "
                "Only a sample of individual flow records is retained as evidence."
            ),
        }

    def agent_alerts(self, incident_id: str) -> list[dict]:
        record = self.require(incident_id)
        return [{key: copy.deepcopy(self.alerts[alert_id][key])
                 for key in AGENT_ALERT_FIELDS if key in self.alerts[alert_id]}
                for alert_id in record.incident.get('alert_ids') or [] if alert_id in self.alerts]

    def agent_flows(self, incident_id: str, limit: int = 6) -> list[dict]:
        flows = self.evidence_flows(incident_id)[: max(1, min(limit, 20))]
        return [
            {
                "flow_id": flow.get("flow_id"),
                "timestamp": flow.get("timestamp"),
                "source_ip": flow.get("source_ip"),
                "source_port": flow.get("source_port"),
                "destination_ip": flow.get("destination_ip"),
                "destination_port": flow.get("destination_port"),
                "packet_count": flow.get("packet_count"),
            }
            for flow in flows
        ]

    def agent_statistics(self, incident_id: str) -> dict:
        record = self.require(incident_id)
        alert = record.alert
        case_alerts = [self.alerts[alert_id] for alert_id in record.incident.get('alert_ids') or [] if alert_id in self.alerts]
        flows = self.evidence_flows(incident_id)
        dest_ports = [flow.get("destination_port") for flow in flows]
        src_ports = [flow.get("source_port") for flow in flows]
        packets = [float(flow.get("packet_count") or 0) for flow in flows]
        return {
            "incident_id": incident_id,
            "window_seconds": (self._alerts_payload.get("rules") or {}).get("window_seconds", 60),
            "group_totals": {
                "flows": record.incident.get("flow_count"),
                "alert_minutes": len(case_alerts),
            },
            "alert_totals": [{"alert_id": item.get("alert_id"), "flows": item.get("flow_count"),
                              "destination_ports": item.get("destination_port_count"),
                              "source_ports": item.get("source_port_count"),
                              "independent_sources": item.get("source_count")}
                             for item in case_alerts],
            "sampled": {
                "flows_returned": len(flows),
                "distinct_destination_ports": len(set(dest_ports)),
                "distinct_source_ports": len(set(src_ports)),
                "mean_packets_per_flow": round(sum(packets) / len(packets), 2) if packets else 0,
                "top_destination_ports": _top_counts(dest_ports),
            },
            "rule_basis": alert.get("rule_basis"),
            "scope_note": (
                "alert_totals describe individual one-minute groups; group_totals.flows is the case sum. "
                "sampled describes only the individual flow records retrieved as evidence."
            ),
        }

    def canonical_statistic_numbers(self, incident_id: str) -> set[float]:
        """Numbers backed by stored aggregates or computed from linked sample flows."""
        record = self.require(incident_id)
        numbers = {float(record.incident.get('flow_count') or 0)}
        for alert_id in record.incident.get('alert_ids') or []:
            alert = self.alerts.get(alert_id)
            if not alert:
                continue
            for field in ('flow_count', 'destination_port_count', 'source_port_count', 'source_count'):
                if isinstance(alert.get(field), (int, float)):
                    numbers.add(float(alert[field]))
            # The raw aggregate packet total is retained in the rule basis.
            for match in re.finditer(r'([\d,]+)\s+packets?', alert.get('rule_basis') or '', re.IGNORECASE):
                numbers.add(float(match.group(1).replace(',', '')))
        samples = self.evidence_flows(incident_id)
        numbers.add(float(len(samples)))
        packets = [float(flow.get('packet_count') or 0) for flow in samples]
        numbers.update(packets)
        numbers.add(float(len({flow.get('destination_port') for flow in samples})))
        numbers.add(float(len({flow.get('source_port') for flow in samples})))
        if packets:
            numbers.add(float(round(sum(packets) / len(packets), 2)))
        return numbers

    # ---------------------------------------------------------- analyst view
    def analyst_incident(self, incident_id: str) -> dict:
        record = self.require(incident_id)
        incident, alert = record.incident, record.alert
        return {
            "incident_id": incident_id,
            "category": alert.get("type"),
            "source_ip": incident.get("source_ip"),
            "destination_ip": incident.get("destination_ip"),
            "window_start": incident.get("window_start"),
            "flow_count": incident.get("flow_count"),
            "source_file": incident.get("source_file"),
            "alert_id": alert.get("alert_id"),
            "rule_basis": alert.get("rule_basis"),
            "destination_port_count": alert.get("destination_port_count"),
            "source_port_count": alert.get("source_port_count"),
            "source_count": alert.get("source_count"),
            "evidence_sample_ids": list(incident.get("evidence_sample_ids") or []),
            # Explicitly separated evaluation data - never used by the agent.
            "reference_label": {
                "values": alert.get("dataset_labels") or {},
                "note": "CIC-IDS2017 ground-truth label, shown for evaluation only.",
            },
        }

    def analyst_evidence(self, incident_id: str) -> dict:
        record = self.require(incident_id)
        flows = self.evidence_flows(incident_id)
        alert = record.alert
        return {
            "incident_id": incident_id,
            "alerts": [{"alert_id": item.get('alert_id'), "type": item.get('type'),
                        "rule_basis": item.get('rule_basis'), "flow_count": item.get('flow_count'),
                        "timestamp": item.get('timestamp')}
                       for item in self.agent_alerts(incident_id)],
            "alert": {
                "alert_id": alert.get("alert_id"),
                "type": alert.get("type"),
                "rule_basis": alert.get("rule_basis"),
                "flow_count": alert.get("flow_count"),
                "timestamp": alert.get("timestamp"),
            },
            "flows": [
                {
                    **strip_labels(flow),
                    "reference_label": flow.get("dataset_label") or "",
                }
                for flow in flows
            ],
            "counts": {
                "registered_evidence": len(flows) + len(record.incident.get('alert_ids') or []),
                "flow_records": len(flows),
            },
        }

    # ----------------------------------------------------------------- meta
    def summary(self) -> dict:
        categories: dict[str, int] = {}
        for alert in self.alerts.values():
            key = str(alert.get("type") or "Unknown")
            categories[key] = categories.get(key, 0) + 1
        represented_flows = sum(int(incident.get("flow_count") or 0) for incident in self.incidents.values())
        return {
            "provenance": self._alerts_payload.get("provenance") or {},
            "rules": self._alerts_payload.get("rules") or {},
            "evaluation": self._alerts_payload.get("evaluation") or {},
            "counts": {
                "incidents": len(self.incidents),
                "alerts": len(self.alerts),
                "sampled_flows": len(self.flows),
                "alert_categories": categories,
                "represented_flows": represented_flows,
                "timelines": len(self._timeline_by_incident),
            },
        }


def _top_counts(values: Iterable[Any], limit: int = 3) -> list[dict]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"port": port, "count": count} for port, count in ordered[:limit]]
