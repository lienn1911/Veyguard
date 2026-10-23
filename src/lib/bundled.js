/**
 * Offline fallback built from the committed Module 1/3 artefacts.
 *
 * Purpose: the dashboard, incident list and timeline must still work when the
 * Python API is not running (a teammate opening the repo without Python, or a
 * reviewer without a dataset). Everything produced here comes from real
 * ``real-alerts.json`` / ``real-timelines.json`` output - nothing is invented -
 * but it is explicitly labelled as the bundled preview, and AI triage stays
 * disabled because there is no backend to validate a verdict.
 *
 * Shapes intentionally mirror the API responses so components do not branch.
 */

import alertsPayload from '../real-alerts.json';
import timelinesPayload from '../real-timelines.json';

const alertsByIncident = new Map(alertsPayload.alerts.map((alert) => [alert.incident_id, alert]));
const timelinesByIncident = new Map(timelinesPayload.timelines.map((item) => [item.incident_id, item]));

function analystAlert(alert) {
  return {
    alert_id: alert.alert_id,
    type: alert.type,
    rule_basis: alert.rule_basis,
    flow_count: alert.flow_count,
    timestamp: alert.timestamp,
  };
}

export function bundledDataset() {
  const categories = {};
  alertsPayload.alerts.forEach((alert) => {
    categories[alert.type] = (categories[alert.type] || 0) + 1;
  });
  return {
    provenance: alertsPayload.provenance,
    rules: alertsPayload.rules,
    evaluation: alertsPayload.evaluation,
    counts: {
      incidents: alertsPayload.incidents.length,
      alerts: alertsPayload.alerts.length,
      sampled_flows: alertsPayload.flows.length,
      alert_categories: categories,
      represented_flows: alertsPayload.incidents.reduce(
        (total, incident) => total + (incident.flow_count || 0),
        0,
      ),
      timelines: timelinesPayload.timelines.length,
    },
    triage_summary: {},
    attack_categories: ['PortScan', 'DoS', 'BruteForce'],
    source: 'bundled',
  };
}

export function bundledIncidents() {
  return alertsPayload.incidents.map((incident) => {
    const alert = alertsByIncident.get(incident.incident_id);
    return {
      incident_id: incident.incident_id,
      category: alert?.type ?? 'Unknown',
      source_ip: incident.source_ip,
      destination_ip: incident.destination_ip,
      window_start: incident.window_start,
      flow_count: incident.flow_count,
      rule_basis: alert?.rule_basis ?? '',
      triage: {
        status: null,
        verdict: null,
        confidence: null,
        requires_confirmation: false,
        triaged_at: null,
        run_id: null,
        decision: 'pending',
      },
    };
  });
}

export function bundledIncident(incidentId) {
  const incident = alertsPayload.incidents.find((item) => item.incident_id === incidentId);
  if (!incident) return null;
  const alert = alertsByIncident.get(incidentId);
  const timeline = timelinesByIncident.get(incidentId) || { incident_id: incidentId, events: [] };
  const flows = alertsPayload.flows.filter((flow) =>
    (alert?.evidence_sample_ids || []).includes(flow.flow_id),
  );

  return {
    incident: {
      incident_id: incidentId,
      category: alert?.type ?? 'Unknown',
      source_ip: incident.source_ip,
      destination_ip: incident.destination_ip,
      window_start: incident.window_start,
      flow_count: incident.flow_count,
      source_file: incident.source_file,
      alert_id: alert?.alert_id ?? null,
      rule_basis: alert?.rule_basis ?? '',
      destination_port_count: alert?.destination_port_count ?? null,
      source_port_count: alert?.source_port_count ?? null,
      source_count: alert?.source_count ?? null,
      evidence_sample_ids: alert?.evidence_sample_ids ?? [],
      reference_label: {
        values: alert?.dataset_labels ?? {},
        note: 'CIC-IDS2017 ground-truth label, shown for evaluation only.',
      },
    },
    evidence: {
      incident_id: incidentId,
      alert: alert ? analystAlert(alert) : null,
      flows: flows.map((flow) => ({ ...flow, reference_label: flow.dataset_label || '' })),
      counts: {
        registered_evidence: flows.length + (alert ? 1 : 0),
        flow_records: flows.length,
      },
    },
    timeline,
    triage: null,
    decision: null,
    recommendations: {
      available: false,
      items: [],
      detail: 'Bundled preview: the API is offline, so Module 4 cannot be queried.',
      owner: 'Module 4 (teammate)',
    },
  };
}
