"""Transparent investigation order, independent of AI verdict and ground truth."""
import math
from datetime import datetime

VERSION = 'activity-v1'
LEVELS = ('High', 'Medium', 'Low')


def suggested_priority(data, incident):
    unknown = {'level': 'Not assessed', 'score': None, 'source': 'rules',
               'version': VERSION, 'reasons': ['Case activity measurements are incomplete.']}
    by_id = {row['alert_id']: row for row in data.get('alerts', [])}
    ids = incident.get('alert_ids') or []
    alerts = [by_id[key] for key in ids if key in by_id]
    def number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0
    count = incident.get('flow_count')
    if not ids or len(alerts) != len(ids) or not number(count):
        return unknown
    if any(not number(row.get('destination_port_count')) or not number(row.get('flow_count'))
           or not row.get('source_ip') for row in alerts):
        return unknown
    if sum(row['flow_count'] for row in alerts) != count:
        return unknown
    try:
        first = datetime.fromisoformat(incident['window_start'])
        last = datetime.fromisoformat(incident['window_end'])
        elapsed = (last - first).total_seconds() / 60
        if elapsed < 0:
            return unknown
    except (KeyError, TypeError, ValueError):
        return unknown
    # Alert windows represent minute starts; include the final minute. Gaps
    # count toward the window average, rather than overstating burst density.
    rate = count / (elapsed + 1)
    ports = max(row['destination_port_count'] for row in alerts)
    sources = len({row['source_ip'] for row in alerts})
    score, reasons = 0, []
    if rate >= 5000:
        points = 2 if rate >= 10000 else 1
        score += points
        reasons.append(f'{rate:,.0f} flow records per minute across the case window (+{points})')
    if len(alerts) >= 3:
        points = 2 if len(alerts) >= 10 else 1
        score += points
        reasons.append(f'{len(alerts)} related alerts (+{points})')
    if sources >= 3:
        score += 2
        reasons.append(f'{sources} observed source IPs (+2)')
    if ports >= 100:
        points = 2 if ports >= 250 else 1
        score += points
        reasons.append(f'Up to {ports} destination ports in one minute (+{points})')
    return {'level': 'High' if score >= 5 else 'Medium' if score >= 3 else 'Low',
            'score': score, 'source': 'rules', 'version': VERSION,
            'reasons': reasons or ['Activity is below the higher review-order thresholds.']}


def effective_priority(data, incident, override=None):
    suggested = suggested_priority(data, incident)
    if override and override.get('level') in LEVELS:
        return {**suggested, 'level': override['level'], 'source': 'analyst',
                'reason': override.get('reason'), 'analyst': override.get('analyst'),
                'updated_at': override.get('updated_at'), 'suggested': suggested}
    return {**suggested, 'suggested': suggested}


def latest_overrides(db):
    overrides = {}
    import json
    for incident_id, payload, timestamp in db.execute(
            "SELECT incident_id, payload, ts FROM audit_events WHERE event = 'CASE_REVIEW_PRIORITY_SET' ORDER BY seq"):
        overrides[incident_id] = {**json.loads(payload), 'updated_at': timestamp}
    return overrides


def save_priority(data, incident_id, level, reason, analyst, confirmed, db_path):
    from contextlib import closing
    import sqlite3
    from .unified_audit import initialize, append_in_transaction
    incident = next((row for row in data['incidents'] if row['incident_id'] == incident_id), None)
    if incident is None:
        raise ValueError('Unknown case')
    if level not in (*LEVELS, 'automatic'):
        raise ValueError('Choose High, Medium, Low or the rule suggestion')
    if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1000:
        raise ValueError('A reason of 10-1000 characters is required')
    if not isinstance(analyst, str) or not analyst.strip() or confirmed is not True:
        raise ValueError('Explicit analyst confirmation is required')
    initialize(db_path)
    with closing(sqlite3.connect(db_path, timeout=30)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        previous = effective_priority(data, incident, latest_overrides(db).get(incident_id))
        payload = {'level': None if level == 'automatic' else level, 'reason': reason.strip(),
                   'analyst': analyst, 'previous_level': previous['level'],
                   'previous_source': previous['source'], 'suggested_level': previous['suggested']['level'],
                   'version': VERSION}
        event = append_in_transaction(db, 'CASE_REVIEW_PRIORITY_SET', incident_id=incident_id,
                                      actor=f'analyst:{analyst}', payload=payload)
        # Time comes from the immutable event, not a user-supplied timestamp.
        payload['updated_at'] = event['ts']
        return effective_priority(data, incident, payload)
