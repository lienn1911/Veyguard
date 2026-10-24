"""Local, indexed copy of the complete CIC flow archive for analyst drill-down."""

import argparse
import csv
import io
import json
import os
import sqlite3
import zipfile
import zlib
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

from services.alerts import finite_number, parse_time


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / 'data' / 'raw-flows.db'
PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


def import_archive(archive_path, db_path=DEFAULT_DB):
    archive_path = Path(archive_path)
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = db_path.with_suffix('.importing.db')
    if temporary.exists():
        temporary.unlink()
    db = sqlite3.connect(temporary)
    try:
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('PRAGMA synchronous=OFF')
        db.execute('PRAGMA temp_store=MEMORY')
        db.executescript('''
            CREATE TABLE raw_flows (
                id INTEGER PRIMARY KEY,
                source_file TEXT NOT NULL,
                source_row INTEGER NOT NULL,
                event_time TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port TEXT NOT NULL,
                destination_port TEXT NOT NULL,
                protocol TEXT NOT NULL,
                flow_id TEXT NOT NULL,
                forward_packets REAL NOT NULL,
                backward_packets REAL NOT NULL,
                raw_json BLOB NOT NULL
            );
            CREATE TABLE import_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ''')
        total = 0
        files = []
        with zipfile.ZipFile(archive_path) as archive:
            members = [name for name in archive.namelist() if name.lower().endswith('.csv')]
            if not members:
                raise ValueError('Archive contains no CSV files')
            for member in members:
                source_file = Path(member).name
                reader = csv.DictReader(io.TextIOWrapper(archive.open(member), encoding='cp1252', errors='replace', newline=''))
                batch = []
                file_rows = 0
                invalid_timestamps = 0
                blank_rows = 0
                for source_row, row in enumerate(reader, start=2):
                    fields = {key.strip().removeprefix('ï»¿'): str(value).strip() for key, value in row.items() if key}
                    normalized = {key.lower(): value for key, value in fields.items()}
                    if not any(normalized.get(key) for key in ('flow id', 'source ip', 'destination ip', 'timestamp')):
                        blank_rows += 1
                        continue
                    try:
                        stamp = parse_time(normalized.get('timestamp', ''), source_file).isoformat(timespec='seconds')
                    except ValueError:
                        stamp = ''
                        invalid_timestamps += 1
                    batch.append((source_file, source_row, stamp,
                                  normalized.get('source ip', ''), normalized.get('destination ip', ''),
                                  normalized.get('source port', ''), normalized.get('destination port', ''),
                                  normalized.get('protocol', ''), normalized.get('flow id', ''),
                                  finite_number(normalized.get('total fwd packets')),
                                  finite_number(normalized.get('total backward packets')),
                                  zlib.compress(json.dumps(fields, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), 1)))
                    if len(batch) >= 1000:
                        db.executemany('''INSERT INTO raw_flows
                            (source_file, source_row, event_time, source_ip, destination_ip,
                             source_port, destination_port, protocol, flow_id,
                             forward_packets, backward_packets, raw_json)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', batch)
                        file_rows += len(batch)
                        batch.clear()
                if batch:
                    db.executemany('''INSERT INTO raw_flows
                        (source_file, source_row, event_time, source_ip, destination_ip,
                         source_port, destination_port, protocol, flow_id,
                         forward_packets, backward_packets, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', batch)
                    file_rows += len(batch)
                db.commit()
                total += file_rows
                files.append({'name': source_file, 'rows': file_rows, 'invalid_timestamps': invalid_timestamps,
                              'blank_rows_skipped': blank_rows})
                print(f'Imported {source_file}: {file_rows:,} flows ({blank_rows:,} blank rows skipped)', flush=True)
        print('Creating lookup index...', flush=True)
        db.execute('CREATE INDEX raw_flows_case_time ON raw_flows (source_file, source_ip, destination_ip, event_time, id)')
        meta = {'archive': archive_path.name, 'archive_bytes': archive_path.stat().st_size,
                'rows': total, 'files': files, 'complete': True}
        db.execute('INSERT INTO import_meta (key, value) VALUES (?, ?)', ('manifest', json.dumps(meta)))
        db.commit()
    except BaseException:
        db.close()
        temporary.unlink(missing_ok=True)
        raise
    db.close()
    os.replace(temporary, db_path)
    return meta


def database_status(db_path=DEFAULT_DB):
    if not Path(db_path).exists():
        return {'available': False, 'reason': 'Raw archive has not been imported'}
    with closing(sqlite3.connect(f'file:{Path(db_path).resolve().as_posix()}?mode=ro', uri=True)) as db:
        row = db.execute('SELECT value FROM import_meta WHERE key = ?', ('manifest',)).fetchone()
    if not row:
        return {'available': False, 'reason': 'Raw archive import is incomplete'}
    return {'available': True, **json.loads(row[0])}


def query_case_flows(incident, alerts, *, minute=None, page=1, page_size=PAGE_SIZE, db_path=DEFAULT_DB):
    if not isinstance(page, int) or not 1 <= page <= 100000:
        raise ValueError('Page must be between 1 and 100000')
    if not isinstance(page_size, int) or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f'Page size must be between 1 and {MAX_PAGE_SIZE}')
    case_start = datetime.fromisoformat(incident['window_start'][:16]) - timedelta(minutes=1)
    case_end = datetime.fromisoformat(incident['window_end'][:16]) + timedelta(minutes=2)
    if minute is not None:
        try:
            start = datetime.strptime(minute, '%Y-%m-%dT%H:%M')
        except ValueError as error:
            raise ValueError('Minute must use YYYY-MM-DDTHH:MM') from error
        end = start + timedelta(minutes=1)
        if start < case_start or end > case_end:
            raise ValueError('Minute is outside this case context')
    else:
        start, end = case_start, case_end
    pairs = sorted({(alert['source_ip'], alert['destination_ip']) for alert in alerts})
    if not pairs:
        return {'total': 0, 'page': page, 'page_size': page_size, 'records': []}
    clauses = ' OR '.join('(source_ip = ? AND destination_ip = ?)' for _ in pairs)
    params = [incident['source_file'], start.isoformat(timespec='seconds'), end.isoformat(timespec='seconds')]
    params.extend(value for pair in pairs for value in pair)
    where = f'source_file = ? AND event_time >= ? AND event_time < ? AND ({clauses})'
    with closing(sqlite3.connect(f'file:{Path(db_path).resolve().as_posix()}?mode=ro', uri=True)) as db:
        total = db.execute(f'SELECT COUNT(*) FROM raw_flows WHERE {where}', params).fetchone()[0]
        rows = db.execute(f'''SELECT source_file, source_row, event_time, source_ip, destination_ip,
                                     source_port, destination_port, protocol, flow_id,
                                     forward_packets, backward_packets, raw_json
                              FROM raw_flows WHERE {where}
                              ORDER BY event_time, id LIMIT ? OFFSET ?''',
                          [*params, page_size, (page - 1) * page_size]).fetchall()
    records = [{
        'source_file': row[0], 'source_row': row[1], 'timestamp': row[2],
        'source_ip': row[3], 'destination_ip': row[4],
        'source_port': row[5], 'destination_port': row[6], 'protocol': row[7],
        'flow_id': row[8], 'forward_packets': row[9], 'backward_packets': row[10],
        'fields': json.loads(zlib.decompress(row[11])),
    } for row in rows]
    return {'total': total, 'page': page, 'page_size': page_size, 'records': records,
            'start': start.isoformat(timespec='minutes'), 'end': end.isoformat(timespec='minutes')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('-o', '--output', type=Path, default=DEFAULT_DB)
    args = parser.parse_args()
    print(json.dumps(import_archive(args.archive, args.output)), flush=True)


if __name__ == '__main__':
    main()
