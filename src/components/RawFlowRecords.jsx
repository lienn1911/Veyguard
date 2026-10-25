import React, { useEffect, useState } from 'react';

const format = (value) => Number(value || 0).toLocaleString('en-US');
const protocolName = (value) =>
  ({ 6: 'TCP', 17: 'UDP', 1: 'ICMP' })[String(value)] || String(value || '—');
const flowBytes = (fields) =>
  Number(fields['Total Length of Fwd Packets'] || 0) +
  Number(fields['Total Length of Bwd Packets'] || 0);

export default function RawFlowRecords({ incidentId, minute }) {
  const [page, setPage] = useState(1);
  const [showAll, setShowAll] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    setPage(1);
    setShowAll(false);
  }, [incidentId, minute]);
  useEffect(() => {
    setShowAll(false);
  }, [page]);
  useEffect(() => {
    if (!incidentId) return;
    const controller = new AbortController();
    const params = new URLSearchParams({ page: String(page) });
    if (minute) params.set('minute', minute);
    setResult(null);
    setError('');
    fetch(`/api/cases/${encodeURIComponent(incidentId)}/raw-flows?${params}`, {
      signal: controller.signal,
    })
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok)
          throw new Error(
            payload.error === 'Unknown endpoint'
              ? 'Raw records service is outdated. Restart SOC Desk.'
              : payload.error || 'Raw records unavailable',
          );
        setResult(payload);
      })
      .catch((reason) => {
        if (reason.name !== 'AbortError') setError(reason.message);
      });
    return () => controller.abort();
  }, [incidentId, minute, page]);

  if (error)
    return (
      <p className="incident-evidence-empty" role="alert">
        {error}
      </p>
    );
  if (!result) return <p className="incident-evidence-empty">Loading communication records…</p>;
  if (!result.available)
    return (
      <p className="incident-evidence-empty">
        Communication records are not imported on this computer. Run the dataset import from the
        README.
      </p>
    );

  const pages = Math.ceil(result.total / result.page_size);
  return (
    <div className="raw-records">
      <div className="raw-records-summary">
        <strong>{format(result.total)} communication records</strong>
        <span>
          {minute
            ? `${minute.replace('T', ' ')} · dataset time`
            : 'Case window and adjacent minutes'}
        </span>
      </div>
      {result.records.length > 0 && (
        <div className="raw-records-columns" aria-hidden="true">
          <span>Time</span>
          <span>Source → destination</span>
          <span>Packets</span>
          <span />
        </div>
      )}
      {result.records.slice(0, showAll ? undefined : 8).map((record) => (
        <details className="raw-record" key={`${record.source_file}:${record.source_row}`}>
          <summary>
            <time>{record.timestamp.slice(11)}</time>
            <span>
              {record.source_ip}:{record.source_port} → {record.destination_ip}:
              {record.destination_port}
            </span>
            <strong>{format(record.forward_packets + record.backward_packets)} packets</strong>
            <small>Details</small>
          </summary>
          <div className="raw-record-detail">
            <dl className="raw-record-key-fields">
              <dt>Protocol</dt>
              <dd>{protocolName(record.protocol)}</dd>
              <dt>Packets sent / received</dt>
              <dd>
                {format(record.forward_packets)} / {format(record.backward_packets)}
              </dd>
              <dt>Data transferred</dt>
              <dd>{format(flowBytes(record.fields))} bytes</dd>
              <dt>Dataset label</dt>
              <dd>{record.fields.Label || '—'}</dd>
            </dl>
            <details className="raw-record-technical">
              <summary>All technical fields</summary>
              <dl>
                <dt>Source record</dt>
                <dd>
                  {record.source_file} · row {format(record.source_row)}
                </dd>
                {Object.entries(record.fields).map(([name, value]) => (
                  <React.Fragment key={name}>
                    <dt>{name}</dt>
                    <dd>{value || '—'}</dd>
                  </React.Fragment>
                ))}
              </dl>
            </details>
          </div>
        </details>
      ))}
      <div className="raw-records-footer">
        {!showAll && result.records.length > 8 && (
          <button type="button" className="case-minute-more" onClick={() => setShowAll(true)}>
            Show all {format(result.records.length)} records on this page
          </button>
        )}
        {pages > 1 && (
          <div className="raw-records-pages">
            <button type="button" disabled={page === 1} onClick={() => setPage(page - 1)}>
              Previous
            </button>
            <span>
              Page {page} of {format(pages)}
            </span>
            <button type="button" disabled={page >= pages} onClick={() => setPage(page + 1)}>
              Next
            </button>
          </div>
        )}
      </div>
      {result.total === 0 && (
        <p className="incident-evidence-empty">No communication records in this time range.</p>
      )}
    </div>
  );
}
