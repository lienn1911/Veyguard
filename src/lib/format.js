export const VERDICTS = ['Likely Attack', 'Likely Benign', 'Needs Review'];

const VERDICT_CLASS = {
  'Likely Attack': 'attack',
  'Likely Benign': 'benign',
  'Needs Review': 'review',
};

export function verdictClass(verdict) {
  return VERDICT_CLASS[verdict] || 'unknown';
}

export function categoryClass(category) {
  return String(category || '').toLowerCase();
}

export function formatNumber(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  return Number(value).toLocaleString('en-US');
}

export function formatConfidence(value) {
  if (value === null || value === undefined || value === '') return '';
  const label = typeof value === 'number' ? `${Math.round(value * 100)}%` : String(value);
  return `${label.charAt(0).toUpperCase()}${label.slice(1)} Confidence`;
}

export function formatTimestamp(value) {
  if (!value) return '—';
  return String(value).replace('T', ' ').slice(0, 16);
}

export function formatTime(value) {
  if (!value) return '—';
  return String(value).slice(11, 19) || String(value);
}

export function formatDuration(ms) {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function shortId(value, keep = 4) {
  if (!value) return '—';
  const text = String(value);
  const parts = text.split('-');
  if (parts.length === 1) {
    return text.length > keep * 2 ? `…${text.slice(-keep)}` : text;
  }
  return `${parts[0]}-…${parts[parts.length - 1].slice(-keep)}`;
}

export function titleForMode(mode) {
  if (mode === 'live') return 'Live model';
  if (mode === 'mock') return 'Mock model';
  return 'Offline';
}
