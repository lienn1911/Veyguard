import React from 'react';

const points = (text) => String(text || '')
  .replace(/\((?:ALT-|FLOW-)[^)]*\)/g, '')
  .replace(/\b(?:ALT|FLOW)-[A-Z0-9]+\b/g, '')
  .replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/)
  .map((point) => point.replace(/^(Observed|Inference):\s*/i, '').trim())
  .filter(Boolean).map((point) => point.replace(/[a-z]/i, (letter) => letter.toUpperCase())).slice(0, 3);
const keywords = /(PortScan|BruteForce|DoS|network service discovery|authorization and intent remain unknown|not establish[^.;]*|requires? explicit analyst confirmation|failed logins|successful compromise|repeated broad destination-port probing)/gi;
export default function AssessmentSummary({ text }) {
  return <ul className="ai-summary-points">{points(text).map((point, index) => <li key={index}>{point.split(keywords).map((part, i) => i % 2 ? <strong key={i}>{part}</strong> : part)}</li>)}</ul>;
}
