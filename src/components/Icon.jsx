import React from 'react';

const PATHS = {
  overview: (
    <>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.6" />
      <rect x="13.5" y="3" width="7.5" height="4.5" rx="1.4" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.6" />
      <rect x="13.5" y="10.5" width="7.5" height="10.5" rx="1.6" />
    </>
  ),
  incidents: (
    <>
      <path d="M8 6h13M8 12h13M8 18h13" />
      <circle cx="3.6" cy="6" r="1.1" />
      <circle cx="3.6" cy="12" r="1.1" />
      <circle cx="3.6" cy="18" r="1.1" />
    </>
  ),
  audit: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
      <path d="M14 3v5h5" />
      <path d="M9 13h6M9 17h4" />
    </>
  ),
  shield: (
    <>
      <path d="M12 21.5s7.5-3.6 7.5-9.5V5.5L12 2.5 4.5 5.5V12c0 5.9 7.5 9.5 7.5 9.5Z" />
      <path d="m9 11.8 2.2 2.2 4-4.4" />
    </>
  ),
  arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m20 20-3.6-3.6" />
    </>
  ),
  filter: <path d="M4 6.5h16M7 12h10M10 17.5h4" />,
  sort: <path d="M7 7.5h10M7 12h7M7 16.5h4" />,
  alert: (
    <>
      <path d="M12 3.2 2.6 20h18.8L12 3.2Z" />
      <path d="M12 9.5v4.5" />
      <path d="M12 17.2h.01" />
    </>
  ),
  check: <path d="m4.5 12.5 4.6 4.5L19.5 6.5" />,
  checkCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m8.3 12.2 2.6 2.5 4.8-5.2" />
    </>
  ),
  close: <path d="M6.5 6.5l11 11m0-11-11 11" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5.2l3.3 2" />
    </>
  ),
  cpu: (
    <>
      <rect x="6.5" y="6.5" width="11" height="11" rx="2" />
      <path d="M9.5 2.5v3M14.5 2.5v3M9.5 18.5v3M14.5 18.5v3M2.5 9.5h3M2.5 14.5h3M18.5 9.5h3M18.5 14.5h3" />
    </>
  ),
  spark: (
    <>
      <path d="M11.5 3.5 13.2 8l4.6 1.7-4.6 1.7-1.7 4.6-1.7-4.6L5.2 9.7 9.8 8Z" />
      <path d="M18.4 15.2l.8 1.9 1.9.8-1.9.8-.8 1.9-.8-1.9-1.9-.8 1.9-.8Z" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m7 9.5 3 2.9-3 2.9" />
      <path d="M13 15.3h4" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="10" width="15" height="10.5" rx="2" />
      <path d="M8.2 10V7.3a3.8 3.8 0 0 1 7.6 0V10" />
    </>
  ),
  hash: (
    <>
      <path d="M9.5 3.5 8 20.5M16 3.5l-1.5 17M3.8 8.8h16.4M3 15.2h16.4" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.4" />
    </>
  ),
  chevron: <path d="m9.5 5.5 6.5 6.5-6.5 6.5" />,
  chevronDown: <path d="m5.5 9 6.5 6.5L18.5 9" />,
  refresh: (
    <>
      <path d="M20 11.5A8 8 0 1 0 17.6 17" />
      <path d="M20.2 4.8v6.4h-6.4" />
    </>
  ),
  user: (
    <>
      <circle cx="12" cy="8" r="3.8" />
      <path d="M4.5 21c0-4 3.5-6 7.5-6s7.5 2 7.5 6" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5.8" rx="7.8" ry="2.9" />
      <path d="M4.2 5.8v12.4c0 1.6 3.5 2.9 7.8 2.9s7.8-1.3 7.8-2.9V5.8" />
      <path d="M4.2 12c0 1.6 3.5 2.9 7.8 2.9s7.8-1.3 7.8-2.9" />
    </>
  ),
  activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
  play: <path d="m8 5.5 11 6.5-11 6.5Z" />,
  dot: <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" />,
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5" />
      <path d="M12 7.6h.01" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  minus: <path d="M5 12h14" />,
};

export default function Icon({ name, size = 18, className }) {
  const content = PATHS[name] || PATHS.dot;
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {content}
    </svg>
  );
}
