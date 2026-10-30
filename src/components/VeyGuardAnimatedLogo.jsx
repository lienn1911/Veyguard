
import React from 'react';

export default function VeyGuardAnimatedLogo() {
  return (
    <svg
      className="vg-animation"
      viewBox="0 0 1240 1240"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="VeyGuard"
    >
      {/* 1. Draw the upper curved ribbon */}
      <g className="vg-sketch">
        <path
          className="vg-line vg-top"
          pathLength="100"
          d="M405 343
             C525 263 630 250 699 260
             C795 273 871 345 900 409"
        />

        {/* 2. Draw the V ribbon */}
        <path
          className="vg-line vg-v"
          pathLength="100"
          d="M344 365
             C429 500 520 634 647 719"
        />

        {/* 3. Draw the G horizontal ribbon */}
        <path
          className="vg-line vg-g"
          pathLength="100"
          d="M611 546
             C636 507 650 473 692 472
             L899 472"
        />

        {/* 4. Draw the lower curved ribbon */}
        <path
          className="vg-line vg-bottom"
          pathLength="100"
          d="M897 475
             C891 615 786 729 624 813
             C605 814 591 807 575 791"
        />
      </g>

      {/* Original VeyGuard logo appears after drawing */}
      <image
        className="vg-original"
        href="/VeyGuard-logo.png"
        x="0"
        y="0"
        width="1240"
        height="1240"
        preserveAspectRatio="xMidYMid meet"
      />
    </svg>
  );
}
