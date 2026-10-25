// Adapted from pqoqubbw/icons; see LICENSE and SOURCE.md.
import React from "react";

import type { Variants } from "motion/react";
import { motion, useAnimation } from "motion/react";
import type { HTMLAttributes } from "react";
import { forwardRef, useCallback, useImperativeHandle, useRef } from "react";

import { cn } from "./utils";

export interface LogInIconHandle {
  startAnimation: () => void;
  stopAnimation: () => void;
}

interface LogInIconProps extends HTMLAttributes<HTMLSpanElement> {
  size?: number;
}

const PATH_VARIANTS: Variants = {
  animate: {
    x: -2,
    translateX: [0, 3, 0],
    transition: {
      duration: 0.4,
    },
  },
};

const LogInIcon = forwardRef<LogInIconHandle, LogInIconProps>(
  ({ onMouseEnter, onMouseLeave, className, size = 28, ...props }, ref) => {
    const controls = useAnimation();
    const isControlledRef = useRef(false);

    useImperativeHandle(ref, () => {
      isControlledRef.current = true;

      return {
        startAnimation: () => controls.start("animate"),
        stopAnimation: () => controls.start("normal"),
      };
    });

    const handleMouseEnter = useCallback(
      (e: React.MouseEvent<HTMLSpanElement>) => {
        if (isControlledRef.current) {
          onMouseEnter?.(e);
        } else {
          controls.start("animate");
        }
      },
      [controls, onMouseEnter]
    );

    const handleMouseLeave = useCallback(
      (e: React.MouseEvent<HTMLSpanElement>) => {
        if (isControlledRef.current) {
          onMouseLeave?.(e);
        } else {
          controls.start("normal");
        }
      },
      [controls, onMouseLeave]
    );

    return (
      <span
        className={cn(className)}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        {...props}
      >
        <svg
          fill="none"
          height={size}
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          viewBox="0 0 24 24"
          width={size}
          xmlns="http://www.w3.org/2000/svg"
        >
          <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
          <motion.polyline
            animate={controls}
            points="10 17 15 12 10 7"
            variants={PATH_VARIANTS}
          />
          <motion.line
            animate={controls}
            variants={PATH_VARIANTS}
            x1="3"
            x2="15"
            y1="12"
            y2="12"
          />
        </svg>
      </span>
    );
  }
);

LogInIcon.displayName = "LogInIcon";

export { LogInIcon };
