/**
 * @file Animated loading spinner with an optional message.
 *
 * Uses Tailwind animation utilities and the project's cyan accent colour
 * to stay consistent with the dark cybersecurity theme.
 */

import React from 'react';
import PropTypes from 'prop-types';

/** Map of size presets to Tailwind dimension classes. */
const SIZE_MAP = {
  sm: 'h-4 w-4 border-2',
  md: 'h-8 w-8 border-2',
  lg: 'h-12 w-12 border-4',
};

/**
 * Circular spinner that optionally displays a descriptive message.
 *
 * @param {{ message?: string, size?: 'sm'|'md'|'lg' }} props
 * @returns {React.ReactElement}
 */
export default function LoadingSpinner({ message, size = 'md' }) {
  const sizeClasses = SIZE_MAP[size] ?? SIZE_MAP.md;

  return (
    <div
      className="flex flex-col items-center justify-center gap-3"
      role="status"
      aria-label={message ?? 'Loading'}
    >
      <span
        className={`inline-block rounded-full border-cyan-400 border-t-transparent animate-spin ${sizeClasses}`}
      />
      {message && (
        <p className="text-sm text-slate-400">{message}</p>
      )}
    </div>
  );
}

LoadingSpinner.propTypes = {
  /** Descriptive text rendered below the spinner. */
  message: PropTypes.string,
  /** Visual size of the spinner. */
  size: PropTypes.oneOf(['sm', 'md', 'lg']),
};

LoadingSpinner.defaultProps = {
  message: undefined,
  size: 'md',
};
