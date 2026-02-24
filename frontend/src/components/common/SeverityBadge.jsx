/**
 * @file Coloured badge that displays a severity level.
 *
 * The component maps the incoming severity string to the matching colour
 * from the central palette and renders a pill-shaped label using Tailwind.
 */

import React from 'react';
import PropTypes from 'prop-types';
import { SEVERITY_COLORS, SEVERITY_BG } from '../../constants/colors';

/**
 * Small pill-shaped badge displaying CRITICAL, HIGH, MEDIUM, LOW, or INFO.
 *
 * @param {{ severity: string }} props
 * @returns {React.ReactElement}
 */
export default function SeverityBadge({ severity }) {
  const level = (severity ?? 'info').toLowerCase();
  const color = SEVERITY_COLORS[level] ?? SEVERITY_COLORS.info;
  const bg = SEVERITY_BG[level] ?? SEVERITY_BG.info;

  return (
    <span
      data-testid="severity-badge"
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide"
      style={{ color, backgroundColor: bg }}
      aria-label={`Severity: ${level}`}
    >
      {level.toUpperCase()}
    </span>
  );
}

SeverityBadge.propTypes = {
  /** One of: critical, high, medium, low, info. */
  severity: PropTypes.string.isRequired,
};
