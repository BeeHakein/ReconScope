/**
 * @file Tests for the SeverityBadge component.
 *
 * Confirms that each severity level renders the correct colour and
 * uppercased label text, and that unknown levels fall back gracefully.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import SeverityBadge from '../../components/common/SeverityBadge';
import { SEVERITY_COLORS, SEVERITY_BG } from '../../constants/colors';

/**
 * Convert a hex colour string to the rgb() format that jsdom returns
 * when reading computed inline styles.
 *
 * @param {string} hex - e.g. '#ef4444'
 * @returns {string} - e.g. 'rgb(239, 68, 68)'
 */
function hexToRgb(hex) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgb(${r}, ${g}, ${b})`;
}

/**
 * Convert an rgba() string like "rgba(239, 68, 68, 0.15)" to the
 * normalised format jsdom returns (which preserves rgba).
 *
 * @param {string} rgba
 * @returns {string}
 */
function normaliseRgba(rgba) {
  return rgba.replace(/\s+/g, ' ').trim();
}

/* ── Test suite ────────────────────────────────────────────── */

describe('SeverityBadge', () => {
  it('renders a CRITICAL badge with the correct red colour', () => {
    render(<SeverityBadge severity="critical" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveTextContent('CRITICAL');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.critical));
    expect(badge.style.backgroundColor).toBe(normaliseRgba(SEVERITY_BG.critical));
  });

  it('renders a HIGH badge with the correct orange colour', () => {
    render(<SeverityBadge severity="high" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('HIGH');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.high));
    expect(badge.style.backgroundColor).toBe(normaliseRgba(SEVERITY_BG.high));
  });

  it('renders a MEDIUM badge with the correct yellow colour', () => {
    render(<SeverityBadge severity="medium" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('MEDIUM');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.medium));
    expect(badge.style.backgroundColor).toBe(normaliseRgba(SEVERITY_BG.medium));
  });

  it('renders a LOW badge with the correct green colour', () => {
    render(<SeverityBadge severity="low" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('LOW');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.low));
    expect(badge.style.backgroundColor).toBe(normaliseRgba(SEVERITY_BG.low));
  });

  it('renders an INFO badge with the correct cyan colour', () => {
    render(<SeverityBadge severity="info" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('INFO');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.info));
    expect(badge.style.backgroundColor).toBe(normaliseRgba(SEVERITY_BG.info));
  });

  it('falls back to info styling for an unknown severity level', () => {
    render(<SeverityBadge severity="unknown" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('UNKNOWN');
    // Fallback colour is SEVERITY_COLORS.info per the component logic
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.info));
    expect(badge.style.backgroundColor).toBe(normaliseRgba(SEVERITY_BG.info));
  });

  it('handles mixed-case severity input by lowercasing', () => {
    render(<SeverityBadge severity="Critical" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('CRITICAL');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.critical));
  });

  it('handles fully uppercase severity input', () => {
    render(<SeverityBadge severity="HIGH" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveTextContent('HIGH');
    expect(badge.style.color).toBe(hexToRgb(SEVERITY_COLORS.high));
  });

  it('has the correct aria-label for accessibility', () => {
    render(<SeverityBadge severity="medium" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge).toHaveAttribute('aria-label', 'Severity: medium');
  });

  it('renders as an inline span element', () => {
    render(<SeverityBadge severity="low" />);

    const badge = screen.getByTestId('severity-badge');
    expect(badge.tagName).toBe('SPAN');
  });
});
