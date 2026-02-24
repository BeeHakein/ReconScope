/**
 * @file Tests for the StatsBar component.
 *
 * Ensures the four stat cards (Subdomains, Services, CVEs, Risk Level)
 * render correctly with given data, zeros, and colour-coded risk levels.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import StatsBar from '../../components/scan/StatsBar';
import { SEVERITY_COLORS } from '../../constants/colors';

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

/* ── Helpers ───────────────────────────────────────────────── */

/**
 * Render StatsBar with a stats object.
 *
 * @param {object} stats
 */
function renderStatsBar(stats) {
  return render(<StatsBar stats={stats} />);
}

/* ── Test suite ────────────────────────────────────────────── */

describe('StatsBar', () => {
  it('renders all four stat cards with the supplied values', () => {
    renderStatsBar({
      subdomains_found: 42,
      services_found: 15,
      cves_found: 7,
      overall_risk: 'high',
    });

    expect(screen.getByTestId('stats-bar')).toBeInTheDocument();
    expect(screen.getByText('Subdomains')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('Services')).toBeInTheDocument();
    expect(screen.getByText('15')).toBeInTheDocument();
    expect(screen.getByText('CVEs')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
    expect(screen.getByText('Risk Level')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('renders zeros correctly when all stats are zero', () => {
    renderStatsBar({
      subdomains_found: 0,
      services_found: 0,
      cves_found: 0,
      overall_risk: 'info',
    });

    const zeros = screen.getAllByText('0');
    expect(zeros).toHaveLength(3);
    expect(screen.getByText('Info')).toBeInTheDocument();
  });

  it('defaults to zeros and "Info" when no stats are provided', () => {
    renderStatsBar(undefined);

    const zeros = screen.getAllByText('0');
    expect(zeros).toHaveLength(3);
    expect(screen.getByText('Info')).toBeInTheDocument();
  });

  it('displays "Critical" label with the critical colour for risk >= 80 equivalent', () => {
    renderStatsBar({ overall_risk: 'critical' });

    const riskCard = screen.getByTestId('stat-card-risk-level');
    expect(riskCard).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeInTheDocument();

    // The icon span inside the risk card should use the critical colour
    const iconSpan = riskCard.querySelector('span[aria-hidden="true"]');
    expect(iconSpan.style.color).toBe(hexToRgb(SEVERITY_COLORS.critical));
  });

  it('displays "High" label with the high colour', () => {
    renderStatsBar({ overall_risk: 'high' });

    expect(screen.getByText('High')).toBeInTheDocument();

    const riskCard = screen.getByTestId('stat-card-risk-level');
    const iconSpan = riskCard.querySelector('span[aria-hidden="true"]');
    expect(iconSpan.style.color).toBe(hexToRgb(SEVERITY_COLORS.high));
  });

  it('displays "Medium" label with the medium colour', () => {
    renderStatsBar({ overall_risk: 'medium' });

    expect(screen.getByText('Medium')).toBeInTheDocument();

    const riskCard = screen.getByTestId('stat-card-risk-level');
    const iconSpan = riskCard.querySelector('span[aria-hidden="true"]');
    expect(iconSpan.style.color).toBe(hexToRgb(SEVERITY_COLORS.medium));
  });

  it('displays "Low" label with the low colour', () => {
    renderStatsBar({ overall_risk: 'low' });

    expect(screen.getByText('Low')).toBeInTheDocument();

    const riskCard = screen.getByTestId('stat-card-risk-level');
    const iconSpan = riskCard.querySelector('span[aria-hidden="true"]');
    expect(iconSpan.style.color).toBe(hexToRgb(SEVERITY_COLORS.low));
  });

  it('displays "Info" label with the info colour', () => {
    renderStatsBar({ overall_risk: 'info' });

    expect(screen.getByText('Info')).toBeInTheDocument();

    const riskCard = screen.getByTestId('stat-card-risk-level');
    const iconSpan = riskCard.querySelector('span[aria-hidden="true"]');
    expect(iconSpan.style.color).toBe(hexToRgb(SEVERITY_COLORS.info));
  });

  it('handles mixed-case risk level strings', () => {
    renderStatsBar({ overall_risk: 'HIGH' });

    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('renders each stat card with the correct test ID', () => {
    renderStatsBar({
      subdomains_found: 1,
      services_found: 2,
      cves_found: 3,
      overall_risk: 'low',
    });

    expect(screen.getByTestId('stat-card-subdomains')).toBeInTheDocument();
    expect(screen.getByTestId('stat-card-services')).toBeInTheDocument();
    expect(screen.getByTestId('stat-card-cves')).toBeInTheDocument();
    expect(screen.getByTestId('stat-card-risk-level')).toBeInTheDocument();
  });
});
