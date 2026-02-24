/**
 * @file Horizontal bar of summary statistics for the current scan.
 *
 * Four cards display subdomains found, services found, CVEs found,
 * and the overall risk level -- each with a colour-coded icon.
 */

import React from 'react';
import PropTypes from 'prop-types';
import { SEVERITY_COLORS } from '../../constants/colors';

/**
 * Derive a risk label and matching colour from a textual risk string.
 *
 * @param {string|null} risk - One of critical, high, medium, low, info.
 * @returns {{ label: string, color: string }}
 */
function riskDisplay(risk) {
  const key = (risk ?? 'info').toLowerCase();
  const label = key.charAt(0).toUpperCase() + key.slice(1);
  const color = SEVERITY_COLORS[key] ?? SEVERITY_COLORS.info;
  return { label, color };
}

/**
 * Individual stat card.
 *
 * @param {{ title: string, value: string|number, iconColor: string }} props
 */
function StatCard({ title, value, iconColor }) {
  return (
    <div
      data-testid={`stat-card-${title.toLowerCase().replace(/\s/g, '-')}`}
      className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-3"
    >
      <span
        className="flex h-9 w-9 items-center justify-center rounded-lg text-lg"
        style={{ color: iconColor, backgroundColor: `${iconColor}15` }}
        aria-hidden="true"
      >
        &#x25CF;
      </span>
      <div className="flex flex-col">
        <span className="text-xs font-medium text-slate-400">{title}</span>
        <span className="text-lg font-bold text-slate-100">{value}</span>
      </div>
    </div>
  );
}

StatCard.propTypes = {
  title: PropTypes.string.isRequired,
  value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
  iconColor: PropTypes.string.isRequired,
};

/**
 * Row of four summary-statistic cards.
 *
 * @param {{
 *   stats: {
 *     subdomains_found?: number,
 *     services_found?: number,
 *     cves_found?: number,
 *     overall_risk?: string,
 *   }
 * }} props
 * @returns {React.ReactElement}
 */
export default function StatsBar({ stats }) {
  const {
    subdomains_found: subdomains = 0,
    services_found: services = 0,
    cves_found: cves = 0,
    overall_risk: overallRisk = 'info',
  } = stats ?? {};

  const risk = riskDisplay(overallRisk);

  return (
    <div
      data-testid="stats-bar"
      className="grid grid-cols-2 gap-3 lg:grid-cols-4"
    >
      <StatCard title="Subdomains" value={subdomains} iconColor="#06b6d4" />
      <StatCard title="Services" value={services} iconColor="#8b5cf6" />
      <StatCard title="CVEs" value={cves} iconColor="#ef4444" />
      <StatCard title="Risk Level" value={risk.label} iconColor={risk.color} />
    </div>
  );
}

StatsBar.propTypes = {
  /** Aggregate scan statistics. */
  stats: PropTypes.shape({
    subdomains_found: PropTypes.number,
    services_found: PropTypes.number,
    cves_found: PropTypes.number,
    overall_risk: PropTypes.string,
  }),
};

StatsBar.defaultProps = {
  stats: {},
};
