/**
 * @file Card displaying a single correlation insight from the engine.
 *
 * Shows the correlation type, severity, descriptive message, and the
 * list of affected assets.
 */

import React from 'react';
import PropTypes from 'prop-types';
import SeverityBadge from '../common/SeverityBadge';

/** Human-readable labels for correlation type badges. */
const TYPE_LABELS = {
  subnet: 'Subnet',
  forgotten_asset: 'Forgotten Asset',
  exposure: 'Exposure',
  cert: 'Certificate',
  tech_inconsistency: 'Tech Inconsistency',
  version_spread: 'Version Spread',
  cve_clustering: 'CVE Cluster',
  shared_vulnerability: 'Shared Vuln',
  dns_anomaly: 'DNS Anomaly',
  email_security: 'Email Security',
  epss_risk: 'EPSS Risk',
  network_exposure: 'Network Exposure',
  single_point_of_failure: 'Single Point of Failure',
  service_sprawl: 'Service Sprawl',
  admin_exposure: 'Admin Exposure',
  auth_exposure: 'Auth Exposure',
  aging_infrastructure: 'Aging Infra',
  shadow_it: 'Shadow IT',
  low_complexity_exposure: 'Zero-Click',
  dns_config: 'DNS Config',
};

/** Tailwind classes for the correlation type badge. */
const TYPE_STYLES = {
  subnet: 'bg-blue-500/15 text-blue-400',
  forgotten_asset: 'bg-orange-500/15 text-orange-400',
  exposure: 'bg-red-500/15 text-red-400',
  cert: 'bg-yellow-500/15 text-yellow-400',
  tech_inconsistency: 'bg-purple-500/15 text-purple-400',
  version_spread: 'bg-purple-500/15 text-purple-400',
  cve_clustering: 'bg-red-500/15 text-red-400',
  shared_vulnerability: 'bg-red-500/15 text-red-400',
  dns_anomaly: 'bg-cyan-500/15 text-cyan-400',
  email_security: 'bg-amber-500/15 text-amber-400',
  epss_risk: 'bg-rose-500/15 text-rose-400',
  network_exposure: 'bg-red-500/15 text-red-400',
  single_point_of_failure: 'bg-orange-500/15 text-orange-400',
  service_sprawl: 'bg-indigo-500/15 text-indigo-400',
  admin_exposure: 'bg-red-500/15 text-red-400',
  auth_exposure: 'bg-rose-500/15 text-rose-400',
  aging_infrastructure: 'bg-amber-500/15 text-amber-400',
  shadow_it: 'bg-violet-500/15 text-violet-400',
  low_complexity_exposure: 'bg-red-500/15 text-red-400',
  dns_config: 'bg-cyan-500/15 text-cyan-400',
};

/**
 * Card for a single correlation insight.
 *
 * @param {{ correlation: object }} props
 * @returns {React.ReactElement}
 */
export default function CorrelationCard({ correlation }) {
  const {
    correlation_type: type,
    severity,
    message,
    affected_assets: assets = [],
  } = correlation;

  const typeLabel = TYPE_LABELS[type] ?? type ?? 'Unknown';
  const typeStyle = TYPE_STYLES[type] ?? 'bg-slate-700/30 text-slate-400';

  return (
    <article
      className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 transition-colors hover:border-slate-700"
      aria-label={`Correlation: ${typeLabel}`}
    >
      {/* Header row */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span
          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${typeStyle}`}
        >
          {typeLabel}
        </span>
        <SeverityBadge severity={severity ?? 'info'} />
      </div>

      {/* Message */}
      {message && (
        <p className="mb-4 text-sm leading-relaxed text-slate-300">
          {message}
        </p>
      )}

      {/* Affected assets */}
      {assets.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-medium uppercase text-slate-500">
            Affected Assets ({assets.length})
          </h4>
          <ul className="flex flex-wrap gap-2" aria-label="Affected assets">
            {assets.map((asset) => (
              <li
                key={asset}
                className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1 font-mono text-xs text-slate-300"
              >
                {asset}
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

CorrelationCard.propTypes = {
  /** Correlation insight object from the API. */
  correlation: PropTypes.shape({
    id: PropTypes.string.isRequired,
    correlation_type: PropTypes.string,
    severity: PropTypes.string,
    message: PropTypes.string,
    affected_assets: PropTypes.arrayOf(PropTypes.string),
  }).isRequired,
};
