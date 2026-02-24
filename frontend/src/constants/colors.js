/**
 * @file Centralised colour constants for the ReconScope UI.
 *
 * Every colour used for severity badges, graph nodes, and graph edges is
 * defined here so that the palette stays consistent across components and
 * is easy to adjust in a single place.
 */

/* ── Severity ──────────────────────────────────────────────── */

/**
 * Solid foreground colours mapped to each severity level.
 * Use these for text, icons, and border highlights.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const SEVERITY_COLORS = Object.freeze({
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#06b6d4',
});

/**
 * Semi-transparent background colours for severity badges.
 * Pair with the matching {@link SEVERITY_COLORS} foreground for contrast.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const SEVERITY_BG = Object.freeze({
  critical: 'rgba(239, 68, 68, 0.15)',
  high: 'rgba(249, 115, 22, 0.15)',
  medium: 'rgba(234, 179, 8, 0.15)',
  low: 'rgba(34, 197, 94, 0.15)',
  info: 'rgba(6, 182, 212, 0.15)',
});

/* ── Graph node colours ────────────────────────────────────── */

/**
 * Colours assigned to each node type rendered in the Cytoscape graph.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const NODE_COLORS = Object.freeze({
  domain: '#3b82f6',
  subdomain: '#06b6d4',
  service: '#8b5cf6',
  technology: '#f59e0b',
  cve: '#ef4444',
});

/* ── Graph edge colours ────────────────────────────────────── */

/**
 * Colours assigned to each edge (relationship) type in the Cytoscape graph.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const EDGE_COLORS = Object.freeze({
  resolves_to: '#64748b',
  runs_on: '#8b5cf6',
  uses_tech: '#f59e0b',
  has_vuln: '#ef4444',
});
