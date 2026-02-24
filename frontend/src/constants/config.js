/**
 * @file Runtime configuration for the ReconScope frontend.
 *
 * All environment-dependent values are read from Vite's
 * `import.meta.env` and fall back to sensible localhost defaults so that
 * the app works out of the box during development.
 */

/* ── Base URLs ─────────────────────────────────────────────── */

/**
 * Root URL of the HTTP API (no trailing slash).
 * Override at build time with the `VITE_API_URL` environment variable.
 *
 * @type {string}
 */
export const API_BASE_URL =
  import.meta.env.VITE_API_URL || 'http://localhost:8000';

/**
 * Root URL for WebSocket connections (no trailing slash).
 * Override at build time with the `VITE_WS_URL` environment variable.
 *
 * @type {string}
 */
export const WS_BASE_URL =
  import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

/**
 * Versioned API prefix used by the Axios client.
 *
 * @type {string}
 */
export const API_V1 = `${API_BASE_URL}/api/v1`;

/* ── WebSocket helpers ─────────────────────────────────────── */

/**
 * Build the full WebSocket URL for a given scan.
 *
 * @param {string} scanId - UUID of the scan to subscribe to.
 * @returns {string} The WebSocket endpoint URL.
 */
export const WS_SCAN_URL = (scanId) =>
  `${WS_BASE_URL}/ws/scans/${scanId}`;

/* ── Scan defaults ─────────────────────────────────────────── */

/**
 * Reconnaissance modules enabled by default when starting a new scan.
 *
 * @type {ReadonlyArray<string>}
 */
export const DEFAULT_MODULES = Object.freeze([
  'crtsh',
  'alienvault',
  'hackertarget',
  'anubis',
  'webarchive',
  'dns',
  'whois',
  'techdetect',
  'cvematch',
]);

/**
 * Active scanning modules that directly probe the target infrastructure.
 * Only available when scan mode is set to "active".
 *
 * @type {ReadonlyArray<string>}
 */
export const ACTIVE_MODULES = Object.freeze([
  'subbuster',
  'portscan',
  'dirbuster',
  'sslaudit',
  'headeraudit',
]);

/* ── WebSocket reconnection ────────────────────────────────── */

/**
 * Milliseconds to wait before attempting to reconnect a dropped
 * WebSocket connection.
 *
 * @type {number}
 */
export const RECONNECT_INTERVAL = 3000;

/**
 * Maximum number of consecutive reconnection attempts before giving up.
 *
 * @type {number}
 */
export const MAX_RECONNECT_ATTEMPTS = 5;
