/**
 * @file Axios HTTP client and API helper functions for ReconScope.
 *
 * Every endpoint exposed by the FastAPI backend has a corresponding
 * function here.  The shared Axios instance applies a base URL, a
 * default timeout, and a response interceptor that normalises errors
 * into a predictable shape.
 */

import axios from 'axios';
import { API_V1 } from '../constants/config';

/* ── Axios instance ────────────────────────────────────────── */

/**
 * Pre-configured Axios instance pointing at the versioned API.
 *
 * @type {import('axios').AxiosInstance}
 */
const client = axios.create({
  baseURL: API_V1,
  timeout: 30_000,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
});

/* ── Response interceptor ──────────────────────────────────── */

client.interceptors.response.use(
  (response) => response,
  (error) => {
    /** @type {{ status: number|null, message: string, data: unknown }} */
    const normalised = {
      status: error.response?.status ?? null,
      message:
        error.response?.data?.detail ??
        error.response?.data?.message ??
        error.message ??
        'An unexpected error occurred',
      data: error.response?.data ?? null,
    };

    // Attach the normalised payload so callers can inspect it directly.
    error.apiError = normalised;

    return Promise.reject(error);
  },
);

/* ── Scans ─────────────────────────────────────────────────── */

/**
 * Start a new reconnaissance scan.
 *
 * @param {string}   target         - The target domain to scan.
 * @param {string[]} modules        - List of module identifiers to run.
 * @param {boolean}  scopeConfirmed - Whether the user confirmed they own / are
 *                                    authorised to scan the target.
 * @param {string}   [scanMode='passive'] - Scan mode: 'passive' or 'active'.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function createScan(target, modules, scopeConfirmed, scanMode = 'passive') {
  return client.post('/scans', {
    target,
    modules,
    scope_confirmed: scopeConfirmed,
    scan_mode: scanMode,
  });
}

/**
 * Retrieve a paginated list of scans.
 *
 * @param {number} [skip=0]   - Number of records to skip.
 * @param {number} [limit=20] - Maximum number of records to return.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScans(skip = 0, limit = 20) {
  return client.get('/scans', { params: { skip, limit } });
}

/**
 * Retrieve the details of a single scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScan(scanId) {
  return client.get(`/scans/${scanId}`);
}

/**
 * Delete a scan and all of its associated data.
 *
 * @param {string} scanId - UUID of the scan to delete.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function deleteScan(scanId) {
  return client.delete(`/scans/${scanId}`);
}

/* ── Scan results ──────────────────────────────────────────── */

/**
 * Fetch aggregated results for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanResults(scanId) {
  return client.get(`/scans/${scanId}/results`);
}

/**
 * Fetch discovered subdomains for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanSubdomains(scanId) {
  return client.get(`/scans/${scanId}/subdomains`);
}

/**
 * Fetch discovered services (open ports / protocols) for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanServices(scanId) {
  return client.get(`/scans/${scanId}/services`);
}

/**
 * Fetch detected technologies for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanTechnologies(scanId) {
  return client.get(`/scans/${scanId}/technologies`);
}

/**
 * Fetch matched CVEs for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanCves(scanId) {
  return client.get(`/scans/${scanId}/cves`);
}

/**
 * Fetch consolidated findings (all severity levels) for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanFindings(scanId) {
  return client.get(`/scans/${scanId}/findings`);
}

/* ── Analysis / correlation ────────────────────────────────── */

/**
 * Fetch computed attack paths for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanAttackPaths(scanId) {
  return client.get(`/scans/${scanId}/attack-paths`);
}

/**
 * Fetch cross-module correlations for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanCorrelations(scanId) {
  return client.get(`/scans/${scanId}/correlations`);
}

/* ── Graph ─────────────────────────────────────────────────── */

/**
 * Fetch the Cytoscape-compatible graph payload for a scan.
 *
 * @param {string} scanId - UUID of the scan.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanGraph(scanId) {
  return client.get(`/scans/${scanId}/graph`);
}

/* ── Delta / comparison ────────────────────────────────────── */

/**
 * Compare two scans and return the delta (added / removed / changed).
 *
 * @param {string} scanId        - UUID of the current scan.
 * @param {string} compareScanId - UUID of the scan to compare against.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getScanDelta(scanId, compareScanId) {
  return client.get(`/scans/${scanId}/delta`, {
    params: { compare_scan_id: compareScanId },
  });
}

/* ── Targets ───────────────────────────────────────────────── */

/**
 * Retrieve the list of all previously scanned targets.
 *
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getTargets() {
  return client.get('/targets');
}

/**
 * Retrieve the scan history for a specific domain.
 *
 * @param {string} domain - The domain whose history to fetch.
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getTargetHistory(domain) {
  return client.get(`/targets/${encodeURIComponent(domain)}/history`);
}

/* ── Export ────────────────────────────────────────────────── */

/**
 * Download scan results as JSON.
 *
 * @param {string} scanId - UUID of the scan.
 */
export function exportScanJSON(scanId) {
  return client.get(`/scans/${scanId}/export/json`, { responseType: 'blob' });
}

/**
 * Download scan results as CSV.
 *
 * @param {string} scanId - UUID of the scan.
 */
export function exportScanCSV(scanId) {
  return client.get(`/scans/${scanId}/export/csv`, { responseType: 'blob' });
}

/**
 * Download scan results as PDF.
 *
 * @param {string} scanId - UUID of the scan.
 */
export function exportScanPDF(scanId) {
  return client.get(`/scans/${scanId}/export/pdf`, { responseType: 'blob' });
}

/* ── Schedules ────────────────────────────────────────────── */

/**
 * List all scan schedules.
 *
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function getSchedules() {
  return client.get('/schedules');
}

/**
 * Create a new scan schedule.
 *
 * @param {{ target: string, modules: string[], cron_expression: string }} data
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function createSchedule(data) {
  return client.post('/schedules', data);
}

/**
 * Update a scan schedule.
 *
 * @param {string} scheduleId
 * @param {{ is_active?: boolean, cron_expression?: string }} data
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function updateSchedule(scheduleId, data) {
  return client.patch(`/schedules/${scheduleId}`, data);
}

/**
 * Delete a scan schedule.
 *
 * @param {string} scheduleId
 * @returns {Promise<import('axios').AxiosResponse>}
 */
export function deleteSchedule(scheduleId) {
  return client.delete(`/schedules/${scheduleId}`);
}

export default client;
