/**
 * @file High-level hook encapsulating all scan CRUD operations.
 *
 * Combines the API client with the global ScanContext so components can
 * trigger scans, load results, or delete history with a single call.
 */

import { useCallback } from 'react';
import {
  createScan as apiCreateScan,
  getScans as apiGetScans,
  getScanGraph,
  getScanFindings,
  getScanAttackPaths,
  getScanCorrelations,
  getScan as apiGetScan,
  deleteScan as apiDeleteScan,
} from '../api/client';
import {
  useScanContext,
  SET_CURRENT_SCAN,
  SET_SCAN_RESULTS,
  SET_SCANS,
  SET_LOADING,
  SET_ERROR,
  RESET_SCAN,
} from '../context/ScanContext';

/**
 * Provides imperative helpers for scan lifecycle management.
 *
 * @returns {{
 *   startScan: (target: string, modules: string[], scopeConfirmed: boolean, scanMode?: string) => Promise<string>,
 *   loadScans: () => Promise<void>,
 *   loadScanResults: (scanId: string) => Promise<void>,
 *   deleteScan: (scanId: string) => Promise<void>,
 *   resetScan: () => void,
 *   loading: boolean,
 *   error: string|null,
 * }}
 */
export default function useScan() {
  const { state, dispatch } = useScanContext();

  /**
   * Start a new scan and persist the response as `currentScan`.
   *
   * @param {string}   target         - The domain to scan.
   * @param {string[]} modules        - Module identifiers.
   * @param {boolean}  scopeConfirmed - Scope-confirmation flag.
   * @param {string}   [scanMode='passive'] - Scan mode: 'passive' or 'active'.
   * @returns {Promise<string>} The UUID of the created scan.
   */
  const startScan = useCallback(
    async (target, modules, scopeConfirmed, scanMode = 'passive') => {
      dispatch({ type: SET_LOADING, payload: true });
      dispatch({ type: SET_ERROR, payload: null });

      try {
        const { data } = await apiCreateScan(target, modules, scopeConfirmed, scanMode);
        dispatch({
          type: SET_CURRENT_SCAN,
          payload: {
            ...data,
            progress: {
              current_module: null,
              modules_completed: [],
              modules_pending: data.modules ?? [],
              percentage: 0,
            },
          },
        });
        return data.scan_id;
      } catch (err) {
        const message =
          err.apiError?.message ?? 'Failed to start scan. Please try again.';
        dispatch({ type: SET_ERROR, payload: message });
        throw err;
      } finally {
        dispatch({ type: SET_LOADING, payload: false });
      }
    },
    [dispatch],
  );

  /**
   * Fetch the list of all scans and store them in context.
   */
  const loadScans = useCallback(async () => {
    dispatch({ type: SET_LOADING, payload: true });

    try {
      const { data } = await apiGetScans();
      dispatch({ type: SET_SCANS, payload: data });
    } catch (err) {
      dispatch({
        type: SET_ERROR,
        payload: err.apiError?.message ?? 'Failed to load scans.',
      });
    } finally {
      dispatch({ type: SET_LOADING, payload: false });
    }
  }, [dispatch]);

  /**
   * Load the full results for a scan (graph, findings, attack paths,
   * correlations) in parallel and merge them into `scanResults`.
   *
   * @param {string} scanId
   */
  const loadScanResults = useCallback(
    async (scanId) => {
      dispatch({ type: SET_LOADING, payload: true });

      try {
        const [scanRes, graphRes, findingsRes, pathsRes, correlationsRes] =
          await Promise.all([
            apiGetScan(scanId),
            getScanGraph(scanId),
            getScanFindings(scanId),
            getScanAttackPaths(scanId),
            getScanCorrelations(scanId),
          ]);

        dispatch({
          type: SET_SCAN_RESULTS,
          payload: {
            scan: scanRes.data,
            graph: graphRes.data,
            findings: findingsRes.data,
            attackPaths: pathsRes.data,
            correlations: correlationsRes.data,
          },
        });

        dispatch({ type: SET_CURRENT_SCAN, payload: scanRes.data });
      } catch (err) {
        dispatch({
          type: SET_ERROR,
          payload: err.apiError?.message ?? 'Failed to load scan results.',
        });
      } finally {
        dispatch({ type: SET_LOADING, payload: false });
      }
    },
    [dispatch],
  );

  /**
   * Delete a scan and remove it from the local list.
   *
   * @param {string} scanId
   */
  const deleteScanById = useCallback(
    async (scanId) => {
      dispatch({ type: SET_LOADING, payload: true });

      try {
        await apiDeleteScan(scanId);
        dispatch({
          type: SET_SCANS,
          payload: state.scans.filter((s) => s.scan_id !== scanId),
        });
      } catch (err) {
        dispatch({
          type: SET_ERROR,
          payload: err.apiError?.message ?? 'Failed to delete scan.',
        });
      } finally {
        dispatch({ type: SET_LOADING, payload: false });
      }
    },
    [dispatch, state.scans],
  );

  /**
   * Reset the scan state back to the initial empty state.
   */
  const resetScan = useCallback(() => {
    dispatch({ type: RESET_SCAN });
  }, [dispatch]);

  return {
    startScan,
    loadScans,
    loadScanResults,
    deleteScan: deleteScanById,
    resetScan,
    loading: state.loading,
    error: state.error,
  };
}
