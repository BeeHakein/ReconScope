/**
 * @file Tests for the useScan hook.
 *
 * Mocks the API client functions and wraps the hook in ScanProvider
 * to verify that scan operations correctly update context state.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import React from 'react';

/* ── Mock the API client ───────────────────────────────────── */

vi.mock('../../api/client', () => ({
  createScan: vi.fn(),
  getScans: vi.fn(),
  getScan: vi.fn(),
  getScanGraph: vi.fn(),
  getScanFindings: vi.fn(),
  getScanAttackPaths: vi.fn(),
  getScanCorrelations: vi.fn(),
  deleteScan: vi.fn(),
  default: {},
}));

import {
  createScan as mockCreateScan,
  getScans as mockGetScans,
  getScan as mockGetScan,
  getScanGraph as mockGetScanGraph,
  getScanFindings as mockGetScanFindings,
  getScanAttackPaths as mockGetScanAttackPaths,
  getScanCorrelations as mockGetScanCorrelations,
  deleteScan as mockDeleteScan,
} from '../../api/client';

import { ScanProvider, useScanContext } from '../../context/ScanContext';
import useScan from '../../hooks/useScan';

/* ── Helpers ───────────────────────────────────────────────── */

function Wrapper({ children }) {
  return <ScanProvider>{children}</ScanProvider>;
}

/* ── Test suite ────────────────────────────────────────────── */

describe('useScan', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  /* ── startScan ─────────────────────────────────────────── */

  it('calls createScan API with the correct parameters', async () => {
    const scanResponse = {
      data: { scan_id: 'uuid-1', target: 'example.com', status: 'queued' },
    };
    mockCreateScan.mockResolvedValueOnce(scanResponse);

    const { result } = renderHook(() => useScan(), { wrapper: Wrapper });

    await act(async () => {
      await result.current.startScan('example.com', ['dns', 'crtsh'], true);
    });

    expect(mockCreateScan).toHaveBeenCalledTimes(1);
    expect(mockCreateScan).toHaveBeenCalledWith('example.com', ['dns', 'crtsh'], true);
  });

  it('returns the scan ID after a successful startScan call', async () => {
    mockCreateScan.mockResolvedValueOnce({
      data: { scan_id: 'uuid-123', target: 'example.com', status: 'queued' },
    });

    const { result } = renderHook(() => useScan(), { wrapper: Wrapper });

    let scanId;
    await act(async () => {
      scanId = await result.current.startScan('example.com', ['dns'], true);
    });

    expect(scanId).toBe('uuid-123');
  });

  it('sets loading to false after startScan completes', async () => {
    mockCreateScan.mockResolvedValueOnce({
      data: { scan_id: 'uuid-1', status: 'queued' },
    });

    const { result } = renderHook(() => useScan(), { wrapper: Wrapper });

    expect(result.current.loading).toBe(false);

    await act(async () => {
      await result.current.startScan('example.com', ['dns'], true);
    });

    // After the async call resolves, loading should be back to false
    expect(result.current.loading).toBe(false);
  });

  it('sets error state when startScan API fails', async () => {
    const apiError = new Error('Network error');
    apiError.apiError = { message: 'Server is unreachable' };
    mockCreateScan.mockRejectedValueOnce(apiError);

    const { result } = renderHook(() => useScan(), { wrapper: Wrapper });

    await act(async () => {
      try {
        await result.current.startScan('example.com', ['dns'], true);
      } catch (e) {
        // Expected to throw
      }
    });

    expect(result.current.error).toBe('Server is unreachable');
    expect(result.current.loading).toBe(false);
  });

  it('uses a default error message when apiError is missing', async () => {
    mockCreateScan.mockRejectedValueOnce(new Error('timeout'));

    const { result } = renderHook(() => useScan(), { wrapper: Wrapper });

    await act(async () => {
      try {
        await result.current.startScan('example.com', ['dns'], true);
      } catch (e) {
        // Expected
      }
    });

    expect(result.current.error).toBe('Failed to start scan. Please try again.');
  });

  /* ── loadScans ─────────────────────────────────────────── */

  it('calls getScans API and updates scans list in state', async () => {
    const scansList = [
      { scan_id: 'a', target: 'one.com', status: 'completed' },
      { scan_id: 'b', target: 'two.com', status: 'running' },
    ];
    mockGetScans.mockResolvedValueOnce({ data: scansList });

    const { result } = renderHook(
      () => {
        const scan = useScan();
        const ctx = useScanContext();
        return { ...scan, state: ctx.state };
      },
      { wrapper: Wrapper },
    );

    await act(async () => {
      await result.current.loadScans();
    });

    expect(mockGetScans).toHaveBeenCalledTimes(1);
    expect(result.current.state.scans).toEqual(scansList);
    expect(result.current.loading).toBe(false);
  });

  it('sets error state when loadScans API fails', async () => {
    const err = new Error('fail');
    err.apiError = { message: 'Cannot load scans' };
    mockGetScans.mockRejectedValueOnce(err);

    const { result } = renderHook(() => useScan(), { wrapper: Wrapper });

    await act(async () => {
      await result.current.loadScans();
    });

    expect(result.current.error).toBe('Cannot load scans');
  });

  /* ── loadScanResults ───────────────────────────────────── */

  it('fetches all result types in parallel for loadScanResults', async () => {
    mockGetScan.mockResolvedValueOnce({ data: { scan_id: 'x', status: 'completed' } });
    mockGetScanGraph.mockResolvedValueOnce({ data: { nodes: [], edges: [] } });
    mockGetScanFindings.mockResolvedValueOnce({ data: [] });
    mockGetScanAttackPaths.mockResolvedValueOnce({ data: [] });
    mockGetScanCorrelations.mockResolvedValueOnce({ data: [] });

    const { result } = renderHook(
      () => {
        const scan = useScan();
        const ctx = useScanContext();
        return { ...scan, state: ctx.state };
      },
      { wrapper: Wrapper },
    );

    await act(async () => {
      await result.current.loadScanResults('x');
    });

    expect(mockGetScan).toHaveBeenCalledWith('x');
    expect(mockGetScanGraph).toHaveBeenCalledWith('x');
    expect(mockGetScanFindings).toHaveBeenCalledWith('x');
    expect(mockGetScanAttackPaths).toHaveBeenCalledWith('x');
    expect(mockGetScanCorrelations).toHaveBeenCalledWith('x');

    expect(result.current.state.scanResults).toEqual({
      scan: { scan_id: 'x', status: 'completed' },
      graph: { nodes: [], edges: [] },
      findings: [],
      attackPaths: [],
      correlations: [],
    });
  });

  /* ── resetScan ─────────────────────────────────────────── */

  it('resets the scan state while preserving the scans list', async () => {
    // First load some scans
    const scansList = [{ scan_id: 'a', target: 'one.com' }];
    mockGetScans.mockResolvedValueOnce({ data: scansList });

    const { result } = renderHook(
      () => {
        const scan = useScan();
        const ctx = useScanContext();
        return { ...scan, state: ctx.state };
      },
      { wrapper: Wrapper },
    );

    await act(async () => {
      await result.current.loadScans();
    });

    expect(result.current.state.scans).toEqual(scansList);

    // Now reset
    act(() => {
      result.current.resetScan();
    });

    expect(result.current.state.currentScan).toBeNull();
    expect(result.current.state.scanResults).toBeNull();
    expect(result.current.state.scans).toEqual(scansList); // preserved
  });
});
