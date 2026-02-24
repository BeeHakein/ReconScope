/**
 * @file Tests for the ScanContext (ScanProvider + useScanContext).
 *
 * Exercises every action type in the reducer and verifies the correct
 * state transitions, including the initial state, setting values,
 * adding messages, and resetting.
 */

import { describe, it, expect, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import React from 'react';
import {
  ScanProvider,
  useScanContext,
  SET_CURRENT_SCAN,
  SET_SCAN_RESULTS,
  SET_SCANS,
  SET_SELECTED_NODE,
  SET_FILTERS,
  ADD_WS_MESSAGE,
  SET_LOADING,
  SET_ERROR,
  UPDATE_SCAN_PROGRESS,
  RESET_SCAN,
} from '../../context/ScanContext';

/* ── Helper ────────────────────────────────────────────────── */

/**
 * Render useScanContext inside a ScanProvider wrapper.
 */
function renderScanContext() {
  return renderHook(() => useScanContext(), {
    wrapper: ({ children }) => <ScanProvider>{children}</ScanProvider>,
  });
}

/* ── Test suite ────────────────────────────────────────────── */

describe('ScanContext', () => {
  it('provides the correct initial state', () => {
    const { result } = renderScanContext();

    expect(result.current.state).toEqual({
      currentScan: null,
      scanResults: null,
      scans: [],
      selectedNode: null,
      filters: { severity: 'all', nodeType: 'all' },
      wsMessages: [],
      loading: false,
      error: null,
    });
  });

  it('provides a dispatch function', () => {
    const { result } = renderScanContext();

    expect(typeof result.current.dispatch).toBe('function');
  });

  it('throws when useScanContext is used outside a ScanProvider', () => {
    // Suppress the expected console.error from React
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      renderHook(() => useScanContext());
    }).toThrow('useScanContext must be used within a ScanProvider');

    spy.mockRestore();
  });

  /* ── SET_CURRENT_SCAN ──────────────────────────────────── */

  it('updates currentScan and clears error on SET_CURRENT_SCAN', () => {
    const { result } = renderScanContext();

    // Set an error first
    act(() => {
      result.current.dispatch({ type: SET_ERROR, payload: 'some error' });
    });
    expect(result.current.state.error).toBe('some error');

    // Dispatch SET_CURRENT_SCAN
    const scanData = { scan_id: 'uuid-1', target: 'example.com', status: 'running' };
    act(() => {
      result.current.dispatch({ type: SET_CURRENT_SCAN, payload: scanData });
    });

    expect(result.current.state.currentScan).toEqual(scanData);
    expect(result.current.state.error).toBeNull();
  });

  /* ── SET_SCAN_RESULTS ──────────────────────────────────── */

  it('updates scanResults on SET_SCAN_RESULTS', () => {
    const { result } = renderScanContext();

    const results = {
      scan: { scan_id: 'uuid-1' },
      graph: { nodes: [], edges: [] },
      findings: [{ id: '1', severity: 'critical' }],
      attackPaths: [],
      correlations: [],
    };

    act(() => {
      result.current.dispatch({ type: SET_SCAN_RESULTS, payload: results });
    });

    expect(result.current.state.scanResults).toEqual(results);
  });

  /* ── SET_SCANS ─────────────────────────────────────────── */

  it('updates the scans list on SET_SCANS', () => {
    const { result } = renderScanContext();

    const scans = [
      { scan_id: 'a', target: 'one.com' },
      { scan_id: 'b', target: 'two.com' },
    ];

    act(() => {
      result.current.dispatch({ type: SET_SCANS, payload: scans });
    });

    expect(result.current.state.scans).toEqual(scans);
  });

  /* ── SET_SELECTED_NODE ─────────────────────────────────── */

  it('updates selectedNode on SET_SELECTED_NODE', () => {
    const { result } = renderScanContext();

    const nodeData = { id: 'n1', label: 'example.com', type: 'domain' };

    act(() => {
      result.current.dispatch({ type: SET_SELECTED_NODE, payload: nodeData });
    });

    expect(result.current.state.selectedNode).toEqual(nodeData);
  });

  it('clears selectedNode when SET_SELECTED_NODE is dispatched with null', () => {
    const { result } = renderScanContext();

    act(() => {
      result.current.dispatch({
        type: SET_SELECTED_NODE,
        payload: { id: 'n1', label: 'x', type: 'domain' },
      });
    });

    act(() => {
      result.current.dispatch({ type: SET_SELECTED_NODE, payload: null });
    });

    expect(result.current.state.selectedNode).toBeNull();
  });

  /* ── SET_FILTERS ───────────────────────────────────────── */

  it('merges filters on SET_FILTERS', () => {
    const { result } = renderScanContext();

    act(() => {
      result.current.dispatch({
        type: SET_FILTERS,
        payload: { severity: 'critical' },
      });
    });

    expect(result.current.state.filters).toEqual({
      severity: 'critical',
      nodeType: 'all',
    });
  });

  it('can update multiple filter fields at once', () => {
    const { result } = renderScanContext();

    act(() => {
      result.current.dispatch({
        type: SET_FILTERS,
        payload: { severity: 'high', nodeType: 'subdomain' },
      });
    });

    expect(result.current.state.filters).toEqual({
      severity: 'high',
      nodeType: 'subdomain',
    });
  });

  /* ── ADD_WS_MESSAGE ────────────────────────────────────── */

  it('appends to wsMessages on ADD_WS_MESSAGE', () => {
    const { result } = renderScanContext();

    const msg1 = { event: 'module_started', module: 'dns' };
    const msg2 = { event: 'module_completed', module: 'dns' };

    act(() => {
      result.current.dispatch({ type: ADD_WS_MESSAGE, payload: msg1 });
    });

    expect(result.current.state.wsMessages).toEqual([msg1]);

    act(() => {
      result.current.dispatch({ type: ADD_WS_MESSAGE, payload: msg2 });
    });

    expect(result.current.state.wsMessages).toEqual([msg1, msg2]);
  });

  /* ── SET_LOADING ───────────────────────────────────────── */

  it('sets loading state on SET_LOADING', () => {
    const { result } = renderScanContext();

    act(() => {
      result.current.dispatch({ type: SET_LOADING, payload: true });
    });

    expect(result.current.state.loading).toBe(true);

    act(() => {
      result.current.dispatch({ type: SET_LOADING, payload: false });
    });

    expect(result.current.state.loading).toBe(false);
  });

  /* ── SET_ERROR ─────────────────────────────────────────── */

  it('sets error and clears loading on SET_ERROR', () => {
    const { result } = renderScanContext();

    act(() => {
      result.current.dispatch({ type: SET_LOADING, payload: true });
    });

    act(() => {
      result.current.dispatch({ type: SET_ERROR, payload: 'Something went wrong' });
    });

    expect(result.current.state.error).toBe('Something went wrong');
    expect(result.current.state.loading).toBe(false);
  });

  /* ── UPDATE_SCAN_PROGRESS ──────────────────────────────── */

  it('merges progress data into currentScan on UPDATE_SCAN_PROGRESS', () => {
    const { result } = renderScanContext();

    // First set a current scan
    act(() => {
      result.current.dispatch({
        type: SET_CURRENT_SCAN,
        payload: { scan_id: 'uuid-1', status: 'queued', progress: {} },
      });
    });

    // Then update its progress
    act(() => {
      result.current.dispatch({
        type: UPDATE_SCAN_PROGRESS,
        payload: { status: 'running', progress: { current_module: 'dns' } },
      });
    });

    expect(result.current.state.currentScan.status).toBe('running');
    expect(result.current.state.currentScan.progress.current_module).toBe('dns');
  });

  it('does nothing for UPDATE_SCAN_PROGRESS when currentScan is null', () => {
    const { result } = renderScanContext();

    act(() => {
      result.current.dispatch({
        type: UPDATE_SCAN_PROGRESS,
        payload: { status: 'running' },
      });
    });

    expect(result.current.state.currentScan).toBeNull();
  });

  /* ── RESET_SCAN ────────────────────────────────────────── */

  it('resets to initial state but preserves the scans list', () => {
    const { result } = renderScanContext();

    // Populate the state
    act(() => {
      result.current.dispatch({
        type: SET_SCANS,
        payload: [{ scan_id: 'a' }, { scan_id: 'b' }],
      });
    });
    act(() => {
      result.current.dispatch({
        type: SET_CURRENT_SCAN,
        payload: { scan_id: 'a', status: 'completed' },
      });
    });
    act(() => {
      result.current.dispatch({
        type: SET_SCAN_RESULTS,
        payload: { graph: {}, findings: [] },
      });
    });
    act(() => {
      result.current.dispatch({
        type: ADD_WS_MESSAGE,
        payload: { event: 'test' },
      });
    });
    act(() => {
      result.current.dispatch({
        type: SET_SELECTED_NODE,
        payload: { id: 'n1' },
      });
    });

    // Reset
    act(() => {
      result.current.dispatch({ type: RESET_SCAN });
    });

    expect(result.current.state.currentScan).toBeNull();
    expect(result.current.state.scanResults).toBeNull();
    expect(result.current.state.selectedNode).toBeNull();
    expect(result.current.state.wsMessages).toEqual([]);
    expect(result.current.state.loading).toBe(false);
    expect(result.current.state.error).toBeNull();
    expect(result.current.state.filters).toEqual({ severity: 'all', nodeType: 'all' });

    // Scans list is preserved
    expect(result.current.state.scans).toEqual([{ scan_id: 'a' }, { scan_id: 'b' }]);
  });

  /* ── Unknown action ────────────────────────────────────── */

  it('returns unchanged state for an unknown action type', () => {
    const { result } = renderScanContext();

    const stateBefore = result.current.state;

    act(() => {
      result.current.dispatch({ type: 'NONEXISTENT_ACTION', payload: 'foo' });
    });

    expect(result.current.state).toEqual(stateBefore);
  });
});
