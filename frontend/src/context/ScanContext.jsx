/**
 * @file Centralised state management for the ReconScope scan lifecycle.
 *
 * Uses React Context combined with `useReducer` so that every component
 * in the tree can read and update scan state without prop-drilling.
 */

import React, { createContext, useContext, useReducer, useMemo } from 'react';
import PropTypes from 'prop-types';

/* ── Action types ─────────────────────────────────────────── */

export const SET_CURRENT_SCAN = 'SET_CURRENT_SCAN';
export const SET_SCAN_RESULTS = 'SET_SCAN_RESULTS';
export const SET_SCANS = 'SET_SCANS';
export const SET_SELECTED_NODE = 'SET_SELECTED_NODE';
export const SET_FILTERS = 'SET_FILTERS';
export const ADD_WS_MESSAGE = 'ADD_WS_MESSAGE';
export const SET_LOADING = 'SET_LOADING';
export const SET_ERROR = 'SET_ERROR';
export const UPDATE_SCAN_PROGRESS = 'UPDATE_SCAN_PROGRESS';
export const RESET_SCAN = 'RESET_SCAN';

/* ── Initial state ────────────────────────────────────────── */

/** @type {import('./ScanContext').ScanState} */
const initialState = {
  currentScan: null,
  scanResults: null,
  scans: [],
  selectedNode: null,
  filters: { severity: 'all', nodeType: 'all' },
  wsMessages: [],
  loading: false,
  error: null,
};

/* ── Reducer ──────────────────────────────────────────────── */

/**
 * Pure reducer that produces the next state for every dispatched action.
 *
 * @param {typeof initialState} state
 * @param {{ type: string, payload?: unknown }} action
 * @returns {typeof initialState}
 */
function scanReducer(state, action) {
  switch (action.type) {
    case SET_CURRENT_SCAN:
      return { ...state, currentScan: action.payload, error: null };
    case SET_SCAN_RESULTS:
      return { ...state, scanResults: action.payload };
    case SET_SCANS:
      return { ...state, scans: action.payload };
    case SET_SELECTED_NODE:
      return { ...state, selectedNode: action.payload };
    case SET_FILTERS:
      return { ...state, filters: { ...state.filters, ...action.payload } };
    case ADD_WS_MESSAGE:
      return { ...state, wsMessages: [...state.wsMessages, action.payload] };
    case SET_LOADING:
      return { ...state, loading: action.payload };
    case SET_ERROR:
      return { ...state, error: action.payload, loading: false };
    case UPDATE_SCAN_PROGRESS:
      return {
        ...state,
        currentScan: state.currentScan
          ? { ...state.currentScan, ...action.payload }
          : state.currentScan,
      };
    case RESET_SCAN:
      return { ...initialState, scans: state.scans };
    default:
      return state;
  }
}

/* ── Context ──────────────────────────────────────────────── */

const ScanContext = createContext(undefined);

/* ── Provider ─────────────────────────────────────────────── */

/**
 * Wraps descendant components with scan-lifecycle state and a dispatch
 * function.
 *
 * @param {{ children: React.ReactNode }} props
 */
export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);

  const value = useMemo(() => ({ state, dispatch }), [state]);

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

ScanProvider.propTypes = {
  children: PropTypes.node.isRequired,
};

/* ── Hook ─────────────────────────────────────────────────── */

/**
 * Convenience hook that returns the current scan state and dispatch.
 *
 * @returns {{ state: typeof initialState, dispatch: React.Dispatch }}
 * @throws {Error} When called outside a `<ScanProvider>`.
 */
export function useScanContext() {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return context;
}
