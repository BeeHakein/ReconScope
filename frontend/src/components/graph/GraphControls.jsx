/**
 * @file Control panel for the Cytoscape graph (zoom, filter, layout).
 *
 * Receives a ref to the Cytoscape core instance so it can programmatically
 * zoom, fit, and filter nodes without re-rendering the graph component.
 */

import React, { useCallback } from 'react';
import PropTypes from 'prop-types';
import { NODE_COLORS } from '../../constants/colors';
import { useScanContext, SET_FILTERS } from '../../context/ScanContext';

const NODE_TYPES = ['domain', 'subdomain', 'service', 'technology', 'cve'];
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];
const BTN = 'flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700 bg-slate-800 text-sm text-slate-300 hover:bg-slate-700 transition-colors';

/**
 * Graph toolbar with zoom, filter, and layout-reset controls.
 *
 * @param {{ cyRef: React.MutableRefObject<object|null> }} props
 * @returns {React.ReactElement}
 */
export default function GraphControls({ cyRef }) {
  const { state, dispatch } = useScanContext();
  const { filters } = state;

  const handleZoomIn = useCallback(function zoomIn() {
    const cy = cyRef.current;
    if (cy) cy.zoom(cy.zoom() * 1.25);
  }, [cyRef]);

  const handleZoomOut = useCallback(function zoomOut() {
    const cy = cyRef.current;
    if (cy) cy.zoom(cy.zoom() * 0.8);
  }, [cyRef]);

  const handleFit = useCallback(function fitView() {
    cyRef.current?.fit(undefined, 30);
  }, [cyRef]);

  const handleResetLayout = useCallback(function resetLayout() {
    cyRef.current?.layout({ name: 'cose-bilkent', animate: 'end' }).run();
  }, [cyRef]);

  function handleNodeTypeChange(e) {
    dispatch({ type: SET_FILTERS, payload: { nodeType: e.target.value } });
  }
  function handleSeverityChange(e) {
    dispatch({ type: SET_FILTERS, payload: { severity: e.target.value } });
  }

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3" aria-label="Graph controls">
      <div className="flex gap-1">
        <button type="button" onClick={handleZoomIn} className={BTN} aria-label="Zoom in">+</button>
        <button type="button" onClick={handleZoomOut} className={BTN} aria-label="Zoom out">&minus;</button>
        <button type="button" onClick={handleFit} className={BTN} aria-label="Fit graph to viewport">&#x2922;</button>
      </div>
      <span className="h-6 w-px bg-slate-700" aria-hidden="true" />
      <label className="flex items-center gap-2 text-xs text-slate-400">
        Type
        <select value={filters.nodeType} onChange={handleNodeTypeChange} className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 focus:border-cyan-400 focus:outline-none" aria-label="Filter by node type">
          <option value="all">All</option>
          {NODE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>
      <label className="flex items-center gap-2 text-xs text-slate-400">
        Severity
        <select value={filters.severity} onChange={handleSeverityChange} className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 focus:border-cyan-400 focus:outline-none" aria-label="Filter by severity">
          <option value="all">All</option>
          {SEVERITY_LEVELS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <span className="h-6 w-px bg-slate-700" aria-hidden="true" />
      <button type="button" onClick={handleResetLayout} className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors" aria-label="Reset graph layout">
        Reset Layout
      </button>
      <div className="ml-auto hidden gap-3 lg:flex">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span key={type} className="flex items-center gap-1 text-xs text-slate-400">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} aria-hidden="true" />
            {type}
          </span>
        ))}
      </div>
    </div>
  );
}

GraphControls.propTypes = {
  /** Mutable ref containing the Cytoscape core instance. */
  cyRef: PropTypes.shape({ current: PropTypes.object }).isRequired,
};
