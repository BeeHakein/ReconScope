/**
 * @file Slide-in detail panel for the currently selected graph node.
 *
 * Reads `selectedNode` from ScanContext and renders its properties,
 * metadata, risk information, and connected neighbours.
 */

import React from 'react';
import {
  useScanContext,
  SET_SELECTED_NODE,
} from '../../context/ScanContext';
import SeverityBadge from '../common/SeverityBadge';
import { NODE_COLORS } from '../../constants/colors';

/**
 * Slide-in panel anchored to the right edge of its parent container.
 *
 * @returns {React.ReactElement|null}
 */
export default function NodeDetailPanel() {
  const { state, dispatch } = useScanContext();
  const { selectedNode, scanResults } = state;

  if (!selectedNode) return null;

  /** Close the panel and deselect the node. */
  function handleClose() {
    dispatch({ type: SET_SELECTED_NODE, payload: null });
  }

  /** Collect edges and neighbours from the graph data. */
  const edges = (scanResults?.graph?.edges ?? []).filter(
    (e) => e.source === selectedNode.id || e.target === selectedNode.id,
  );

  const neighbourIds = edges.map((e) =>
    e.source === selectedNode.id ? e.target : e.source,
  );

  const neighbours = (scanResults?.graph?.nodes ?? []).filter((n) =>
    neighbourIds.includes(n.id),
  );

  const nodeColor =
    NODE_COLORS[selectedNode.type] ?? '#64748b';

  return (
    <aside
      className="absolute right-0 top-0 z-40 flex h-full w-80 flex-col border-l border-slate-800 bg-slate-900 shadow-xl animate-fade-in overflow-y-auto"
      aria-label="Node details"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-slate-100 truncate">
          {selectedNode.label}
        </h3>
        <button
          type="button"
          onClick={handleClose}
          className="rounded p-1 text-slate-400 hover:text-slate-200"
          aria-label="Close detail panel"
        >
          &#x2715;
        </button>
      </div>

      <div className="flex flex-col gap-4 px-4 py-4 text-sm">
        {/* Type & Risk */}
        <div className="flex items-center gap-2">
          <span
            className="inline-block h-3 w-3 rounded-full"
            style={{ backgroundColor: nodeColor }}
            aria-hidden="true"
          />
          <span className="capitalize text-slate-300">{selectedNode.type}</span>
          <SeverityBadge severity={selectedNode.risk_level ?? 'info'} />
        </div>

        {/* Risk score */}
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Risk Score</span>
          <span className="font-mono text-slate-100">
            {selectedNode.risk_score ?? 0}
          </span>
        </div>

        {/* Metadata */}
        {selectedNode.metadata &&
          Object.keys(selectedNode.metadata).length > 0 && (
            <div>
              <h4 className="mb-2 text-xs font-medium uppercase text-slate-500">
                Metadata
              </h4>
              <dl className="space-y-1">
                {Object.entries(selectedNode.metadata).map(([key, value]) => (
                  <div key={key} className="flex justify-between gap-2">
                    <dt className="truncate text-slate-400">{key}</dt>
                    <dd className="truncate font-mono text-slate-200">
                      {String(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

        {/* Connected edges */}
        {edges.length > 0 && (
          <div>
            <h4 className="mb-2 text-xs font-medium uppercase text-slate-500">
              Connections ({edges.length})
            </h4>
            <ul className="space-y-1">
              {edges.map((e, i) => (
                <li
                  key={i}
                  className="rounded border border-slate-800 bg-slate-800/40 px-3 py-1.5 text-xs text-slate-300"
                >
                  <span className="font-mono">{e.type}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Neighbours */}
        {neighbours.length > 0 && (
          <div>
            <h4 className="mb-2 text-xs font-medium uppercase text-slate-500">
              Neighbours ({neighbours.length})
            </h4>
            <ul className="space-y-1">
              {neighbours.map((n) => (
                <li
                  key={n.id}
                  className="truncate rounded border border-slate-800 bg-slate-800/40 px-3 py-1.5 text-xs text-slate-300"
                >
                  {n.label}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </aside>
  );
}
