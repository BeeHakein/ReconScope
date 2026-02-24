/**
 * @file Expandable card displaying a single inferred attack path.
 *
 * Shows the severity, title, ordered attack steps with MITRE ATT&CK
 * technique IDs, and the list of affected nodes.
 */

import React, { useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import SeverityBadge from '../common/SeverityBadge';
import {
  useScanContext,
  SET_SELECTED_NODE,
} from '../../context/ScanContext';

/**
 * Card component for a single attack path.
 *
 * @param {{ attackPath: object }} props
 * @returns {React.ReactElement}
 */
export default function AttackPathCard({ attackPath }) {
  const { dispatch } = useScanContext();
  const [expanded, setExpanded] = useState(false);

  /** Toggle the expanded state of the card. */
  const handleToggle = useCallback(function toggle() {
    setExpanded((prev) => !prev);
  }, []);

  /** Highlight a node in the graph by dispatching to context. */
  function handleNodeClick(nodeId) {
    return function onClickNode() {
      dispatch({
        type: SET_SELECTED_NODE,
        payload: { id: nodeId, label: nodeId, type: 'unknown' },
      });
    };
  }

  const { severity, title, steps = [], affected_nodes: nodes = [] } = attackPath;

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 transition-colors hover:border-slate-700">
      {/* Header */}
      <button
        type="button"
        onClick={handleToggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
        aria-expanded={expanded}
        aria-label={`Attack path: ${title}`}
      >
        <SeverityBadge severity={severity} />
        <span className="flex-1 text-sm font-medium text-slate-200 truncate">
          {title}
        </span>
        <span className="text-xs text-slate-500">
          {steps.length} step{steps.length !== 1 ? 's' : ''}
        </span>
        <span
          className={`text-slate-400 transition-transform ${expanded ? 'rotate-180' : ''}`}
          aria-hidden="true"
        >
          &#x25BE;
        </span>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-slate-800 px-4 py-4 animate-fade-in">
          {/* Steps */}
          {steps.length > 0 && (
            <ol className="mb-4 space-y-3" aria-label="Attack steps">
              {steps.map((step, idx) => (
                <li key={idx} className="flex gap-3 text-sm">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-slate-800 text-xs font-bold text-cyan-400">
                    {idx + 1}
                  </span>
                  <div className="flex flex-col">
                    <span className="text-slate-300">{step.description}</span>
                    <a
                      href={`https://attack.mitre.org/techniques/${step.technique.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="mt-0.5 font-mono text-xs text-slate-500 hover:text-cyan-400 transition-colors"
                      title={`MITRE ATT&CK ${step.technique}`}
                    >
                      {step.technique} ↗
                    </a>
                  </div>
                </li>
              ))}
            </ol>
          )}

          {/* Affected nodes */}
          {nodes.length > 0 && (
            <div>
              <h4 className="mb-2 text-xs font-medium uppercase text-slate-500">
                Affected Nodes
              </h4>
              <div className="flex flex-wrap gap-2">
                {nodes.map((nodeId) => (
                  <button
                    key={nodeId}
                    type="button"
                    onClick={handleNodeClick(nodeId)}
                    className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1 font-mono text-xs text-slate-300 hover:border-cyan-700 hover:text-cyan-400 transition-colors"
                    aria-label={`Highlight node ${nodeId}`}
                  >
                    {nodeId}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

AttackPathCard.propTypes = {
  /** Attack path object from the API. */
  attackPath: PropTypes.shape({
    id: PropTypes.string.isRequired,
    severity: PropTypes.string.isRequired,
    title: PropTypes.string,
    steps: PropTypes.arrayOf(
      PropTypes.shape({
        description: PropTypes.string.isRequired,
        node_id: PropTypes.string.isRequired,
        technique: PropTypes.string.isRequired,
      }),
    ),
    affected_nodes: PropTypes.arrayOf(PropTypes.string),
  }).isRequired,
};
