/**
 * @file Interactive Cytoscape.js attack-surface graph.
 *
 * Renders the network of domains, subdomains, services, technologies,
 * and CVEs using a force-directed CoSE-Bilkent layout.  Nodes are
 * coloured by type and sized by risk score; edges reflect relationship
 * type.  Clicking a node updates the global ScanContext.
 */

import React, { useRef, useCallback, useEffect } from 'react';
import PropTypes from 'prop-types';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import { NODE_COLORS, EDGE_COLORS } from '../../constants/colors';
import { useScanContext, SET_SELECTED_NODE } from '../../context/ScanContext';

/** Map severity labels to numeric rank for threshold filtering. */
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/* Register the layout extension once. */
if (!cytoscape.prototype._coseBilkentRegistered) {
  cytoscape.use(coseBilkent);
  cytoscape.prototype._coseBilkentRegistered = true;
}

/** CoSE-Bilkent layout configuration. */
const LAYOUT = {
  name: 'cose-bilkent',
  animate: 'end',
  animationDuration: 500,
  nodeRepulsion: 8000,
  idealEdgeLength: 120,
  edgeElasticity: 0.45,
  nestingFactor: 0.1,
  gravity: 0.25,
  tile: true,
  fit: true,
  padding: 30,
};

/**
 * Convert API graph data into Cytoscape elements.
 *
 * @param {{ nodes: object[], edges: object[] }} graphData
 * @returns {Array<object>}
 */
function toElements(graphData) {
  const nodes = (graphData?.nodes ?? []).map((n) => ({
    data: {
      id: n.id,
      label: n.label,
      type: n.type,
      risk_level: n.risk_level,
      risk_score: n.risk_score,
      metadata: n.metadata,
    },
  }));

  const edges = (graphData?.edges ?? []).map((e, i) => ({
    data: {
      id: `e-${i}`,
      source: e.source,
      target: e.target,
      type: e.type,
    },
  }));

  return [...nodes, ...edges];
}

/** Cytoscape stylesheet applied to every graph instance. */
const STYLESHEET = [
  {
    selector: 'node',
    style: {
      label: 'data(label)',
      'font-size': 10,
      color: '#e2e8f0',
      'text-valign': 'bottom',
      'text-margin-y': 6,
      'background-color': '#64748b',
      width: 'mapData(risk_score, 0, 100, 20, 50)',
      height: 'mapData(risk_score, 0, 100, 20, 50)',
    },
  },
  ...Object.entries(NODE_COLORS).map(([type, color]) => ({
    selector: `node[type="${type}"]`,
    style: { 'background-color': color },
  })),
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': '#475569',
      'target-arrow-color': '#475569',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
    },
  },
  ...Object.entries(EDGE_COLORS).map(([type, color]) => ({
    selector: `edge[type="${type}"]`,
    style: { 'line-color': color, 'target-arrow-color': color },
  })),
  {
    selector: ':selected',
    style: {
      'border-width': 3,
      'border-color': '#06b6d4',
    },
  },
];

/**
 * Cytoscape-powered interactive network graph.
 *
 * @param {{ graphData: { nodes: object[], edges: object[] } }} props
 * @returns {React.ReactElement}
 */
export default function AttackGraph({ graphData, cyRef: externalCyRef }) {
  const { state, dispatch } = useScanContext();
  const internalCyRef = useRef(null);
  const cyRef = externalCyRef || internalCyRef;
  const { filters } = state;

  const elements = toElements(graphData);

  /** Persist the Cytoscape core reference for external controls. */
  const handleCyReady = useCallback(
    function onCyReady(cy) {
      cyRef.current = cy;

      cy.on('tap', 'node', function handleNodeTap(event) {
        const nodeData = event.target.data();
        dispatch({ type: SET_SELECTED_NODE, payload: nodeData });
      });

      cy.on('tap', function handleBackgroundTap(event) {
        if (event.target === cy) {
          dispatch({ type: SET_SELECTED_NODE, payload: null });
        }
      });
    },
    [dispatch, cyRef],
  );

  /* Re-run layout when graph data changes. */
  useEffect(() => {
    if (cyRef.current && elements.length > 0) {
      cyRef.current.layout(LAYOUT).run();
    }
  }, [elements.length, cyRef]);

  /* Apply filters when they change. */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const nodeTypeFilter = filters.nodeType || 'all';
    const severityFilter = filters.severity || 'all';
    const severityThreshold = SEVERITY_RANK[severityFilter] ?? -1;

    cy.batch(() => {
      cy.nodes().forEach((node) => {
        const type = node.data('type');
        const riskLevel = (node.data('risk_level') || 'info').toLowerCase();
        const nodeRank = SEVERITY_RANK[riskLevel] ?? 0;

        const typeMatch = nodeTypeFilter === 'all' || type === nodeTypeFilter;
        const sevMatch = severityFilter === 'all' || nodeRank >= severityThreshold;

        const visible = typeMatch && sevMatch;
        node.style('display', visible ? 'element' : 'none');
      });

      /* Hide edges whose source or target is hidden. */
      cy.edges().forEach((edge) => {
        const srcVisible = edge.source().style('display') !== 'none';
        const tgtVisible = edge.target().style('display') !== 'none';
        edge.style('display', srcVisible && tgtVisible ? 'element' : 'none');
      });
    });
  }, [filters.nodeType, filters.severity, cyRef]);

  if (!elements.length) {
    return (
      <div className="flex h-96 items-center justify-center text-sm text-slate-500">
        No graph data available.
      </div>
    );
  }

  return (
    <div
      className="relative h-[600px] w-full rounded-lg border border-slate-800 bg-slate-950"
      aria-label="Attack surface graph"
    >
      <CytoscapeComponent
        elements={elements}
        layout={LAYOUT}
        stylesheet={STYLESHEET}
        className="h-full w-full"
        cy={handleCyReady}
      />
    </div>
  );
}

AttackGraph.propTypes = {
  /** Graph payload with `nodes` and `edges` arrays from the API. */
  graphData: PropTypes.shape({
    nodes: PropTypes.arrayOf(PropTypes.object),
    edges: PropTypes.arrayOf(PropTypes.object),
  }).isRequired,
  /** Optional external ref so parent controls can access the Cytoscape core. */
  cyRef: PropTypes.shape({ current: PropTypes.object }),
};

AttackGraph.defaultProps = {
  cyRef: undefined,
};
