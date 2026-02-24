/**
 * @file Tests for the AttackGraph component.
 *
 * Mocks Cytoscape and react-cytoscapejs so the tests run in jsdom
 * without needing a real canvas.  Verifies that the graph container
 * renders, that nodes/edges produce a CytoscapeComponent, and that
 * empty data shows a fallback message.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';

/* ── Mocks ─────────────────────────────────────────────────── */

/*
 * Mock cytoscape core and the cose-bilkent extension so the import
 * does not attempt real canvas rendering.
 *
 * NOTE: vi.mock factories are hoisted, so we cannot reference variables
 * declared in this file scope.  All mock logic must be self-contained
 * inside the factory.
 */
vi.mock('cytoscape', () => {
  const fn = Object.assign(() => {}, {
    use: () => {},
    prototype: {},
  });
  return { default: fn };
});

vi.mock('cytoscape-cose-bilkent', () => ({
  default: () => {},
}));

/*
 * Mock react-cytoscapejs to render a plain div so we can verify
 * it receives the correct props.
 */
vi.mock('react-cytoscapejs', () => ({
  default: function MockCytoscapeComponent(props) {
    return (
      <div data-testid="cytoscape-component" data-elements={JSON.stringify(props.elements)}>
        Cytoscape Mock
      </div>
    );
  },
}));

import { ScanProvider } from '../../context/ScanContext';
import AttackGraph from '../../components/graph/AttackGraph';

/* ── Helpers ───────────────────────────────────────────────── */

function renderGraph(graphData) {
  return render(
    <ScanProvider>
      <AttackGraph graphData={graphData} />
    </ScanProvider>,
  );
}

/* ── Sample data ───────────────────────────────────────────── */

const GRAPH_WITH_NODES = {
  nodes: [
    { id: 'n1', label: 'example.com', type: 'domain', risk_level: 'high', risk_score: 80, metadata: {} },
    { id: 'n2', label: 'sub.example.com', type: 'subdomain', risk_level: 'medium', risk_score: 50, metadata: {} },
    { id: 'n3', label: 'nginx/1.21', type: 'technology', risk_level: 'low', risk_score: 20, metadata: {} },
  ],
  edges: [
    { source: 'n1', target: 'n2', type: 'resolves_to' },
    { source: 'n2', target: 'n3', type: 'uses_tech' },
  ],
};

const EMPTY_GRAPH = {
  nodes: [],
  edges: [],
};

/* ── Test suite ────────────────────────────────────────────── */

describe('AttackGraph', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the graph container when nodes are present', () => {
    renderGraph(GRAPH_WITH_NODES);

    const container = screen.getByLabelText('Attack surface graph');
    expect(container).toBeInTheDocument();
  });

  it('renders the CytoscapeComponent when given graph data with nodes', () => {
    renderGraph(GRAPH_WITH_NODES);

    const cytoComponent = screen.getByTestId('cytoscape-component');
    expect(cytoComponent).toBeInTheDocument();

    // Verify elements were passed
    const elements = JSON.parse(cytoComponent.getAttribute('data-elements'));
    // 3 nodes + 2 edges = 5 elements
    expect(elements).toHaveLength(5);
  });

  it('passes nodes with the correct data structure to CytoscapeComponent', () => {
    renderGraph(GRAPH_WITH_NODES);

    const cytoComponent = screen.getByTestId('cytoscape-component');
    const elements = JSON.parse(cytoComponent.getAttribute('data-elements'));

    const nodeElements = elements.filter((el) => !el.data.source);
    expect(nodeElements).toHaveLength(3);

    const domainNode = nodeElements.find((n) => n.data.id === 'n1');
    expect(domainNode.data.label).toBe('example.com');
    expect(domainNode.data.type).toBe('domain');
    expect(domainNode.data.risk_score).toBe(80);
  });

  it('passes edges with the correct data structure to CytoscapeComponent', () => {
    renderGraph(GRAPH_WITH_NODES);

    const cytoComponent = screen.getByTestId('cytoscape-component');
    const elements = JSON.parse(cytoComponent.getAttribute('data-elements'));

    const edgeElements = elements.filter((el) => el.data.source);
    expect(edgeElements).toHaveLength(2);

    const firstEdge = edgeElements[0];
    expect(firstEdge.data.source).toBe('n1');
    expect(firstEdge.data.target).toBe('n2');
    expect(firstEdge.data.type).toBe('resolves_to');
  });

  it('renders an empty-state message when graphData has no nodes', () => {
    renderGraph(EMPTY_GRAPH);

    expect(screen.getByText(/no graph data available/i)).toBeInTheDocument();
    expect(screen.queryByTestId('cytoscape-component')).not.toBeInTheDocument();
  });

  it('renders an empty-state message when graphData is null-ish', () => {
    renderGraph({ nodes: null, edges: null });

    expect(screen.getByText(/no graph data available/i)).toBeInTheDocument();
  });

  it('does not render the CytoscapeComponent in the empty state', () => {
    renderGraph(EMPTY_GRAPH);

    expect(screen.queryByTestId('cytoscape-component')).not.toBeInTheDocument();
  });
});
