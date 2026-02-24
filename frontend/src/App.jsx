/**
 * @file Root application component for the ReconScope dashboard.
 *
 * Orchestrates the top-level view transitions:
 *   - Empty state   -> ScanInput form
 *   - Running scan  -> ScanProgress + partial results
 *   - Completed scan -> Full results with tabbed navigation
 *
 * A scan-history sidebar is always visible on the left so users can
 * browse and select previous scans.
 */

import React, { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import Layout from './components/layout/Layout';
import ScanInput from './components/scan/ScanInput';
import ScanProgress from './components/scan/ScanProgress';
import ScanHistory from './components/scan/ScanHistory';
import StatsBar from './components/scan/StatsBar';
import TabNavigation from './components/common/TabNavigation';
import AttackGraph from './components/graph/AttackGraph';
import GraphControls from './components/graph/GraphControls';
import NodeDetailPanel from './components/graph/NodeDetailPanel';
import FindingsTable from './components/findings/FindingsTable';
import FindingsFilter from './components/findings/FindingsFilter';
import AttackPathCard from './components/attack-paths/AttackPathCard';
import CorrelationCard from './components/insights/CorrelationCard';
import LoadingSpinner from './components/common/LoadingSpinner';
import ExportMenu from './components/scan/ExportMenu';
import { useScanContext, SET_CURRENT_SCAN, SET_SCAN_RESULTS } from './context/ScanContext';
import useScan from './hooks/useScan';

/**
 * Inner application shell rendered inside the ScanProvider.
 *
 * @returns {React.ReactElement}
 */
function AppContent() {
  const { state, dispatch } = useScanContext();
  const { currentScan, scanResults, scans, loading } = state;
  const { loadScanResults, loadScans, deleteScan, resetScan } = useScan();

  const [activeTab, setActiveTab] = useState('graph');
  const [showInput, setShowInput] = useState(false);
  const [findingsFilters, setFindingsFilters] = useState({
    severities: ['critical', 'high', 'medium', 'low', 'info'],
    search: '',
    sortDir: 'desc',
  });

  const cyRef = useRef(null);

  const scanStatus = currentScan?.status;
  const scanId = currentScan?.scan_id;
  const isRunning = scanStatus === 'running' || scanStatus === 'queued';
  const isCompleted = scanStatus === 'completed';

  /* When a new scan is set as current, hide the input form and refresh list. */
  useEffect(() => {
    if (currentScan && showInput) {
      setShowInput(false);
      loadScans();
    }
  }, [currentScan, showInput, loadScans]);

  /* Load results once the scan completes and refresh the sidebar. */
  useEffect(() => {
    if (isCompleted && scanId && !scanResults) {
      loadScanResults(scanId);
      loadScans();
    }
  }, [isCompleted, scanId, scanResults, loadScanResults, loadScans]);

  /* Load the scan list on mount. */
  useEffect(() => {
    loadScans();
  }, [loadScans]);

  /** Select a scan from the history. */
  const handleSelectScan = useCallback(
    (scan) => {
      setShowInput(false);
      dispatch({ type: SET_SCAN_RESULTS, payload: null });
      dispatch({ type: SET_CURRENT_SCAN, payload: scan });
      if (scan.status === 'completed') {
        loadScanResults(scan.scan_id);
      }
    },
    [dispatch, loadScanResults],
  );

  /** Handle new scan button. */
  const handleNewScan = useCallback(() => {
    resetScan();
    setShowInput(true);
  }, [resetScan]);

  /** Handle delete. */
  const handleDelete = useCallback(
    (id) => {
      deleteScan(id);
      if (scanId === id) {
        resetScan();
      }
    },
    [deleteScan, scanId, resetScan],
  );

  /** Callback for tab changes. */
  const handleTabChange = useCallback(function onTabChange(id) {
    setActiveTab(id);
  }, []);

  /** Callback for findings filter changes. */
  const handleFilterChange = useCallback(function onFilterChange(next) {
    setFindingsFilters(next);
  }, []);

  /* Derive filtered findings. */
  const findings = scanResults?.findings ?? [];
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const sevMatch = findingsFilters.severities.includes(
        (f.severity ?? '').toLowerCase(),
      );
      const searchMatch =
        !findingsFilters.search ||
        (f.title ?? '').toLowerCase().includes(findingsFilters.search.toLowerCase()) ||
        (f.asset ?? '').toLowerCase().includes(findingsFilters.search.toLowerCase());
      return sevMatch && searchMatch;
    });
  }, [findings, findingsFilters]);

  const attackPaths = scanResults?.attackPaths ?? [];
  const correlations = scanResults?.correlations ?? [];

  /** Tab definitions with live counts. */
  const tabs = [
    { id: 'graph', label: 'Graph', count: scanResults?.graph?.nodes?.length },
    { id: 'findings', label: 'Findings', count: findings.length || undefined },
    { id: 'attack-paths', label: 'Attack Paths', count: attackPaths.length || undefined },
    { id: 'insights', label: 'Insights', count: correlations.length || undefined },
  ];

  /** Stats for the bar. */
  const stats = {
    subdomains_found: currentScan?.total_subdomains ?? currentScan?.stats?.subdomains_found ?? 0,
    services_found: currentScan?.total_services ?? currentScan?.stats?.services_found ?? 0,
    cves_found: currentScan?.total_cves ?? currentScan?.stats?.cves_found ?? 0,
    overall_risk: currentScan?.overall_risk ?? 'info',
  };

  /* ── Main content area ─────────────────────────── */
  const renderContent = () => {
    /* Show input form */
    if (showInput || (!currentScan && scans.length === 0)) {
      return (
        <div className="flex min-h-[70vh] items-center justify-center">
          <ScanInput />
        </div>
      );
    }

    /* No scan selected, but history exists */
    if (!currentScan) {
      return (
        <div className="flex min-h-[70vh] items-center justify-center">
          <div className="text-center text-slate-500">
            <p className="text-lg mb-2">Select a scan from history</p>
            <p className="text-sm">or start a new scan</p>
            <button
              type="button"
              onClick={handleNewScan}
              className="mt-4 px-6 py-2 rounded bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm"
            >
              + New Scan
            </button>
          </div>
        </div>
      );
    }

    /* Loading */
    if (loading && !scanResults) {
      return (
        <div className="flex min-h-[50vh] items-center justify-center">
          <LoadingSpinner message="Loading scan data..." size="lg" />
        </div>
      );
    }

    /* Failed scan */
    if (scanStatus === 'failed') {
      return (
        <div className="space-y-6 py-4">
          <StatsBar stats={stats} />
          <div className="flex items-center justify-center min-h-[30vh]">
            <div className="text-center">
              <div className="text-red-400 text-lg mb-2">Scan Failed</div>
              <p className="text-sm text-slate-500">
                The scan of <span className="font-mono text-slate-300">{currentScan.target}</span> has failed.
              </p>
              <button
                type="button"
                onClick={handleNewScan}
                className="mt-4 px-4 py-2 rounded bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm"
              >
                Start New Scan
              </button>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-6 py-4">
        {/* Stats (always visible when scan active) */}
        <StatsBar stats={stats} />

        {/* Running / queued -> show progress */}
        {isRunning && <ScanProgress />}

        {/* Completed -> show results */}
        {isCompleted && scanResults && (
          <>
            <div className="flex items-center justify-between gap-4">
              <TabNavigation
                tabs={tabs}
                activeTab={activeTab}
                onTabChange={handleTabChange}
              />
              <ExportMenu scanId={scanId} />
            </div>

            <div role="tabpanel" id={`panel-${activeTab}`}>
              {/* Graph */}
              {activeTab === 'graph' && (
                <div className="space-y-3">
                  <GraphControls cyRef={cyRef} />
                  <div className="relative">
                    <AttackGraph graphData={scanResults.graph ?? { nodes: [], edges: [] }} cyRef={cyRef} />
                    <NodeDetailPanel />
                  </div>
                </div>
              )}

              {/* Findings */}
              {activeTab === 'findings' && (
                <div className="space-y-3">
                  <FindingsFilter
                    filters={findingsFilters}
                    onFilterChange={handleFilterChange}
                  />
                  <FindingsTable findings={filteredFindings} />
                </div>
              )}

              {/* Attack Paths */}
              {activeTab === 'attack-paths' && (
                <div className="space-y-3">
                  {attackPaths.length > 0 ? (
                    attackPaths.map((path) => (
                      <AttackPathCard key={path.id} attackPath={path} />
                    ))
                  ) : (
                    <p className="py-10 text-center text-sm text-slate-500">
                      No attack paths identified.
                    </p>
                  )}
                </div>
              )}

              {/* Insights */}
              {activeTab === 'insights' && (
                <div className="space-y-3">
                  {correlations.length > 0 ? (
                    correlations.map((c) => (
                      <CorrelationCard key={c.id} correlation={c} />
                    ))
                  ) : (
                    <p className="py-10 text-center text-sm text-slate-500">
                      No correlation insights available.
                    </p>
                  )}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-[calc(100vh-56px)]">
      {/* ── Sidebar: Scan History ─────────────────── */}
      <div className="flex-shrink-0">
        <ScanHistory
          scans={scans}
          activeScanId={scanId ?? null}
          onSelect={handleSelectScan}
          onDelete={handleDelete}
          onNewScan={handleNewScan}
        />
      </div>

      {/* ── Main content ─────────────────────────── */}
      <main className="flex-1 overflow-y-auto px-6">
        {renderContent()}
      </main>
    </div>
  );
}

/**
 * Root component that wraps everything in the Layout (which provides
 * ScanProvider + Header).
 *
 * @returns {React.ReactElement}
 */
export default function App() {
  return (
    <Layout>
      <AppContent />
    </Layout>
  );
}
