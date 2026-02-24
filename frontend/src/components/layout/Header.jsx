/**
 * @file Fixed top header bar for the ReconScope dashboard.
 *
 * Displays the application logo, the currently-scanned target, and a
 * badge indicating how many scans are stored.
 */

import React from 'react';
import { useScanContext } from '../../context/ScanContext';

/**
 * Application header pinned to the top of the viewport.
 *
 * @returns {React.ReactElement}
 */
export default function Header() {
  const { state } = useScanContext();
  const { currentScan, scans } = state;

  return (
    <header className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between bg-slate-900 border-b border-slate-800 px-6 py-3">
      {/* ── Left: Logo ─────────────────────────────────── */}
      <div className="flex items-center gap-2">
        <span
          className="text-cyan-400 text-xl font-bold tracking-wide"
          aria-label="ReconScope logo"
        >
          &#x25C9;
        </span>
        <h1 className="text-lg font-semibold text-slate-100">
          Recon<span className="text-cyan-400">Scope</span>
        </h1>
      </div>

      {/* ── Centre: Target indicator ───────────────────── */}
      <div className="hidden sm:flex items-center gap-2 text-sm text-slate-400">
        {currentScan ? (
          <>
            <span className="inline-block h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="font-mono text-slate-200">
              {currentScan.target}
            </span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
              {currentScan.status}
            </span>
          </>
        ) : (
          <span>No active scan</span>
        )}
      </div>

      {/* ── Right: Scan count badge ────────────────────── */}
      <div className="flex items-center gap-2">
        <span
          className="inline-flex items-center rounded-full bg-slate-800 px-3 py-1 text-xs font-medium text-slate-300"
          aria-label={`${scans.length} scans stored`}
        >
          {scans.length} scan{scans.length !== 1 ? 's' : ''}
        </span>
      </div>
    </header>
  );
}
