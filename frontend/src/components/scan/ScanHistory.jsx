/**
 * @file Sidebar panel listing all previous scans.
 *
 * Allows the user to select a past scan to view its results, delete scans,
 * or start a new scan. Each row shows the target domain, status, timestamp,
 * and key stats.
 */

import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { SEVERITY_COLORS } from '../../constants/colors';
import ScheduleList from './ScheduleList';

const STATUS_DOTS = {
  completed: 'bg-green-400',
  running: 'bg-cyan-400 animate-pulse',
  queued: 'bg-yellow-400 animate-pulse',
  failed: 'bg-red-400',
  post_processing: 'bg-cyan-400 animate-pulse',
};

/**
 * Format an ISO timestamp to a concise local string.
 *
 * @param {string} iso
 * @returns {string}
 */
function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-US', {
    day: '2-digit',
    month: '2-digit',
    year: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format duration in seconds to a human-readable string.
 *
 * @param {number|null} seconds
 * @returns {string}
 */
function formatDuration(seconds) {
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

/**
 * A single scan row in the history list.
 *
 * @param {{ scan: object, isActive: boolean, onSelect: function, onDelete: function }} props
 */
function ScanRow({ scan, isActive, onSelect, onDelete }) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const handleDelete = (e) => {
    e.stopPropagation();
    if (confirmDelete) {
      onDelete(scan.scan_id);
      setConfirmDelete(false);
    } else {
      setConfirmDelete(true);
      setTimeout(() => setConfirmDelete(false), 3000);
    }
  };

  const dotClass = STATUS_DOTS[scan.status] ?? 'bg-slate-500';

  return (
    <button
      type="button"
      onClick={() => onSelect(scan)}
      className={`w-full text-left px-4 py-3 border-b border-slate-800 transition-colors hover:bg-slate-800/60 ${
        isActive ? 'bg-slate-800 border-l-2 border-l-cyan-400' : ''
      }`}
      aria-label={`Scan ${scan.target} — ${scan.status}`}
    >
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${dotClass}`} />
          <span className="font-mono text-sm text-slate-200 truncate">
            {scan.target}
          </span>
        </div>
        <span className="text-xs text-slate-500 flex-shrink-0 ml-2">
          {formatDate(scan.created_at)}
        </span>
      </div>

      <div className="flex items-center justify-between text-xs text-slate-400 pl-4">
        <div className="flex items-center gap-3">
          <span>{scan.total_subdomains ?? 0} subs</span>
          <span>{scan.total_services ?? 0} svc</span>
          <span>{scan.total_cves ?? 0} CVEs</span>
        </div>
        <div className="flex items-center gap-2">
          {scan.overall_risk && (
            <span
              className="text-xs font-medium"
              style={{ color: SEVERITY_COLORS[scan.overall_risk] ?? SEVERITY_COLORS.info }}
            >
              {scan.overall_risk.toUpperCase()}
            </span>
          )}
          {scan.duration_seconds != null && (
            <span className="text-slate-500">{formatDuration(scan.duration_seconds)}</span>
          )}
        </div>
      </div>

      {/* Delete button */}
      <div className="flex justify-end mt-1">
        <span
          role="button"
          tabIndex={0}
          onClick={handleDelete}
          onKeyDown={(e) => e.key === 'Enter' && handleDelete(e)}
          className={`text-xs px-2 py-0.5 rounded cursor-pointer transition-colors ${
            confirmDelete
              ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
              : 'text-slate-600 hover:text-red-400 hover:bg-slate-800'
          }`}
        >
          {confirmDelete ? 'Sure?' : 'Delete'}
        </span>
      </div>
    </button>
  );
}

ScanRow.propTypes = {
  scan: PropTypes.shape({
    scan_id: PropTypes.string.isRequired,
    target: PropTypes.string.isRequired,
    status: PropTypes.string.isRequired,
    created_at: PropTypes.string,
    total_subdomains: PropTypes.number,
    total_services: PropTypes.number,
    total_cves: PropTypes.number,
    overall_risk: PropTypes.string,
    duration_seconds: PropTypes.number,
  }).isRequired,
  isActive: PropTypes.bool.isRequired,
  onSelect: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
};

/**
 * Scan history sidebar/panel.
 *
 * @param {{ scans: Array, activeScanId: string|null, onSelect: function, onDelete: function, onNewScan: function }} props
 */
export default function ScanHistory({ scans, activeScanId, onSelect, onDelete, onNewScan }) {
  const [collapsed, setCollapsed] = useState(false);

  if (collapsed) {
    return (
      <aside className="flex flex-col h-full bg-slate-900/50 border-r border-slate-800 w-10">
        <button
          type="button"
          onClick={() => setCollapsed(false)}
          className="flex items-center justify-center h-12 text-slate-400 hover:text-cyan-400 transition-colors border-b border-slate-800"
          aria-label="Show scan history"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
        {scans.length > 0 && (
          <div className="flex items-center justify-center mt-2">
            <span className="text-xs text-slate-500 [writing-mode:vertical-lr] rotate-180">
              {scans.length} Scans
            </span>
          </div>
        )}
      </aside>
    );
  }

  return (
    <aside className="flex flex-col h-full w-80 bg-slate-900/50 border-r border-slate-800">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCollapsed(true)}
            className="text-slate-400 hover:text-cyan-400 transition-colors"
            aria-label="Collapse scan history"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <h2 className="text-sm font-semibold text-slate-300">Scan History</h2>
        </div>
        <button
          type="button"
          onClick={onNewScan}
          className="text-xs px-3 py-1 rounded bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
        >
          + New Scan
        </button>
      </div>

      {/* Scan list */}
      <div className="flex-1 overflow-y-auto">
        {scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 text-sm px-4">
            <p>No scans yet.</p>
            <p className="text-xs mt-1">Start a new scan to get started.</p>
          </div>
        ) : (
          scans.map((scan) => (
            <ScanRow
              key={scan.scan_id}
              scan={scan}
              isActive={scan.scan_id === activeScanId}
              onSelect={onSelect}
              onDelete={onDelete}
            />
          ))
        )}
      </div>

      {/* Schedules */}
      <div className="border-t border-slate-800 px-4 py-3">
        <ScheduleList />
      </div>

      {/* Footer with count */}
      {scans.length > 0 && (
        <div className="px-4 py-2 border-t border-slate-800 text-xs text-slate-500 text-center">
          {scans.length} scan{scans.length !== 1 ? 's' : ''} saved
        </div>
      )}
    </aside>
  );
}

ScanHistory.propTypes = {
  scans: PropTypes.arrayOf(PropTypes.object).isRequired,
  activeScanId: PropTypes.string,
  onSelect: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  onNewScan: PropTypes.func.isRequired,
};

ScanHistory.defaultProps = {
  activeScanId: null,
};
