/**
 * @file Live scan progress display with module status indicators.
 *
 * Subscribes to WebSocket messages via the scan context to show
 * real-time module completion, an animated progress bar, and per-module
 * status icons (completed, running, pending).
 */

import React from 'react';
import { useScanContext } from '../../context/ScanContext';
import useWebSocket from '../../hooks/useWebSocket';
import LoadingSpinner from '../common/LoadingSpinner';

/** Map a module status to an icon element. */
function statusIcon(status) {
  if (status === 'completed') {
    return (
      <span className="text-green-400" aria-label="Completed">
        &#x2713;
      </span>
    );
  }
  if (status === 'running') {
    return <LoadingSpinner size="sm" />;
  }
  return (
    <span className="text-slate-600" aria-label="Pending">
      &#x25CB;
    </span>
  );
}

/**
 * Determine each module's status from the progress object.
 *
 * @param {object} progress
 * @returns {Array<{ id: string, status: string }>}
 */
function deriveModuleStates(progress) {
  if (!progress) return [];

  const completed = new Set(progress.modules_completed ?? []);
  const pending = progress.modules_pending ?? [];
  const current = progress.current_module;

  const ordered = [
    ...Array.from(completed),
    ...(current && !completed.has(current) ? [current] : []),
    ...pending.filter((m) => m !== current),
  ];

  return ordered.map((id) => {
    if (completed.has(id)) return { id, status: 'completed' };
    if (id === current) return { id, status: 'running' };
    return { id, status: 'pending' };
  });
}

/**
 * Renders the real-time progress of the current scan.
 *
 * @returns {React.ReactElement}
 */
export default function ScanProgress() {
  const { state } = useScanContext();
  const { currentScan } = state;

  useWebSocket(currentScan?.scan_id ?? null);

  const progress = currentScan?.progress;
  const percentage = progress?.percentage ?? 0;
  const modules = deriveModuleStates(progress);

  return (
    <section
      className="mx-auto max-w-xl animate-fade-in rounded-xl border border-slate-800 bg-slate-900/60 p-6"
      aria-label="Scan progress"
    >
      <h2 className="mb-4 text-lg font-semibold text-slate-100">
        Scanning <span className="text-cyan-400">{currentScan?.target}</span>
      </h2>

      {/* Progress bar */}
      <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
        <span>Progress</span>
        <span>{percentage}%</span>
      </div>
      <div className="mb-6 h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-cyan-400 transition-all duration-500"
          style={{ width: `${percentage}%` }}
          role="progressbar"
          aria-valuenow={percentage}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Scan ${percentage}% complete`}
        />
      </div>

      {/* Module list */}
      <ul className="space-y-2" aria-label="Module statuses">
        {modules.map(({ id, status }) => (
          <li
            key={id}
            className={`flex items-center gap-3 rounded-lg border px-4 py-2 text-sm ${
              status === 'running'
                ? 'border-cyan-800 bg-cyan-900/20 text-cyan-300'
                : status === 'completed'
                  ? 'border-slate-700 bg-slate-800/40 text-slate-300'
                  : 'border-slate-800 bg-slate-800/20 text-slate-500'
            }`}
          >
            {statusIcon(status)}
            <span className="font-mono">{id}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
