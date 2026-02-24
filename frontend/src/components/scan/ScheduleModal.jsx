/**
 * @file Modal for creating/editing scan schedules.
 *
 * Provides cron presets (daily, weekly, monthly) and a custom cron input
 * for power users.
 */

import React, { useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import { DEFAULT_MODULES } from '../../constants/config';
import { createSchedule } from '../../api/client';

const CRON_PRESETS = [
  { label: 'Daily (02:00 UTC)', value: '0 2 * * *' },
  { label: 'Weekly (Mon 02:00)', value: '0 2 * * 1' },
  { label: 'Monthly (1st of month)', value: '0 2 1 * *' },
  { label: 'Every 12 hours', value: '0 */12 * * *' },
  { label: 'Custom', value: 'custom' },
];

/**
 * Schedule creation modal.
 *
 * @param {{ onClose: () => void, onCreated: () => void }} props
 * @returns {React.ReactElement}
 */
export default function ScheduleModal({ onClose, onCreated }) {
  const [target, setTarget] = useState('');
  const [preset, setPreset] = useState(CRON_PRESETS[1].value);
  const [customCron, setCustomCron] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const cronValue = preset === 'custom' ? customCron : preset;

  const handleSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      if (!target.trim()) return;

      setLoading(true);
      setError(null);

      try {
        await createSchedule({
          target: target.trim().toLowerCase(),
          modules: DEFAULT_MODULES,
          cron_expression: cronValue,
        });
        onCreated();
        onClose();
      } catch (err) {
        setError(err.apiError?.message || 'Failed to create schedule.');
      } finally {
        setLoading(false);
      }
    },
    [target, cronValue, onCreated, onClose],
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-100">
            Create Scan Schedule
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors"
            aria-label="Close"
          >
            &times;
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Target domain */}
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">
              Target Domain
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
            />
          </div>

          {/* Cron preset */}
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-400">
              Interval
            </label>
            <select
              value={preset}
              onChange={(e) => setPreset(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 focus:border-cyan-400 focus:outline-none"
            >
              {CRON_PRESETS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          {/* Custom cron input */}
          {preset === 'custom' && (
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-400">
                Cron Expression (min hour dom mon dow)
              </label>
              <input
                type="text"
                value={customCron}
                onChange={(e) => setCustomCron(e.target.value)}
                placeholder="0 2 * * 1"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 font-mono text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
              />
            </div>
          )}

          {/* Current cron display */}
          <div className="rounded-lg bg-slate-800/60 p-2 text-center">
            <span className="text-xs text-slate-500">Cron: </span>
            <span className="font-mono text-xs text-cyan-400">{cronValue || '—'}</span>
          </div>

          {/* Error */}
          {error && (
            <p className="text-xs text-red-400">{error}</p>
          )}

          {/* Actions */}
          <div className="flex gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 rounded-lg border border-slate-700 bg-slate-800 py-2 text-sm text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !target.trim()}
              className="flex-1 rounded-lg bg-cyan-600 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50 transition-colors"
            >
              {loading ? 'Creating...' : 'Create Schedule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

ScheduleModal.propTypes = {
  /** Callback to close the modal. */
  onClose: PropTypes.func.isRequired,
  /** Callback after successful creation. */
  onCreated: PropTypes.func.isRequired,
};
