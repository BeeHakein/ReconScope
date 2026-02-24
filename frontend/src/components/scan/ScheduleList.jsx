/**
 * @file Schedule list showing active and inactive scan schedules.
 *
 * Displays schedules with toggle and delete controls. Includes a
 * button to open the ScheduleModal for creating new schedules.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { getSchedules, updateSchedule, deleteSchedule } from '../../api/client';
import ScheduleModal from './ScheduleModal';

/**
 * Schedule management panel.
 *
 * @returns {React.ReactElement}
 */
export default function ScheduleList() {
  const [schedules, setSchedules] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(false);

  const fetchSchedules = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await getSchedules();
      setSchedules(data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSchedules();
  }, [fetchSchedules]);

  const handleToggle = useCallback(async (id, isActive) => {
    try {
      await updateSchedule(id, { is_active: !isActive });
      fetchSchedules();
    } catch {
      // silently fail
    }
  }, [fetchSchedules]);

  const handleDelete = useCallback(async (id) => {
    try {
      await deleteSchedule(id);
      setSchedules((prev) => prev.filter((s) => s.id !== id));
    } catch {
      // silently fail
    }
  }, []);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-slate-300">Schedules</h3>
        <button
          type="button"
          onClick={() => setShowModal(true)}
          className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs text-cyan-400 hover:bg-slate-700 transition-colors"
        >
          + New
        </button>
      </div>

      {loading && schedules.length === 0 && (
        <p className="text-xs text-slate-500">Loading schedules...</p>
      )}

      {!loading && schedules.length === 0 && (
        <p className="text-xs text-slate-500">No schedules yet.</p>
      )}

      <div className="space-y-2">
        {schedules.map((s) => (
          <div
            key={s.id}
            className={`flex items-center gap-3 rounded-lg border p-3 transition-colors ${
              s.is_active
                ? 'border-slate-700 bg-slate-800/60'
                : 'border-slate-800 bg-slate-900/40 opacity-60'
            }`}
          >
            {/* Toggle */}
            <button
              type="button"
              onClick={() => handleToggle(s.id, s.is_active)}
              className={`h-5 w-9 rounded-full transition-colors ${
                s.is_active ? 'bg-cyan-500' : 'bg-slate-600'
              }`}
              aria-label={s.is_active ? 'Deactivate' : 'Activate'}
            >
              <span
                className={`block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                  s.is_active ? 'translate-x-4' : 'translate-x-0.5'
                }`}
              />
            </button>

            {/* Details */}
            <div className="flex-1 min-w-0">
              <p className="truncate text-sm font-medium text-slate-200">
                {s.target}
              </p>
              <p className="text-xs text-slate-500">
                <span className="font-mono">{s.cron_expression}</span>
                {s.next_run_at && (
                  <span className="ml-2">
                    Next run: {new Date(s.next_run_at).toLocaleString('en-US')}
                  </span>
                )}
              </p>
            </div>

            {/* Delete */}
            <button
              type="button"
              onClick={() => handleDelete(s.id)}
              className="text-xs text-slate-500 hover:text-red-400 transition-colors"
              aria-label="Delete schedule"
            >
              &times;
            </button>
          </div>
        ))}
      </div>

      {/* Create modal */}
      {showModal && (
        <ScheduleModal
          onClose={() => setShowModal(false)}
          onCreated={fetchSchedules}
        />
      )}
    </div>
  );
}
