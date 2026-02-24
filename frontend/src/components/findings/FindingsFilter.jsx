/**
 * @file Filter controls for the findings table.
 *
 * Provides severity checkboxes, a text search field, and a sort
 * direction toggle so users can narrow down the findings list.
 */

import React from 'react';
import PropTypes from 'prop-types';
import { SEVERITY_COLORS } from '../../constants/colors';

/** Severity levels rendered as filter checkboxes. */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Findings filter toolbar.
 *
 * @param {{
 *   filters: { severities: string[], search: string, sortDir: 'asc'|'desc' },
 *   onFilterChange: (next: object) => void,
 * }} props
 * @returns {React.ReactElement}
 */
export default function FindingsFilter({ filters, onFilterChange }) {
  const { severities = SEVERITIES, search = '', sortDir = 'desc' } = filters;

  /** Toggle a severity in/out of the active set. */
  function handleSeverityToggle(sev) {
    const next = severities.includes(sev)
      ? severities.filter((s) => s !== sev)
      : [...severities, sev];
    onFilterChange({ ...filters, severities: next });
  }

  /** Update the search query. */
  function handleSearchChange(e) {
    onFilterChange({ ...filters, search: e.target.value });
  }

  /** Flip the sort direction. */
  function handleSortToggle() {
    onFilterChange({
      ...filters,
      sortDir: sortDir === 'asc' ? 'desc' : 'asc',
    });
  }

  return (
    <div
      className="flex flex-wrap items-center gap-4 rounded-lg border border-slate-800 bg-slate-900/60 p-3"
      aria-label="Findings filters"
    >
      {/* Severity checkboxes */}
      <fieldset className="flex flex-wrap gap-2">
        <legend className="sr-only">Filter by severity</legend>
        {SEVERITIES.map((sev) => {
          const active = severities.includes(sev);
          const color = SEVERITY_COLORS[sev];
          return (
            <label
              key={sev}
              className={`flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium uppercase transition-colors ${
                active
                  ? 'border-transparent'
                  : 'border-slate-700 text-slate-500'
              }`}
              style={
                active
                  ? { color, backgroundColor: `${color}20`, borderColor: color }
                  : undefined
              }
            >
              <input
                type="checkbox"
                checked={active}
                onChange={function onToggle() { handleSeverityToggle(sev); }}
                className="sr-only"
                aria-label={`Toggle ${sev} severity`}
              />
              {sev}
            </label>
          );
        })}
      </fieldset>

      {/* Search */}
      <div className="relative flex-1 min-w-[180px]">
        <input
          type="text"
          value={search}
          onChange={handleSearchChange}
          placeholder="Search title or asset..."
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
          aria-label="Search findings"
        />
      </div>

      {/* Sort toggle */}
      <button
        type="button"
        onClick={handleSortToggle}
        className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
        aria-label={`Sort ${sortDir === 'asc' ? 'descending' : 'ascending'}`}
      >
        Sort {sortDir === 'asc' ? '\u2191' : '\u2193'}
      </button>
    </div>
  );
}

FindingsFilter.propTypes = {
  /** Current filter state. */
  filters: PropTypes.shape({
    severities: PropTypes.arrayOf(PropTypes.string),
    search: PropTypes.string,
    sortDir: PropTypes.oneOf(['asc', 'desc']),
  }).isRequired,
  /** Callback receiving the updated filter object. */
  onFilterChange: PropTypes.func.isRequired,
};
