/**
 * @file Horizontal tab bar for switching between result panels.
 *
 * Each tab can carry an optional count badge (e.g. number of findings)
 * and the active tab is highlighted with a cyan underline.
 */

import React from 'react';
import PropTypes from 'prop-types';

/**
 * Renders a row of selectable tabs.
 *
 * @param {{
 *   tabs: Array<{ id: string, label: string, count?: number }>,
 *   activeTab: string,
 *   onTabChange: (id: string) => void,
 * }} props
 * @returns {React.ReactElement}
 */
export default function TabNavigation({ tabs, activeTab, onTabChange }) {
  /**
   * Creates a click handler bound to a specific tab id.
   *
   * @param {string} id
   * @returns {() => void}
   */
  function handleTabClick(id) {
    return function onClickTab() {
      onTabChange(id);
    };
  }

  return (
    <nav
      className="flex gap-1 border-b border-slate-800"
      role="tablist"
      aria-label="Result panels"
    >
      {tabs.map((tab) => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={isActive}
            aria-controls={`panel-${tab.id}`}
            className={`relative px-4 py-2.5 text-sm font-medium transition-colors
              ${isActive ? 'text-cyan-400' : 'text-slate-400 hover:text-slate-200'}`}
            onClick={handleTabClick(tab.id)}
          >
            {tab.label}
            {tab.count != null && (
              <span
                className={`ml-2 inline-flex items-center justify-center rounded-full px-1.5 text-xs
                  ${isActive ? 'bg-cyan-400/15 text-cyan-400' : 'bg-slate-800 text-slate-500'}`}
              >
                {tab.count}
              </span>
            )}
            {isActive && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400 rounded-full" />
            )}
          </button>
        );
      })}
    </nav>
  );
}

TabNavigation.propTypes = {
  /** Ordered list of tab descriptors. */
  tabs: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      count: PropTypes.number,
    }),
  ).isRequired,
  /** `id` of the currently selected tab. */
  activeTab: PropTypes.string.isRequired,
  /** Callback invoked with the `id` of the newly selected tab. */
  onTabChange: PropTypes.func.isRequired,
};
