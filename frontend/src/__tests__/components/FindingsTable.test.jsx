/**
 * @file Tests for the FindingsTable component.
 *
 * Covers rendering of findings rows, sort toggling by severity and
 * risk_score, the empty-state message, and expandable row details.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';
import FindingsTable from '../../components/findings/FindingsTable';

/* ── Sample data ───────────────────────────────────────────── */

const SAMPLE_FINDINGS = [
  {
    id: '1',
    severity: 'critical',
    title: 'RCE on staging',
    asset: 'staging.example.com',
    risk_score: 95,
    cvss_score: 9.8,
    description: 'Remote code execution via deserialization flaw',
    evidence: { url: 'https://staging.example.com/rce' },
  },
  {
    id: '2',
    severity: 'high',
    title: 'SQL Injection',
    asset: 'api.example.com',
    risk_score: 78,
    cvss_score: 8.1,
    description: 'SQL injection in user search endpoint',
    evidence: {},
  },
  {
    id: '3',
    severity: 'low',
    title: 'Information Disclosure',
    asset: 'www.example.com',
    risk_score: 25,
    cvss_score: 3.1,
    description: 'Server version header exposed',
    evidence: {},
  },
  {
    id: '4',
    severity: 'medium',
    title: 'Missing CSP header',
    asset: 'app.example.com',
    risk_score: 45,
    cvss_score: 5.3,
    description: 'Content-Security-Policy header is missing',
    evidence: {},
  },
];

/* ── Test suite ────────────────────────────────────────────── */

describe('FindingsTable', () => {
  it('renders all finding rows from sample data', () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    expect(screen.getByText('RCE on staging')).toBeInTheDocument();
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.getByText('Information Disclosure')).toBeInTheDocument();
    expect(screen.getByText('Missing CSP header')).toBeInTheDocument();
  });

  it('renders severity badges for each finding', () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    const badges = screen.getAllByTestId('severity-badge');
    expect(badges.length).toBe(SAMPLE_FINDINGS.length);

    const badgeTexts = badges.map((b) => b.textContent);
    expect(badgeTexts).toContain('CRITICAL');
    expect(badgeTexts).toContain('HIGH');
    expect(badgeTexts).toContain('MEDIUM');
    expect(badgeTexts).toContain('LOW');
  });

  it('renders asset names', () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    expect(screen.getByText('staging.example.com')).toBeInTheDocument();
    expect(screen.getByText('api.example.com')).toBeInTheDocument();
    expect(screen.getByText('www.example.com')).toBeInTheDocument();
    expect(screen.getByText('app.example.com')).toBeInTheDocument();
  });

  it('renders risk scores', () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    expect(screen.getByText('95')).toBeInTheDocument();
    expect(screen.getByText('78')).toBeInTheDocument();
    expect(screen.getByText('25')).toBeInTheDocument();
    expect(screen.getByText('45')).toBeInTheDocument();
  });

  it('sorts by severity when the Severity column header is clicked', async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    // Default sort is risk_score desc: 95, 78, 45, 25
    const sortBtn = screen.getByRole('button', { name: /sort by severity/i });
    await user.click(sortBtn);

    // After clicking severity, sort is severity desc (critical=0 is
    // first in desc => actually desc means info first, critical last;
    // but the component starts desc which means numerically descending
    // i.e. info(4) first, critical(0) last).
    // Let's verify the ordering by looking at the table rows
    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row');

    // rows[0] = header row, rows[1..4] = data rows
    // desc on severity => info(4)=largest -> first, then low(3), medium(2), high(1), critical(0)
    const dataRows = rows.slice(1);
    expect(dataRows.length).toBe(4);

    // Second click toggles to ascending: critical, high, medium, low, info
    await user.click(sortBtn);

    const rowsAfterAsc = within(table).getAllByRole('row');
    const dataRowsAsc = rowsAfterAsc.slice(1);
    // asc: critical(0) first
    expect(within(dataRowsAsc[0]).getByText('CRITICAL')).toBeInTheDocument();
  });

  it('sorts by risk_score when the Risk Score column header is clicked', async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    // Default is risk_score desc: 95, 78, 45, 25
    const table = screen.getByRole('table');
    let rows = within(table).getAllByRole('row');
    let firstDataRow = rows[1];
    expect(within(firstDataRow).getByText('95')).toBeInTheDocument();

    // Click Risk Score to toggle to ascending
    const sortBtn = screen.getByRole('button', { name: /sort by risk score/i });
    await user.click(sortBtn);

    rows = within(table).getAllByRole('row');
    firstDataRow = rows[1];
    expect(within(firstDataRow).getByText('25')).toBeInTheDocument();
  });

  it('displays "No findings to display." when given an empty array', () => {
    render(<FindingsTable findings={[]} />);

    expect(screen.getByText(/no findings to display/i)).toBeInTheDocument();
  });

  it('expands a row to show the description when clicked', async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    // The description should not be visible initially
    expect(screen.queryByText('Remote code execution via deserialization flaw')).not.toBeInTheDocument();

    // Click the RCE finding row
    const rceTitle = screen.getByText('RCE on staging');
    await user.click(rceTitle.closest('tr'));

    // The expanded detail should now show the description
    expect(screen.getByText('Remote code execution via deserialization flaw')).toBeInTheDocument();
  });

  it('collapses an expanded row when it is clicked again', async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    const rceRow = screen.getByText('RCE on staging').closest('tr');

    // Expand
    await user.click(rceRow);
    expect(screen.getByText('Remote code execution via deserialization flaw')).toBeInTheDocument();

    // Collapse
    await user.click(rceRow);
    expect(screen.queryByText('Remote code execution via deserialization flaw')).not.toBeInTheDocument();
  });

  it('shows evidence JSON in expanded row when evidence is present', async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    const rceRow = screen.getByText('RCE on staging').closest('tr');
    await user.click(rceRow);

    // The evidence contains { url: "https://staging.example.com/rce" }
    expect(screen.getByText(/staging\.example\.com\/rce/)).toBeInTheDocument();
  });

  it('only expands one row at a time', async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    // Expand the first finding
    await user.click(screen.getByText('RCE on staging').closest('tr'));
    expect(screen.getByText('Remote code execution via deserialization flaw')).toBeInTheDocument();

    // Expand the second finding
    await user.click(screen.getByText('SQL Injection').closest('tr'));
    expect(screen.getByText('SQL injection in user search endpoint')).toBeInTheDocument();

    // First finding should be collapsed
    expect(screen.queryByText('Remote code execution via deserialization flaw')).not.toBeInTheDocument();
  });

  it('displays all column headers', () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);

    expect(screen.getByText('Severity')).toBeInTheDocument();
    expect(screen.getByText('Title')).toBeInTheDocument();
    expect(screen.getByText('Asset')).toBeInTheDocument();
    expect(screen.getByText('Risk Score')).toBeInTheDocument();
    expect(screen.getByText('CVSS')).toBeInTheDocument();
  });
});
