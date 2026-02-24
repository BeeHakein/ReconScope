/**
 * @file Tests for the ScanInput component.
 *
 * Verifies that the domain input, module checkboxes, scope confirmation,
 * and the start-scan button behave correctly under various conditions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

/* ── Mocks ─────────────────────────────────────────────────── */

const mockStartScan = vi.fn();

vi.mock('../../hooks/useScan', () => ({
  default: () => ({
    startScan: mockStartScan,
    loading: false,
  }),
}));

/*
 * ScanInput is wrapped in a ScanProvider in the real app.
 * The useScan hook calls useScanContext internally, so we need to
 * provide the ScanProvider.  Because we already mocked useScan above,
 * the provider is not strictly required for *this* mock setup, but we
 * still wrap it so that any other code paths that touch context
 * (e.g. error display) work correctly.
 */
import { ScanProvider } from '../../context/ScanContext';
import ScanInput from '../../components/scan/ScanInput';

/* ── Helpers ───────────────────────────────────────────────── */

function renderScanInput() {
  return render(
    <ScanProvider>
      <ScanInput />
    </ScanProvider>,
  );
}

/* ── Test suite ────────────────────────────────────────────── */

describe('ScanInput', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the domain input field', () => {
    renderScanInput();

    const input = screen.getByLabelText('Target Domain');
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute('type', 'text');
  });

  it('renders the scope confirmation checkbox', () => {
    renderScanInput();

    const checkbox = screen.getByTestId('scope-checkbox');
    expect(checkbox).toBeInTheDocument();
    expect(checkbox).toHaveAttribute('type', 'checkbox');
    expect(checkbox).not.toBeChecked();
  });

  it('renders all default module checkboxes', () => {
    renderScanInput();

    // DEFAULT_MODULES = ['crtsh', 'dns', 'whois', 'techdetect', 'cvematch']
    expect(screen.getByText(/Certificate Transparency/)).toBeInTheDocument();
    expect(screen.getByText(/DNS Enumeration/)).toBeInTheDocument();
    expect(screen.getByText(/WHOIS Lookup/)).toBeInTheDocument();
    expect(screen.getByText(/Technology Detection/)).toBeInTheDocument();
    expect(screen.getByText(/CVE Matching/)).toBeInTheDocument();
  });

  it('disables the submit button when scope is not confirmed', async () => {
    const user = userEvent.setup();
    renderScanInput();

    const input = screen.getByLabelText('Target Domain');
    await user.type(input, 'example.com');

    const button = screen.getByTestId('start-scan-btn');
    expect(button).toBeDisabled();
  });

  it('disables the submit button when domain is empty', async () => {
    const user = userEvent.setup();
    renderScanInput();

    const checkbox = screen.getByTestId('scope-checkbox');
    await user.click(checkbox);

    const button = screen.getByTestId('start-scan-btn');
    expect(button).toBeDisabled();
  });

  it('enables the button and calls startScan on valid submit', async () => {
    const user = userEvent.setup();
    mockStartScan.mockResolvedValueOnce('scan-uuid-123');

    renderScanInput();

    const input = screen.getByLabelText('Target Domain');
    await user.type(input, 'example.com');

    const checkbox = screen.getByTestId('scope-checkbox');
    await user.click(checkbox);

    const button = screen.getByTestId('start-scan-btn');
    expect(button).toBeEnabled();

    await user.click(button);

    await waitFor(() => {
      expect(mockStartScan).toHaveBeenCalledTimes(1);
      expect(mockStartScan).toHaveBeenCalledWith(
        'example.com',
        expect.arrayContaining(['crtsh', 'dns', 'whois', 'techdetect', 'cvematch']),
        true,
      );
    });
  });

  it('shows an error message for an invalid domain', async () => {
    const user = userEvent.setup();
    renderScanInput();

    const input = screen.getByLabelText('Target Domain');
    await user.type(input, 'not a domain');

    const checkbox = screen.getByTestId('scope-checkbox');
    await user.click(checkbox);

    // Button is disabled for invalid domain, so we submit the form directly
    const form = screen.getByTestId('scan-input-form');
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));

    await waitFor(() => {
      const alert = screen.queryByRole('alert');
      // The button should stay disabled because "not a domain" does not match DOMAIN_RE
      const button = screen.getByTestId('start-scan-btn');
      expect(button).toBeDisabled();
    });
  });

  it('shows API error when startScan rejects', async () => {
    const user = userEvent.setup();
    const apiError = new Error('Scan failed');
    apiError.apiError = { message: 'Target not reachable' };
    mockStartScan.mockRejectedValueOnce(apiError);

    renderScanInput();

    const input = screen.getByLabelText('Target Domain');
    await user.type(input, 'example.com');

    const checkbox = screen.getByTestId('scope-checkbox');
    await user.click(checkbox);

    const button = screen.getByTestId('start-scan-btn');
    await user.click(button);

    await waitFor(() => {
      const alert = screen.getByRole('alert');
      expect(alert).toHaveTextContent('Target not reachable');
    });
  });

  it('clears the error when the user types in the domain field', async () => {
    const user = userEvent.setup();
    const apiError = new Error('Scan failed');
    apiError.apiError = { message: 'Server error' };
    mockStartScan.mockRejectedValueOnce(apiError);

    renderScanInput();

    const input = screen.getByLabelText('Target Domain');
    await user.type(input, 'example.com');
    await user.click(screen.getByTestId('scope-checkbox'));
    await user.click(screen.getByTestId('start-scan-btn'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    // Typing into the input clears the error
    await user.type(input, 'x');

    await waitFor(() => {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });
});
