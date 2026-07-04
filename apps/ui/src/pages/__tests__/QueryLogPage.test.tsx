/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, type MockedFunction } from 'vitest';
import { QUERY_LOG_PAGE_SIZE, useQueryLog, type QueryLogEntry } from '../../api/hooks';
import { QueryLogPage } from '../QueryLogPage';
import { renderWithProviders } from '../../test/utils';

vi.mock('../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/hooks')>();
  return { ...actual, useQueryLog: vi.fn() };
});

const mockUseQueryLog = useQueryLog as MockedFunction<typeof useQueryLog>;

function makeEvents(count: number, decision: 'allow' | 'block' = 'block'): QueryLogEntry[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `evt-${i}`,
    occurred_at: '2026-07-03T12:00:00Z',
    group_id: 'grp-uuid',
    group_name: 'test-group',
    tenant_id: 'ten-1',
    client_ip: `10.0.0.${i + 1}`,
    client_name: null,
    qname: `domain-${i}.example.com`,
    qtype: 'A',
    decision,
    matched_rule: null,
    matched_category: decision === 'block' ? 'malware' : null,
    matched_feed_id: null,
    response_code: 'NXDOMAIN',
    cache_hit: false,
    latency_us: 1500,
  }));
}

beforeEach(() => {
  mockUseQueryLog.mockReset();
});

describe('QueryLogPage', () => {
  it('renders the title and filter controls', () => {
    mockUseQueryLog.mockReturnValue({ data: [], isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByRole('heading', { name: /query log/i })).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /search domain/i })).toBeInTheDocument();
    // Two "All" radios exist: one in the decision filter, one in the hours filter
    expect(screen.getAllByRole('radio', { name: /^all$/i })).toHaveLength(2);
    expect(screen.getByRole('radio', { name: /blocked/i })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /allowed/i })).toBeInTheDocument();
  });

  it('shows empty state when no events match', () => {
    mockUseQueryLog.mockReturnValue({ data: [], isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByText(/No DNS events match/i)).toBeInTheDocument();
  });

  it('renders one table row per event', () => {
    mockUseQueryLog.mockReturnValue({ data: makeEvents(3), isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getAllByText(/domain-\d+\.example\.com/)).toHaveLength(3);
  });

  it('shows block badge for blocked events', () => {
    mockUseQueryLog.mockReturnValue({ data: makeEvents(1, 'block'), isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByText('block')).toBeInTheDocument();
  });

  it('shows allow badge for allowed events', () => {
    mockUseQueryLog.mockReturnValue({ data: makeEvents(1, 'allow'), isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByText('allow')).toBeInTheDocument();
  });

  it('displays latency in ms when >= 1000µs', () => {
    mockUseQueryLog.mockReturnValue({ data: makeEvents(1), isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByText('1.5ms')).toBeInTheDocument();
  });

  it('shows "—" for null latency', () => {
    const events = makeEvents(1);
    events[0].latency_us = null;
    mockUseQueryLog.mockReturnValue({ data: events, isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('Next button disabled when fewer than PAGE_SIZE results', () => {
    mockUseQueryLog.mockReturnValue({ data: makeEvents(5), isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled();
  });

  it('Next button enabled when a full page returned', () => {
    mockUseQueryLog.mockReturnValue({ data: makeEvents(QUERY_LOG_PAGE_SIZE), isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByRole('button', { name: /next/i })).toBeEnabled();
  });

  it('clicking Blocked filter re-renders with decision=block call', async () => {
    const user = userEvent.setup();
    mockUseQueryLog.mockReturnValue({ data: [], isLoading: false, error: null } as never);
    renderWithProviders(<QueryLogPage />);
    await user.click(screen.getByRole('radio', { name: /blocked/i }));
    const lastCall = mockUseQueryLog.mock.calls.at(-1)?.[0];
    expect(lastCall?.decision).toBe('block');
  });

  it('shows error message when request fails', () => {
    mockUseQueryLog.mockReturnValue({ data: undefined, isLoading: false, error: new Error('503: upstream') } as never);
    renderWithProviders(<QueryLogPage />);
    expect(screen.getByText(/503: upstream/i)).toBeInTheDocument();
  });
});
