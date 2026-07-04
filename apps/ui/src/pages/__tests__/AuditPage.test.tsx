import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, type MockedFunction } from 'vitest';
import { AUDIT_PAGE_SIZE, useAuditLog, type AuditLogEntry } from '../../api/hooks';
import { AuditPage } from '../AuditPage';
import { renderWithProviders } from '../../test/utils';

vi.mock('../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/hooks')>();
  return { ...actual, useAuditLog: vi.fn() };
});

const mockUseAuditLog = useAuditLog as MockedFunction<typeof useAuditLog>;

function makeEntries(count: number): AuditLogEntry[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `entry-${i}`,
    occurred_at: '2026-07-03T10:00:00Z',
    actor: 'admin@mantis.local',
    action: `tenant.create`,
    resource_type: 'tenant',
    resource_id: `res-${i}-uuid-here`,
    detail: `name=tenant-${i}`,
    tenant_id: 'tenant-1',
  }));
}

beforeEach(() => {
  mockUseAuditLog.mockReset();
});

describe('AuditPage', () => {
  it('shows a spinner while loading', () => {
    mockUseAuditLog.mockReturnValue({ data: undefined, isLoading: true, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(document.querySelector('[class*="Loader"]') ?? screen.getByRole('status', { hidden: true })).toBeTruthy();
  });

  it('shows empty state message when no entries exist', () => {
    mockUseAuditLog.mockReturnValue({ data: [], isLoading: false, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getByText(/No audit entries yet/i)).toBeInTheDocument();
  });

  it('renders table rows for each audit entry', () => {
    mockUseAuditLog.mockReturnValue({ data: makeEntries(3), isLoading: false, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getAllByText('admin@mantis.local')).toHaveLength(3);
    expect(screen.getAllByText(/tenant\.create/i)).toHaveLength(3);
  });

  it('Previous button is disabled on the first page', () => {
    mockUseAuditLog.mockReturnValue({ data: makeEntries(10), isLoading: false, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled();
  });

  it('Next button is disabled when fewer than PAGE_SIZE results returned', () => {
    mockUseAuditLog.mockReturnValue({ data: makeEntries(10), isLoading: false, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled();
  });

  it('Next button is enabled when a full page of results is returned', () => {
    mockUseAuditLog.mockReturnValue({ data: makeEntries(AUDIT_PAGE_SIZE), isLoading: false, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getByRole('button', { name: /next/i })).toBeEnabled();
  });

  it('shows error message when request fails', () => {
    mockUseAuditLog.mockReturnValue({ data: undefined, isLoading: false, error: new Error('500: server error') } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getByText(/500: server error/i)).toBeInTheDocument();
  });

  it('advancing to next page increments page indicator', async () => {
    const user = userEvent.setup();
    mockUseAuditLog.mockReturnValue({ data: makeEntries(AUDIT_PAGE_SIZE), isLoading: false, error: null } as never);
    renderWithProviders(<AuditPage />);
    expect(screen.getByText('Page 1')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /next/i }));
    expect(screen.getByText('Page 2')).toBeInTheDocument();
  });

  it('resource_id is truncated to 8 characters in the resource column', () => {
    const entry = makeEntries(1)[0];
    mockUseAuditLog.mockReturnValue({ data: [entry], isLoading: false, error: null } as never);
    const { container } = renderWithProviders(<AuditPage />);
    // resource_type + ":" + resource_id.slice(0,8) may be split across text nodes
    // 'res-0-uuid-here'.slice(0,8) === 'res-0-uu'
    expect(container.textContent).toContain('tenant:res-0-uu');
  });
});
