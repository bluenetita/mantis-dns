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

import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi, type MockedFunction } from 'vitest';
import { useBlockPageTemplate, useUpsertBlockPageTemplate } from '../../api/hooks';
import { BlockPageCard } from '../BlockPageCard';
import { renderWithProviders } from '../../test/utils';

vi.mock('../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/hooks')>();
  return {
    ...actual,
    useBlockPageTemplate: vi.fn(),
    useUpsertBlockPageTemplate: vi.fn(),
  };
});

const mockUseTemplate = useBlockPageTemplate as MockedFunction<typeof useBlockPageTemplate>;
const mockUseUpsert = useUpsertBlockPageTemplate as MockedFunction<typeof useUpsertBlockPageTemplate>;
const mutate = vi.fn();

beforeEach(() => {
  mockUseTemplate.mockReset();
  mockUseUpsert.mockReset();
  mutate.mockReset();
  mockUseTemplate.mockReturnValue({ data: null } as never);
  mockUseUpsert.mockReturnValue({ mutate, isPending: false } as never);
});

describe('BlockPageCard', () => {
  it('hides redirect fields and preview in NXDOMAIN mode', () => {
    mockUseTemplate.mockReturnValue({ data: null } as never); // default NXDOMAIN
    renderWithProviders(<BlockPageCard groupId="g1" canEdit />);
    expect(screen.queryByLabelText('Redirect IPv4')).toBeNull();
    expect(screen.queryByTitle('Block page preview')).toBeNull();
  });

  it('shows redirect fields and preview in REDIRECT mode', () => {
    mockUseTemplate.mockReturnValue({
      data: {
        block_mode: 'BLOCK_MODE_REDIRECT',
        redirect_ipv4: '10.0.0.53',
        redirect_ipv6: null,
        ttl_seconds: 30,
        title: null,
        message: null,
        logo_url: null,
        brand_color: null,
        contact_url: null,
        show_domain: true,
        show_category: true,
      },
    } as never);
    renderWithProviders(<BlockPageCard groupId="g1" canEdit />);
    expect(screen.getByLabelText('Redirect IPv4')).toBeInTheDocument();
    expect(screen.getByTitle('Block page preview')).toBeInTheDocument();
  });

  it('escapes branding values in the live preview (no HTML injection)', () => {
    mockUseTemplate.mockReturnValue({
      data: {
        block_mode: 'BLOCK_MODE_REDIRECT',
        redirect_ipv4: '10.0.0.53',
        redirect_ipv6: null,
        ttl_seconds: 30,
        title: '<script>evil()</script>',
        message: null,
        logo_url: null,
        brand_color: null,
        contact_url: null,
        show_domain: true,
        show_category: true,
      },
    } as never);

    renderWithProviders(<BlockPageCard groupId="g1" canEdit />);
    const iframe = screen.getByTitle('Block page preview') as HTMLIFrameElement;
    expect(iframe.srcdoc).toContain('&lt;script&gt;');
    expect(iframe.srcdoc).not.toContain('<script>evil');
  });

  it('blocks save when REDIRECT has no redirect IP', () => {
    mockUseTemplate.mockReturnValue({
      data: {
        block_mode: 'BLOCK_MODE_REDIRECT',
        redirect_ipv4: null,
        redirect_ipv6: null,
        ttl_seconds: 30,
        title: null,
        message: null,
        logo_url: null,
        brand_color: null,
        contact_url: null,
        show_domain: true,
        show_category: true,
      },
    } as never);

    renderWithProviders(<BlockPageCard groupId="g1" canEdit />);
    expect(screen.getByRole('button', { name: 'Save block page' })).toBeDisabled();
    expect(screen.getByText('Set an IPv4 or IPv6 address')).toBeInTheDocument();
  });

  it('saves the current form via the upsert mutation', async () => {
    mockUseTemplate.mockReturnValue({
      data: {
        block_mode: 'BLOCK_MODE_REDIRECT',
        redirect_ipv4: '10.0.0.53',
        redirect_ipv6: null,
        ttl_seconds: 30,
        title: 'Blocked',
        message: null,
        logo_url: null,
        brand_color: null,
        contact_url: null,
        show_domain: true,
        show_category: true,
      },
    } as never);

    renderWithProviders(<BlockPageCard groupId="g1" canEdit />);
    await userEvent.click(screen.getByRole('button', { name: 'Save block page' }));
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    expect(mutate.mock.calls[0][0]).toMatchObject({
      block_mode: 'BLOCK_MODE_REDIRECT',
      redirect_ipv4: '10.0.0.53',
    });
  });

  it('hides the save button for non-editors', () => {
    mockUseTemplate.mockReturnValue({ data: null } as never);
    renderWithProviders(<BlockPageCard groupId="g1" canEdit={false} />);
    expect(screen.queryByRole('button', { name: 'Save block page' })).toBeNull();
  });
});
