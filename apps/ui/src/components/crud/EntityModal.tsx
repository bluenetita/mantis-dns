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

import { Modal, type MantineSize } from "@mantine/core";
import type { ReactNode } from "react";

export interface EntityModalProps {
  opened: boolean;
  onClose: () => void;
  /** Caller computes "Add X" / "Edit X" from its own editing-entity state. */
  title: string;
  size?: MantineSize | number;
  children: ReactNode;
}

/**
 * Thin modal shell for the add/edit-entity pattern: one modal, title (and
 * children) swap based on whether the caller is creating or editing. The
 * form inside `children` owns its own save/cancel buttons and loading state.
 */
export function EntityModal({ opened, onClose, title, size = "lg", children }: EntityModalProps) {
  return (
    <Modal opened={opened} onClose={onClose} title={title} size={size}>
      {children}
    </Modal>
  );
}
