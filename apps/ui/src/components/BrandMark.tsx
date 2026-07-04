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

type BrandMarkProps = {
  size?: number;
};

export function BrandMark({ size = 22 }: BrandMarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <g transform="translate(0,5)">
        <g fill="none" stroke="#4c6ef5" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round">
          <polyline points="28,24 18,10 8,-2" />
          <polyline points="72,24 82,10 92,-2" />
        </g>
        <g stroke="#fff" strokeWidth={0.6} strokeLinejoin="round">
          <polygon points="8,40 28,24 50,46" fill="#748ffc" />
          <polygon points="8,40 50,46 26,56" fill="#4c6ef5" />
          <polygon points="92,40 72,24 50,46" fill="#748ffc" />
          <polygon points="92,40 50,46 74,56" fill="#4c6ef5" />
          <polygon points="26,56 50,46 50,92" fill="#4c6ef5" />
          <polygon points="74,56 50,46 50,92" fill="#3b5bdb" />
        </g>
      </g>
    </svg>
  );
}
