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

/**
 * api/client.ts sits outside the React tree and can't call useNavigate, so a
 * 401 can't redirect in-app directly. It notifies this listener instead;
 * AuthContext clears its user, and RequireAuth's existing
 * `<Navigate state={{ from: location.pathname }}>` takes it from there —
 * same in-app redirect a plain expired-session render already gets, instead
 * of a window.location.assign() that reloads the page and drops the route
 * the user was on.
 */
let listener: (() => void) | null = null;

export function onSessionExpired(cb: () => void): () => void {
  listener = cb;
  return () => {
    if (listener === cb) listener = null;
  };
}

export function notifySessionExpired(): void {
  listener?.();
}
