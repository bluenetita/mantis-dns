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

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { apiClient, unwrap } from "../api/client";

export type Role = "admin" | "operator" | "viewer";

export interface AuthUser {
  id: string;
  email: string;
  role: Role;
  tenant_id: string | null;
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (...roles: Role[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // The session lives in an httpOnly cookie the browser attaches on its
    // own — just ask who we are; a 401 means there's no valid session.
    apiClient
      .GET("/api/v1/auth/me")
      .then((res) => {
        setUser(res.error || !res.data ? null : (res.data as AuthUser));
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = unwrap(
      await apiClient.POST("/api/v1/auth/login", { body: { email, password } })
    );
    setUser(res.user as AuthUser);
  }, []);

  const logout = useCallback(async () => {
    await apiClient.POST("/api/v1/auth/logout");
    setUser(null);
  }, []);

  const hasRole = useCallback(
    (...roles: Role[]) => {
      if (!user) return false;
      const minRank = Math.max(...roles.map((r) => ROLE_RANK[r]));
      return ROLE_RANK[user.role] >= minRank;
    },
    [user]
  );

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
