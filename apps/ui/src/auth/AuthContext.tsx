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

const TOKEN_KEY = "aegis_token";

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (...roles: Role[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    apiClient
      .GET("/api/v1/auth/me")
      .then((res) => {
        if (res.error || !res.data) {
          localStorage.removeItem(TOKEN_KEY);
          setToken(null);
          setUser(null);
        } else {
          setUser(res.data as AuthUser);
        }
      })
      .finally(() => setLoading(false));
  }, [token]);

  const login = useCallback(async (email: string, password: string) => {
    const res = unwrap(
      await apiClient.POST("/api/v1/auth/login", { body: { email, password } })
    );
    localStorage.setItem(TOKEN_KEY, res.access_token);
    setToken(res.access_token);
    setUser(res.user as AuthUser);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
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
    <AuthContext.Provider value={{ user, token, loading, login, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}
