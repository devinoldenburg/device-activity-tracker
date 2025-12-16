"use client";

import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from 'react';
import { API_BASE } from '@/lib/socket';

export interface AuthUser {
  id: number;
  username: string;
  allowRegistration: boolean;
  role: 'admin' | 'user';
  status: 'pending' | 'approved';
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  error: string | null;
  allowRegistration: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  register: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [allowRegistration, setAllowRegistration] = useState<boolean>(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/me`, { credentials: 'include' });
      if (!res.ok) {
        setUser(null);
        setAllowRegistration(false);
        return;
      }
      const data = await res.json();
      setUser({ id: data.id, username: data.username, allowRegistration: data.allowRegistration, role: data.role, status: data.status });
      setAllowRegistration(Boolean(data.allowRegistration));
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    setError(null);
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'include'
    });
    if (!res.ok) {
      setError('Anmeldung fehlgeschlagen');
      return false;
    }
    const data = await res.json();
    setUser({ id: data.id, username: data.username, allowRegistration: data.allowRegistration, role: data.role, status: data.status });
    setAllowRegistration(Boolean(data.allowRegistration));
    return true;
  }, []);

  const register = useCallback(async (username: string, password: string) => {
    setError(null);
    const res = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'include'
    });
    if (!res.ok) {
      const msg = res.status === 403 ? 'Registrierung deaktiviert' : 'Registrierung fehlgeschlagen';
      setError(msg);
      return false;
    }
    const data = await res.json();
    setUser({ id: data.id, username: data.username, allowRegistration: data.allowRegistration, role: data.role, status: data.status });
    setAllowRegistration(Boolean(data.allowRegistration));
    return true;
  }, []);

  const logout = useCallback(async () => {
    await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST', credentials: 'include' });
    setUser(null);
  }, []);

  const value: AuthContextValue = {
    user,
    loading,
    error,
    allowRegistration,
    login,
    register,
    logout,
    refresh
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
