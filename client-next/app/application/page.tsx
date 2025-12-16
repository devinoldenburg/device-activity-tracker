"use client";

import { useEffect, useState } from 'react';
import { TopBar } from '@/components/TopBar';
import { useTracker } from '@/components/TrackerProvider';
import { useAuth } from '@/components/AuthProvider';
import { API_BASE } from '@/lib/socket';
import { Shield, CheckCircle2, XCircle, UserCog } from 'lucide-react';
import Link from 'next/link';

interface AdminUserRow {
  id: number;
  username: string;
  createdAt: number;
  role: 'admin' | 'user';
  status: 'pending' | 'approved';
}

export default function ApplicationPage() {
  const { connectionState, connected } = useTracker();
  const { user, refresh } = useAuth();
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = user?.role === 'admin';

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/admin/users`, { credentials: 'include' });
      if (!res.ok) {
        setError('Konnte Nutzer nicht laden');
        setLoading(false);
        return;
      }
      const data = await res.json();
      setUsers(data as AdminUserRow[]);
    } catch {
      setError('Konnte Nutzer nicht laden');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAdmin) load();
  }, [isAdmin]);

  const updateStatus = async (id: number, status: 'approved' | 'pending', role?: 'admin' | 'user') => {
    setError(null);
    const res = await fetch(`${API_BASE}/api/admin/users/${id}/${status === 'approved' ? 'approve' : 'pending'}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
      credentials: 'include'
    });
    if (!res.ok) {
      setError('Update fehlgeschlagen');
      return;
    }
    await load();
    if (user?.id === id) refresh();
  };

  const deleteUser = async (id: number) => {
    if (!confirm('Account wirklich löschen?')) return;
    setError(null);
    const res = await fetch(`${API_BASE}/api/admin/users/${id}`, { method: 'DELETE', credentials: 'include' });
    if (!res.ok) {
      setError('Löschen fehlgeschlagen');
      return;
    }
    await load();
  };

  if (!isAdmin) {
    return (
      <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
        <TopBar connection={connectionState} connected={connected} />
        <main className="p-8">
          <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6">
            <p className="text-sm text-slate-700">Nur Admins können diesen Bereich sehen.</p>
            <Link href="/" className="text-sky-600 font-semibold hover:underline">Zurück zum Dashboard</Link>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-4 md:px-8 py-6 max-w-6xl">
        <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 space-y-3">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Applications</p>
          <h2 className="text-2xl font-bold text-slate-900">Nutzer freischalten & Rollen</h2>
          <p className="text-sm text-slate-600">Prüfe neue Registrierungen, setze Rollen, lösche oder sperre Accounts.</p>
          {error && <div className="text-sm text-rose-700 bg-rose-50 border border-rose-100 rounded-lg px-3 py-2">{error}</div>}
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 border-b border-slate-200">
                  <th className="py-2 pr-4">User</th>
                  <th className="py-2 pr-4">Rolle</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Aktionen</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td className="py-4 text-slate-500" colSpan={4}>Lade...</td></tr>
                ) : users.length === 0 ? (
                  <tr><td className="py-4 text-slate-500" colSpan={4}>Keine Nutzer gefunden.</td></tr>
                ) : (
                  users.map(u => (
                    <tr key={u.id} className="border-b border-slate-100">
                      <td className="py-3 pr-4 font-semibold text-slate-800">{u.username}</td>
                      <td className="py-3 pr-4">
                        <select
                          value={u.role}
                          onChange={(e) => updateStatus(u.id, u.status, e.target.value as 'admin' | 'user')}
                          className="rounded-lg border border-slate-200 px-2 py-1 text-sm"
                          disabled={u.id === 1}
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                        </select>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold ${u.status === 'approved' ? 'bg-emerald-50 text-emerald-700 border border-emerald-100' : 'bg-amber-50 text-amber-700 border border-amber-100'}`}>
                          {u.status === 'approved' ? <CheckCircle2 size={14} /> : <Shield size={14} />} {u.status}
                        </span>
                      </td>
                      <td className="py-3 pr-4 space-x-2">
                        {u.status === 'pending' && (
                          <button
                            onClick={() => updateStatus(u.id, 'approved', u.role)}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-emerald-600 text-white text-xs font-semibold"
                            disabled={u.id === 1}
                          >
                            <CheckCircle2 size={14} /> Freigeben
                          </button>
                        )}
                        {u.status === 'approved' && (
                          <button
                            onClick={() => updateStatus(u.id, 'pending', u.role)}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-amber-100 text-amber-800 text-xs font-semibold border border-amber-200"
                            disabled={u.id === 1}
                          >
                            <Shield size={14} /> Sperren
                          </button>
                        )}
                        {u.id !== 1 && (
                          <button
                            onClick={() => deleteUser(u.id)}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-rose-50 text-rose-700 text-xs font-semibold border border-rose-200"
                          >
                            <XCircle size={14} /> Löschen
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-2"><UserCog size={14} /> Admins können sich nicht selbst löschen.</div>
        </div>
      </main>
    </div>
  );
}
