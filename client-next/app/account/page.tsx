"use client";

import { FormEvent, useState } from 'react';
import { TopBar } from '@/components/TopBar';
import { useTracker } from '@/components/TrackerProvider';
import { useAuth } from '@/components/AuthProvider';
import { API_BASE } from '@/lib/socket';
import { ShieldCheck, KeyRound } from 'lucide-react';

export default function AccountPage() {
  const { connectionState, connected } = useTracker();
  const { user, refresh } = useAuth();

  const [username, setUsername] = useState(user?.username || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleUsername = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    const res = await fetch(`${API_BASE}/api/account/username`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: currentPassword }),
      credentials: 'include'
    });
    setBusy(false);
    if (!res.ok) {
      const text = await res.json().catch(() => ({}));
      setError(text.message || 'Update fehlgeschlagen');
      return;
    }
    setMessage('Benutzername aktualisiert');
    setCurrentPassword('');
    refresh();
    setTimeout(() => setMessage(null), 2500);
  };

  const handlePassword = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    if (newPassword !== newPassword2) {
      setBusy(false);
      setError('Passwörter stimmen nicht überein');
      return;
    }
    const res = await fetch(`${API_BASE}/api/account/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword }),
      credentials: 'include'
    });
    setBusy(false);
    if (!res.ok) {
      const text = await res.json().catch(() => ({}));
      setError(text.message || 'Passwort konnte nicht geändert werden');
      return;
    }
    setMessage('Passwort aktualisiert');
    setCurrentPassword('');
    setNewPassword('');
    setNewPassword2('');
    setTimeout(() => setMessage(null), 2500);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-8 py-8 space-y-6 max-w-4xl">
        <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 space-y-4">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Profil</p>
          <h2 className="text-2xl font-bold text-slate-900">Account & Sicherheit</h2>
          <p className="text-sm text-slate-600">Passe deinen Anzeigenamen an und setze ein neues Passwort. Änderungen gelten sofort.</p>

          {error && <div className="text-sm text-rose-700 bg-rose-50 border border-rose-100 rounded-lg px-3 py-2">{error}</div>}
          {message && <div className="text-sm text-emerald-700 bg-emerald-50 border border-emerald-100 rounded-lg px-3 py-2">{message}</div>}

          <form className="space-y-3" onSubmit={handleUsername}>
            <div className="flex items-center gap-3 text-sm font-semibold text-slate-800">
              <ShieldCheck size={16} /> Benutzername ändern
            </div>
            <div className="grid md:grid-cols-2 gap-3">
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-xl border border-slate-200 px-3 py-2"
                placeholder="Neuer Benutzername"
                autoComplete="username"
                required
              />
              <input
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full rounded-xl border border-slate-200 px-3 py-2"
                placeholder="Aktuelles Passwort"
                type="password"
                autoComplete="current-password"
                required
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 text-white font-semibold hover:bg-slate-800 disabled:opacity-60"
            >
              Speichern
            </button>
          </form>

          <hr className="border-slate-200" />

          <form className="space-y-3" onSubmit={handlePassword}>
            <div className="flex items-center gap-3 text-sm font-semibold text-slate-800">
              <KeyRound size={16} /> Passwort ändern
            </div>
            <div className="grid md:grid-cols-3 gap-3">
              <input
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full rounded-xl border border-slate-200 px-3 py-2"
                placeholder="Aktuelles Passwort"
                type="password"
                autoComplete="current-password"
                required
              />
              <input
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full rounded-xl border border-slate-200 px-3 py-2"
                placeholder="Neues Passwort"
                type="password"
                autoComplete="new-password"
                required
              />
              <input
                value={newPassword2}
                onChange={(e) => setNewPassword2(e.target.value)}
                className="w-full rounded-xl border border-slate-200 px-3 py-2"
                placeholder="Neues Passwort (Wiederholen)"
                type="password"
                autoComplete="new-password"
                required
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 text-white font-semibold hover:bg-slate-800 disabled:opacity-60"
            >
              Passwort speichern
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}
