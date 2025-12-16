"use client";

import { FormEvent, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/components/AuthProvider';
import { API_BASE } from '@/lib/socket';

export default function LoginPage() {
  const { login, user, loading, error, allowRegistration } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [requestSubmitting, setRequestSubmitting] = useState(false);
  const [requestMessage, setRequestMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && user) {
      router.replace('/');
    }
  }, [loading, user, router]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    const ok = await login(username.trim(), password);
    setSubmitting(false);
    if (ok) router.replace('/');
    else setMessage('Login fehlgeschlagen oder Account noch nicht freigegeben');
  };

  const handleRequestAccount = async () => {
    setRequestMessage(null);
    const trimmed = username.trim();
    if (!trimmed || !password) {
      setRequestMessage('Bitte Benutzername und gewünschtes Passwort ausfüllen.');
      return;
    }

    setRequestSubmitting(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username: trimmed, password })
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 202) {
        setRequestMessage('Anfrage eingegangen. Du wirst nach Freischaltung informiert.');
      } else if (res.status === 409) {
        setRequestMessage('Benutzer existiert bereits.');
      } else if (res.status === 400 || res.status === 429) {
        setRequestMessage(data?.message || 'Anfrage abgelehnt. Bitte Eingaben prüfen.');
      } else {
        setRequestMessage('Anfrage fehlgeschlagen. Bitte später erneut versuchen.');
      }
    } catch (err) {
      setRequestMessage('Anfrage fehlgeschlagen. Bitte später erneut versuchen.');
    } finally {
      setRequestSubmitting(false);
    }
  };

  return (
    <div className="w-full max-w-md bg-white shadow-xl rounded-2xl border border-slate-200/80 p-8 space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Device Tracker</p>
        <h1 className="text-2xl font-bold text-slate-900">Anmelden</h1>
        <p className="text-sm text-slate-600 mt-2">Zugriff nur für registrierte Nutzer. Cookies sind erforderlich.</p>
      </div>
      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="space-y-2">
          <label className="text-sm font-semibold text-slate-700">Benutzername</label>
          <input
            className="w-full rounded-xl border border-slate-200 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-sky-400"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
        </div>
        <div className="space-y-2">
          <label className="text-sm font-semibold text-slate-700">Passwort</label>
          <input
            className="w-full rounded-xl border border-slate-200 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-sky-400"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </div>
        {(error || message) && (
          <div className="text-sm text-rose-600 bg-rose-50 border border-rose-100 rounded-lg px-3 py-2">
            {error || message}
          </div>
        )}
        <button
          type="submit"
          disabled={submitting}
          className="w-full flex items-center justify-center gap-2 rounded-xl bg-slate-900 text-white font-semibold py-2.5 hover:bg-slate-800 disabled:opacity-60"
        >
          {submitting ? 'Anmelden...' : 'Login'}
        </button>
      </form>
      {allowRegistration ? (
        <p className="text-sm text-slate-600">
          Noch kein Konto?{' '}
          <Link href="/auth/register" className="text-sky-600 font-semibold hover:underline">Registrieren</Link>
        </p>
      ) : (
        <div className="space-y-3 text-sm text-slate-600">
          <p className="text-slate-600">Noch kein Konto? Registrierung ist deaktiviert. Du kannst eine Freischaltung anfragen:</p>
          <button
            type="button"
            onClick={handleRequestAccount}
            disabled={requestSubmitting}
            className="w-full flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white text-slate-900 font-semibold py-2.5 hover:border-slate-300 disabled:opacity-60"
          >
            {requestSubmitting ? 'Sende Anfrage...' : 'Account-Anfrage senden'}
          </button>
          {requestMessage && (
            <div className="text-sm text-sky-700 bg-sky-50 border border-sky-100 rounded-lg px-3 py-2">{requestMessage}</div>
          )}
        </div>
      )}
    </div>
  );
}
