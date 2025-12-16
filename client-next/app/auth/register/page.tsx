"use client";

import { FormEvent, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/components/AuthProvider';

export default function RegisterPage() {
  const { register, user, loading, error, allowRegistration } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && !allowRegistration) router.replace('/auth/login');
  }, [allowRegistration, loading, router]);

  useEffect(() => {
    if (!loading && user) {
      router.replace('/');
    }
  }, [loading, user, router]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    const ok = await register(username.trim(), password);
    setSubmitting(false);
    if (ok) router.replace('/');
    else setMessage('Registrierung fehlgeschlagen');
  };

  return (
    <div className="w-full max-w-md bg-white shadow-xl rounded-2xl border border-slate-200/80 p-8 space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Device Tracker</p>
        <h1 className="text-2xl font-bold text-slate-900">Registrieren</h1>
        <p className="text-sm text-slate-600 mt-2">Neue Nutzer anlegen, falls freigeschaltet.</p>
      </div>
      {!allowRegistration ? (
        <div className="text-sm text-amber-700 bg-amber-50 border border-amber-100 rounded-lg px-3 py-2">
          Registrierung ist aktuell deaktiviert. Bitte Administrator kontaktieren.
        </div>
      ) : (
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
              autoComplete="new-password"
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
            disabled={submitting || !allowRegistration}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-slate-900 text-white font-semibold py-2.5 hover:bg-slate-800 disabled:opacity-60"
          >
            {submitting ? 'Registriere...' : 'Account beantragen'}
          </button>
        </form>
      )}
      <p className="text-sm text-slate-600">
        Bereits registriert?{' '}
        <Link href="/auth/login" className="text-sky-600 font-semibold hover:underline">Zum Login</Link>
      </p>
    </div>
  );
}
