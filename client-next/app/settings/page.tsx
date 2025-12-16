"use client";

import { useState } from 'react';
import { TopBar } from '@/components/TopBar';
import { useTracker } from '@/components/TrackerProvider';
import { StatCard } from '@/components/StatCard';
import { Shield, Zap, RefreshCw, SlidersHorizontal, Power, PlugZap } from 'lucide-react';
import { API_BASE } from '@/lib/socket';

export default function SettingsPage() {
  const { connectionState, connected, probeMethod, setProbeMethod, platformEnabled, setPlatformEnabled, resetUserData, clearLocalPreferences } = useTracker();
  const [resetMessage, setResetMessage] = useState<string | null>(null);
  const [waMessage, setWaMessage] = useState<string | null>(null);
  const [sigMessage, setSigMessage] = useState<string | null>(null);

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-8 py-8 space-y-6 max-w-5xl">
        <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 space-y-3">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Probing</p>
          <h2 className="text-2xl font-bold text-slate-900">Messmethode & Taktik</h2>
          <p className="text-sm text-slate-600">Delete = leiser, Reaction = auffälliger. Wähle pro Nutzer-Session.</p>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setProbeMethod('delete')}
              className={`px-4 py-2 rounded-xl text-sm font-semibold border ${probeMethod === 'delete' ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-700 border-slate-200'}`}
            >
              Silent Delete
            </button>
            <button
              onClick={() => setProbeMethod('reaction')}
              className={`px-4 py-2 rounded-xl text-sm font-semibold border ${probeMethod === 'reaction' ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-700 border-slate-200'}`}
            >
              Reaction
            </button>
            <span className="inline-flex items-center gap-2 text-xs text-slate-500 px-3 py-1 rounded-lg bg-slate-100 border border-slate-200">
              <SlidersHorizontal size={14} /> Live umschaltbar
            </span>
          </div>
        </div>

        <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 space-y-3">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Plattformen</p>
          <h2 className="text-2xl font-bold text-slate-900">WhatsApp und Signal entkoppeln</h2>
          <p className="text-sm text-slate-600">Schalte jede Plattform separat frei. Deaktivierte Plattformen werden weder hinzugefügt noch angezeigt.</p>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setPlatformEnabled('whatsapp', !platformEnabled.whatsapp)}
              className={`px-4 py-2 rounded-xl text-sm font-semibold border ${platformEnabled.whatsapp ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-700 border-slate-200'}`}
            >
              WhatsApp {platformEnabled.whatsapp ? 'aktiv' : 'aus'}
            </button>
            <button
              onClick={() => setPlatformEnabled('signal', !platformEnabled.signal)}
              className={`px-4 py-2 rounded-xl text-sm font-semibold border ${platformEnabled.signal ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-700 border-slate-200'}`}
            >
              Signal {platformEnabled.signal ? 'aktiv' : 'aus'}
            </button>
            <button
              onClick={() => { setPlatformEnabled('whatsapp', false); setPlatformEnabled('signal', false); }}
              className="px-4 py-2 rounded-xl text-sm font-semibold border bg-white text-slate-700 border-slate-200 inline-flex items-center gap-2"
            >
              <Power size={14} /> Beide aus
            </button>
            <button
              onClick={async () => {
                setWaMessage('Trenne WhatsApp...');
                try {
                  const res = await fetch(`${API_BASE}/api/whatsapp/disconnect`, { method: 'POST', credentials: 'include' });
                  setWaMessage(res.ok ? 'WhatsApp getrennt. Bitte neu koppeln.' : 'Trennen fehlgeschlagen');
                } catch {
                  setWaMessage('Trennen fehlgeschlagen');
                }
                setTimeout(() => setWaMessage(null), 3000);
              }}
              className="px-4 py-2 rounded-xl text-sm font-semibold border bg-white text-slate-700 border-slate-200 inline-flex items-center gap-2"
            >
              <PlugZap size={14} /> WhatsApp trennen
            </button>
            <button
              onClick={async () => {
                setSigMessage('Trenne Signal...');
                try {
                  const res = await fetch(`${API_BASE}/api/signal/disconnect`, { method: 'POST', credentials: 'include' });
                  setSigMessage(res.ok ? 'Signal getrennt. Bitte neu koppeln.' : 'Trennen fehlgeschlagen');
                } catch {
                  setSigMessage('Trennen fehlgeschlagen');
                }
                setTimeout(() => setSigMessage(null), 3000);
              }}
              className="px-4 py-2 rounded-xl text-sm font-semibold border bg-white text-slate-700 border-slate-200 inline-flex items-center gap-2"
            >
              <PlugZap size={14} /> Signal trennen
            </button>
            {waMessage && <span className="text-sm text-slate-600">{waMessage}</span>}
            {sigMessage && <span className="text-sm text-slate-600">{sigMessage}</span>}
          </div>
        </div>

        <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 space-y-3">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Daten & Reset</p>
          <h2 className="text-2xl font-bold text-slate-900">Tracking-Daten zurücksetzen</h2>
          <p className="text-sm text-slate-600">Löscht deine Kontakte und Verlauf aus der Datenbank und stoppt alle aktiven Tracker.</p>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={async () => {
                const ok = await resetUserData();
                setResetMessage(ok ? 'Daten gelöscht und Tracker gestoppt' : 'Reset fehlgeschlagen');
                setTimeout(() => setResetMessage(null), 2500);
              }}
              className="px-4 py-2 rounded-xl text-sm font-semibold border bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100 inline-flex items-center gap-2"
            >
              <RefreshCw size={14} /> Reset ausführen
            </button>
            {resetMessage && <span className="text-sm text-slate-600">{resetMessage}</span>}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => { clearLocalPreferences(); setResetMessage('Lokale Einstellungen gelöscht'); setTimeout(() => setResetMessage(null), 2500); }}
              className="px-4 py-2 rounded-xl text-sm font-semibold border bg-white text-slate-700 border-slate-200 inline-flex items-center gap-2"
            >
              <SlidersHorizontal size={14} /> Lokale Einstellungen löschen
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <StatCard title="Datenschutz" value="Aliasing & Blur" hint="Aliase werden lokal gespeichert" accent="amber" icon={<Shield size={18} />} />
          <StatCard title="Probes" value="Sub-Second" hint="Schnellere Polls aktiv" accent="blue" icon={<Zap size={18} />} />
        </div>
      </main>
    </div>
  );
}
