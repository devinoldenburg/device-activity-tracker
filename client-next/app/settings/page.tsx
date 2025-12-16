"use client";

import { TopBar } from '@/components/TopBar';
import { useTracker } from '@/components/TrackerProvider';
import { StatCard } from '@/components/StatCard';
import { Shield, Zap } from 'lucide-react';

export default function SettingsPage() {
  const { connectionState, connected, probeMethod, setProbeMethod } = useTracker();

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-8 py-8 space-y-6 max-w-5xl">
        <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Probing</p>
          <h2 className="text-2xl font-bold text-slate-900">Messmethode</h2>
          <p className="text-sm text-slate-600 mb-4">Wähle, wie die Probes geschickt werden. Delete ist covert, Reaction etwas sichtbar.</p>
          <div className="flex items-center gap-3">
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
