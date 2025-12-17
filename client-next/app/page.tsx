"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, BarChart3, CheckCircle, History, MessageCircle } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { TopBar } from '@/components/TopBar';
import { StatCard } from '@/components/StatCard';
import { useTracker } from '@/components/TrackerProvider';
import { API_BASE } from '@/lib/socket';

export default function HomePage() {
  const {
    connectionState,
    connected,
    contacts,
  } = useTracker();

  const [totalMetrics, setTotalMetrics] = useState<number | null>(null);

  useEffect(() => {
    async function loadMetrics() {
      try {
        const res = await fetch(`${API_BASE}/api/stats/metrics`, { credentials: 'include' });
        if (!res.ok) return;
        const data = await res.json();
        setTotalMetrics(data.total ?? 0);
      } catch {
        /* ignore transient errors */
      }
    }

    loadMetrics();
  }, []);

  const tracked = contacts.length;
  const online = contacts.filter(c => c.devices.some(d => (d.state || '').includes('Online'))).length;
  const whatsappCount = tracked;

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-4 md:px-8 py-8 space-y-8">
        <section className="relative overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-lift">
          <div className="absolute inset-0 bg-gradient-to-br from-sky-400/10 via-emerald-300/10 to-purple-400/10" />
          <div className="relative p-6 md:p-8 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 md:gap-8">
            <div className="max-w-2xl space-y-3">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Realtime Monitoring</p>
              <h1 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight">High-Frequency Device Activity, neu gedacht</h1>
              <p className="text-base md:text-lg text-slate-600">Schnellere Probes, bessere Timeline, selektive Detailansicht: Nur der Nutzer, den du auswählst, wird geladen und live aktualisiert.</p>
              <div className="flex flex-wrap items-center gap-3">
                <Link href="/users" className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 text-white font-semibold shadow-lift hover:bg-black">
                  Nutzer öffnen <ArrowRight size={16} />
                </Link>
                <Link href="/settings" className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-slate-900 font-semibold border border-slate-200 shadow-sm">
                  Settings
                </Link>
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-3 gap-4 min-w-[260px] w-full sm:max-w-2xl">
              <StatCard title="Tracking" value={`${tracked}`} hint="aktive Kontakte" accent="blue" icon={<History size={18} />} />
              <StatCard title="Online" value={`${online}`} hint="aktuell online" accent="green" icon={<CheckCircle size={18} />} />
              <StatCard title="WhatsApp" value={`${whatsappCount}`} hint="tracked" accent="slate" icon={<MessageCircle size={18} />} />
              <StatCard title="Metrics" value={totalMetrics === null ? '…' : `${totalMetrics}`} hint="gesamt erfasst" accent="green" icon={<BarChart3 size={18} />} />
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ConnectCard
            title="WhatsApp"
            connected={connectionState.whatsapp}
            qr={connectionState.whatsappQr}
            accent="emerald"
            description="Öffne WhatsApp > Einstellungen > Verknüpfte Geräte und scanne den Code."
          />
        </section>
      </main>
    </div>
  );
}

function ConnectCard({ title, connected, qr, accent, description, extra }: { title: string; connected: boolean; qr: string | null; accent: 'emerald' | 'sky'; description: string; extra?: string; }) {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Verbindung</p>
          <p className="text-xl font-bold text-slate-900">{title}</p>
        </div>
        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${connected ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'}`}>
          {connected ? 'Verbunden' : 'QR scannen'}
        </span>
      </div>
      {connected ? (
        <div className="rounded-2xl bg-slate-50 border border-slate-100 p-6 text-center">
          <CheckCircle className="mx-auto mb-3" size={48} color={accent === 'emerald' ? '#10b981' : '#0ea5e9'} />
          <p className="text-lg font-semibold text-slate-800">Verbunden</p>
          {extra && <p className="text-sm text-slate-600 mt-1">{extra}</p>}
        </div>
      ) : (
        <div className="rounded-2xl bg-slate-50 border border-dashed border-slate-200 p-6 flex items-center justify-center min-h-[240px]">
          {qr ? <QRCodeSVG value={qr} size={180} /> : <p className="text-slate-500">Warte auf QR...</p>}
        </div>
      )}
      <p className="text-sm text-slate-600">{description}</p>
    </div>
  );
}
