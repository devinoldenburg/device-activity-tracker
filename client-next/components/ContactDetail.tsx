"use client";

import { useCallback, useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import { Activity, Clock, Download, Gauge, MessageCircle, Monitor, Pencil, Radio, RefreshCw, Trash2, Wifi } from 'lucide-react';
import { ContactInfo, ProbeMethod } from '@/lib/types';
import { HistoryChart } from './HistoryChart';

interface ContactDetailProps {
  contact: ContactInfo;
  onRemove: () => void;
  onRefresh: () => void;
  loading?: boolean;
  probeMethod: ProbeMethod;
  onProbeChange: (method: ProbeMethod) => void;
  onAliasChange: (alias: string) => void;
}

export function ContactDetail({ contact, onRemove, onRefresh, loading, probeMethod, onProbeChange, onAliasChange }: ContactDetailProps) {
  const [aliasDraft, setAliasDraft] = useState(contact.displayNumber);

  useEffect(() => {
    setAliasDraft(contact.contactName || contact.displayNumber);
  }, [contact.contactName, contact.displayNumber, contact.jid]);

  const last = contact.data[contact.data.length - 1];
  const staleAfterMs = 30_000;
  const isStale = contact.updatedAt ? (Date.now() - contact.updatedAt > staleAfterMs) : false;
  const baseStatus = contact.devices.find(d => (d.state || '').includes('Online'))?.state || contact.devices[0]?.state || last?.state || 'Unknown';
  const status = isStale ? 'STALE / CHECK DEVICE' : baseStatus;
  const avgDay = useMemo(() => averageSince(contact.data, 24), [contact.data]);
  const avgWeek = useMemo(() => averageSince(contact.data, 24 * 7), [contact.data]);
  const avg15m = useMemo(() => averageSince(contact.data, 0.25), [contact.data]);
  const jitter = useMemo(() => computeJitter(contact.data), [contact.data]);
  const samples = contact.data.length;
  const lastUpdateLabel = contact.updatedAt ? timeAgo(contact.updatedAt) : '—';

  const PlatformIcon = contact.platform === 'signal' ? Radio : MessageCircle;

  const exportCsv = useCallback(() => {
    if (!contact.data.length) return;
    const header = 'timestamp_iso,timestamp,rtt,avg,median,threshold,state\n';
    const rows = contact.data.map(p => `${new Date(p.timestamp).toISOString()},${p.timestamp},${p.rtt},${p.avg},${p.median},${p.threshold},${p.state}`);
    const blob = new Blob([header + rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${contact.displayNumber.replace(/\D/g, '') || 'contact'}-history.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }, [contact.data, contact.displayNumber]);

  return (
    <div className="glass-card rounded-3xl p-4 md:p-6 space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className={clsx(
            'h-14 w-14 rounded-2xl flex items-center justify-center text-white shadow-lift',
            contact.platform === 'signal' ? 'bg-gradient-to-br from-sky-400 to-blue-600' : 'bg-gradient-to-br from-emerald-400 to-green-600'
          )}>
            <PlatformIcon size={20} />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Aktiver Nutzer</p>
            <p className="text-2xl font-bold text-slate-900">{contact.contactName || contact.displayNumber}</p>
            <p className="text-sm text-slate-600">{contact.displayNumber}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={aliasDraft}
            onChange={(e) => setAliasDraft(e.target.value)}
            placeholder="Alias setzen"
            className="px-3 py-2 rounded-xl border border-slate-200 text-sm bg-white min-w-[180px] flex-1"
          />
          <button
            onClick={() => aliasDraft && onAliasChange(aliasDraft)}
            className="px-3 py-2 rounded-xl bg-slate-900 text-white text-sm font-semibold hover:bg-black flex items-center gap-2"
          >
            <Pencil size={14} /> Speichern
          </button>
          <button
            onClick={onRefresh}
            className="px-3 py-2 rounded-xl bg-slate-100 text-slate-700 text-sm font-semibold hover:bg-slate-200 flex items-center gap-2"
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            History
          </button>
          <button
            onClick={exportCsv}
            className="px-3 py-2 rounded-xl bg-white text-slate-700 text-sm font-semibold border border-slate-200 hover:bg-slate-50 flex items-center gap-2"
            disabled={!contact.data.length}
          >
            <Download size={14} /> CSV
          </button>
          <button
            onClick={onRemove}
            className="px-3 py-2 rounded-xl bg-rose-600 text-white text-sm font-semibold hover:bg-rose-700 flex items-center gap-2"
          >
            <Trash2 size={14} /> Stop
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Status" value={status} icon={<Wifi size={16} />} tone={status.includes('Online') && !isStale ? 'green' : isStale ? 'slate' : 'slate'} />
        <Stat label="Letzte RTT" value={last ? `${Math.round(last.rtt)} ms` : '–'} icon={<Gauge size={16} />} />
        <Stat label="Ø letzte 24h" value={avgDay ? `${avgDay} ms` : '–'} icon={<Clock size={16} />} />
        <Stat label="Ø letzte 7d" value={avgWeek ? `${avgWeek} ms` : '–'} icon={<Clock size={16} />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white rounded-2xl border border-slate-200 p-4 space-y-3 shadow-sm">
          <h4 className="text-sm font-semibold text-slate-700 flex items-center gap-2"><Activity size={16} /> Aktuelle Geräte</h4>
          <div className="space-y-2">
            {contact.devices.map((device, idx) => (
              <div key={device.jid} className="flex items-center justify-between px-3 py-2 rounded-xl bg-slate-50 border border-slate-100">
                <div className="flex items-center gap-2">
                  <Monitor size={14} className="text-slate-500" />
                  <span className="text-sm font-medium text-slate-800">Device {idx + 1}</span>
                </div>
                <span className={clsx(
                  'text-xs px-2 py-1 rounded-lg font-semibold',
                  device.state === 'OFFLINE' ? 'bg-rose-100 text-rose-700' :
                  (device.state || '').includes('Online') ? 'bg-emerald-100 text-emerald-700' :
                  device.state === 'Standby' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'
                )}>
                  {device.state}
                </span>
              </div>
            ))}
            {contact.devices.length === 0 && (
              <p className="text-sm text-slate-500">Keine aktiven Geräte gemeldet.</p>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span className="h-2 w-2 rounded-full bg-emerald-400" /> Client ACK / Online
            <span className="h-2 w-2 rounded-full bg-amber-400" /> Standby
            <span className="h-2 w-2 rounded-full bg-rose-400" /> Offline
          </div>
        </div>

        <div className="lg:col-span-2 bg-white rounded-2xl border border-slate-200 p-4 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-semibold text-slate-700">Probe-Methode</h4>
            <div className="flex items-center gap-2">
              {(['delete', 'reaction'] as ProbeMethod[]).map(method => (
                <button
                  key={method}
                  onClick={() => onProbeChange(method)}
                  className={clsx(
                    'px-3 py-1.5 rounded-lg text-xs font-semibold border',
                    probeMethod === method
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white text-slate-700 border-slate-200 hover:border-slate-300'
                  )}
                >
                  {method === 'delete' ? 'Silent Delete' : 'Reaction' }
                </button>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <MetricBox label="Avg" value={last ? `${last.avg.toFixed(0)} ms` : '–'} />
            <MetricBox label="Median" value={last ? `${last.median.toFixed(0)} ms` : '–'} />
            <MetricBox label="Threshold" value={last ? `${last.threshold.toFixed(0)} ms` : '–'} highlight />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-3">
            <MetricBox label="Ø letzte 15m" value={avg15m ? `${avg15m} ms` : '–'} />
            <MetricBox label="Jitter" value={jitter ? `${jitter} ms` : '–'} />
            <MetricBox label="Samples" value={`${samples}`} />
          </div>
          <div className="mt-3 text-xs text-slate-500">Zuletzt aktualisiert: {lastUpdateLabel}</div>
          <div className="mt-4">
            {isStale && (
              <div className="mb-3 px-3 py-2 rounded-xl bg-amber-50 text-amber-700 text-sm border border-amber-200">
                Keine aktuellen Daten (&gt;30s). Gerät prüfen oder Verbindung neu laden.
              </div>
            )}
            <HistoryChart data={contact.data} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, icon, tone = 'slate' }: { label: string; value: string; icon?: any; tone?: 'green' | 'slate'; }) {
  return (
    <div className={clsx('p-4 rounded-2xl border shadow-sm bg-white flex items-center justify-between', tone === 'green' ? 'border-emerald-200 bg-emerald-50/60' : 'border-slate-200')}>
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</p>
        <p className="text-xl font-semibold text-slate-900">{value}</p>
      </div>
      {icon && <div className="h-10 w-10 rounded-xl bg-slate-900 text-white flex items-center justify-center">{icon}</div>}
    </div>
  );
}

function MetricBox({ label, value, highlight }: { label: string; value: string; highlight?: boolean; }) {
  return (
    <div className={clsx('p-3 rounded-xl border text-sm font-semibold', highlight ? 'border-rose-200 bg-rose-50 text-rose-700' : 'border-slate-200 bg-white text-slate-900')}>
      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</p>
      <p className="text-lg font-bold">{value}</p>
    </div>
  );
}

function averageSince(data: any[], hours: number) {
  const cutoff = Date.now() - hours * 60 * 60 * 1000;
  const slice = data.filter(p => p.timestamp >= cutoff);
  if (!slice.length) return null;
  const sum = slice.reduce((acc, p) => acc + (p.avg ?? 0), 0);
  return Math.round(sum / slice.length);
}

function computeJitter(data: any[]) {
  if (!data.length) return null;
  const window = data.slice(-200);
  const mean = window.reduce((acc, p) => acc + (p.rtt ?? 0), 0) / window.length;
  const variance = window.reduce((acc, p) => acc + Math.pow((p.rtt ?? 0) - mean, 2), 0) / window.length;
  return Math.round(Math.sqrt(variance));
}

function timeAgo(ts: number) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return `${Math.max(1, Math.round(diff / 1000))}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}
