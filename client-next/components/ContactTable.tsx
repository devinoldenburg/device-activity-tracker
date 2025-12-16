"use client";

import { useMemo, useState } from 'react';
import clsx from 'clsx';
import { ArrowDownUp, Clock, MessageCircle, Radio } from 'lucide-react';
import { ContactInfo } from '@/lib/types';

interface ContactTableProps {
  contacts: ContactInfo[];
  onSelect: (jid: string) => void;
  selectedJid: string | null;
}

type SortKey = 'updatedAt' | 'state' | 'avg' | 'rtt';

export function ContactTable({ contacts, onSelect, selectedJid }: ContactTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('updatedAt');
  const [desc, setDesc] = useState(true);

  const rows = useMemo(() => {
    const enriched = contacts.map((c) => {
      const last = c.data[c.data.length - 1];
      const updatedAt = c.updatedAt || last?.timestamp || 0;
      const stale = updatedAt ? (Date.now() - updatedAt > 30_000) : false;
      const state = stale ? 'STALE / CHECK' : (c.devices.find(d => (d.state || '').includes('Online'))?.state || c.devices[0]?.state || last?.state || 'Unknown');
      return {
        ...c,
        last,
        state,
        updatedAt,
        avg: last?.avg ?? 0,
        rtt: last?.rtt ?? 0,
        stale,
      };
    });

    const sorted = [...enriched].sort((a, b) => {
      const factor = desc ? -1 : 1;
      switch (sortKey) {
        case 'state':
          return factor * a.state.localeCompare(b.state);
        case 'avg':
          return factor * ((a.avg || 0) - (b.avg || 0));
        case 'rtt':
          return factor * ((a.rtt || 0) - (b.rtt || 0));
        default:
          return factor * ((a.updatedAt || 0) - (b.updatedAt || 0));
      }
    });

    return sorted;
  }, [contacts, desc, sortKey]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setDesc(!desc);
    } else {
      setSortKey(key);
      setDesc(true);
    }
  };

  return (
    <div className="bg-white rounded-3xl border border-slate-200 shadow-lift p-4 md:p-5">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Alle Kontakte</p>
          <p className="text-sm text-slate-600">Live-Stand, letzte RTT/Avg, sortierbar</p>
        </div>
        <button
          onClick={() => toggleSort('updatedAt')}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-200 text-sm font-semibold text-slate-700 hover:bg-slate-50"
        >
          <ArrowDownUp size={14} /> Sort: {label(sortKey)} {desc ? '↓' : '↑'}
        </button>
      </div>

      {/* Mobile cards */}
      <div className="md:hidden space-y-3">
        {rows.map((row) => (
          <button
            key={row.jid}
            onClick={() => onSelect(row.jid)}
            className={clsx(
              'w-full text-left rounded-2xl border p-4 shadow-sm transition',
              selectedJid === row.jid ? 'bg-slate-900 text-white border-slate-900' : 'bg-white border-slate-200 hover:border-slate-300'
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-1">
                <p className="text-base font-semibold leading-tight">{row.contactName || row.displayNumber}</p>
                <p className={clsx('text-xs', selectedJid === row.jid ? 'text-slate-200' : 'text-slate-500')}>{row.displayNumber}</p>
                <div className="flex items-center gap-2">
                  <span className={clsx(
                    'inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11px] font-semibold',
                    row.platform === 'signal' ? 'bg-sky-50 text-sky-700' : 'bg-emerald-50 text-emerald-700'
                  )}>
                    {row.platform === 'signal' ? <Radio size={12} /> : <MessageCircle size={12} />}
                    {row.platform === 'signal' ? 'Signal' : 'WhatsApp'}
                  </span>
                  <StatusPill state={row.state} inverted={selectedJid === row.jid} stale={row.stale} />
                </div>
              </div>
              <div className="text-right space-y-1 text-sm">
                <div className="font-semibold">{row.rtt ? `${Math.round(row.rtt)} ms` : '—'} RTT</div>
                <div className="text-slate-500 text-xs">Avg {row.avg ? `${Math.round(row.avg)} ms` : '—'}</div>
                <div className="text-slate-500 text-xs">Thresh {row.last?.threshold ? `${Math.round(row.last.threshold)} ms` : '—'}</div>
                <div className="text-[11px] text-slate-500 flex items-center gap-1 justify-end">
                  <Clock size={11} /> {row.updatedAt ? timeAgo(row.updatedAt) : '—'}
                </div>
              </div>
            </div>
          </button>
        ))}
        {rows.length === 0 && (
          <div className="text-center text-slate-500 text-sm py-6">Keine Daten vorhanden.</div>
        )}
      </div>

      {/* Desktop table */}
      <div className="hidden md:block overflow-x-auto scrollbar-thin">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-slate-500 border-b border-slate-200">
              <th className="py-2 pr-3">Kontakt</th>
              <th className="py-2 pr-3">Plattform</th>
              <th className="py-2 pr-3 cursor-pointer" onClick={() => toggleSort('state')}>Status</th>
              <th className="py-2 pr-3 cursor-pointer" onClick={() => toggleSort('rtt')}>RTT</th>
              <th className="py-2 pr-3 cursor-pointer" onClick={() => toggleSort('avg')}>Avg</th>
              <th className="py-2 pr-3">Median</th>
              <th className="py-2 pr-3">Threshold</th>
              <th className="py-2 pr-3 cursor-pointer" onClick={() => toggleSort('updatedAt')}>Zuletzt</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.jid}
                onClick={() => onSelect(row.jid)}
                className={clsx(
                  'border-b border-slate-100 hover:bg-slate-50 transition cursor-pointer',
                  selectedJid === row.jid && 'bg-slate-900 text-white hover:bg-slate-900/90'
                )}
              >
                <td className="py-2 pr-3 font-semibold">
                  <div className="flex flex-col">
                    <span>{row.contactName || row.displayNumber}</span>
                    <span className={clsx('text-xs', selectedJid === row.jid ? 'text-slate-200' : 'text-slate-500')}>
                      {row.displayNumber}
                    </span>
                  </div>
                </td>
                <td className="py-2 pr-3">
                  <span className={clsx(
                    'inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-semibold',
                    row.platform === 'signal' ? 'bg-sky-50 text-sky-700' : 'bg-emerald-50 text-emerald-700'
                  )}>
                    {row.platform === 'signal' ? <Radio size={12} /> : <MessageCircle size={12} />}
                    {row.platform === 'signal' ? 'Signal' : 'WhatsApp'}
                  </span>
                </td>
                <td className="py-2 pr-3">
                  <StatusPill state={row.state} inverted={selectedJid === row.jid} stale={row.stale} />
                </td>
                <td className="py-2 pr-3">{row.rtt ? `${Math.round(row.rtt)} ms` : '—'}</td>
                <td className="py-2 pr-3">{row.avg ? `${Math.round(row.avg)} ms` : '—'}</td>
                <td className="py-2 pr-3">{row.last?.median ? `${Math.round(row.last.median)} ms` : '—'}</td>
                <td className="py-2 pr-3">{row.last?.threshold ? `${Math.round(row.last.threshold)} ms` : '—'}</td>
                <td className="py-2 pr-3 flex items-center gap-1 text-xs">
                  <Clock size={12} /> {row.updatedAt ? timeAgo(row.updatedAt) : '—'}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="py-4 text-center text-slate-500">Keine Daten vorhanden.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function label(key: SortKey) {
  switch (key) {
    case 'state': return 'Status';
    case 'avg': return 'Avg';
    case 'rtt': return 'RTT';
    default: return 'Zuletzt';
  }
}

function timeAgo(ts: number) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return `${Math.max(1, Math.round(diff / 1000))}s`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h`;
  return `${Math.round(diff / 86_400_000)}d`;
}

function StatusPill({ state, inverted, stale }: { state: string; inverted?: boolean; stale?: boolean }) {
  const normalize = state || 'Unknown';
  let tone = 'bg-slate-100 text-slate-700';
  let dot = 'bg-slate-400';
  if (stale) { tone = 'bg-amber-100 text-amber-700'; dot = 'bg-amber-500'; }
  else if (normalize.includes('Online')) { tone = 'bg-emerald-100 text-emerald-700'; dot = 'bg-emerald-500'; }
  else if (normalize === 'Standby') { tone = 'bg-amber-100 text-amber-700'; dot = 'bg-amber-500'; }
  else if (normalize === 'OFFLINE') { tone = 'bg-rose-100 text-rose-700'; dot = 'bg-rose-500'; }
  if (inverted) {
    tone = tone.replace('bg-', 'bg-opacity-20 bg-').replace('text-', 'text-');
  }
  return (
    <span className={clsx('inline-flex items-center gap-2 px-2.5 py-1 rounded-lg text-xs font-semibold', tone)}>
      <span className={clsx('h-2 w-2 rounded-full', dot)} /> {normalize}
    </span>
  );
}
