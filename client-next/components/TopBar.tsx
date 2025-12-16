"use client";

import { Wifi, Zap } from 'lucide-react';
import clsx from 'clsx';
import { ConnectionState } from '@/lib/types';

interface TopBarProps {
  connection: ConnectionState;
  connected: boolean;
}

export function TopBar({ connection, connected }: TopBarProps) {
  const badge = (label: string, on: boolean, tone: 'green' | 'blue') => (
    <span className={clsx(
      'inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold border',
      on
        ? tone === 'green'
          ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
          : 'bg-sky-50 text-sky-700 border-sky-100'
        : 'bg-amber-50 text-amber-700 border-amber-100'
    )}>
      <span className={clsx('h-2 w-2 rounded-full', on ? 'bg-green-500' : 'bg-amber-400')} />
      {label}
    </span>
  );

  return (
    <header className="flex items-center justify-between px-8 py-5 border-b border-slate-200/70 bg-white/70 backdrop-blur-xl">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Realtime Control</p>
        <h1 className="text-2xl font-bold text-slate-900">Activity Tracker UI</h1>
      </div>
      <div className="flex items-center gap-3">
        <span className={clsx(
          'inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-semibold border',
          connected
            ? 'border-emerald-200 text-emerald-700 bg-emerald-50'
            : 'border-rose-200 text-rose-700 bg-rose-50'
        )}>
          <Wifi size={16} /> {connected ? 'Server connected' : 'Disconnected'}
        </span>
        {badge('WhatsApp', connection.whatsapp, 'green')}
        {badge('Signal', connection.signal, 'blue')}
        {connection.signalNumber && (
          <span className="text-xs px-2 py-1 rounded-lg bg-slate-100 text-slate-700 border border-slate-200">
            {connection.signalNumber}
          </span>
        )}
        <span className="hidden md:inline-flex items-center gap-2 text-xs text-slate-500 px-3 py-1 rounded-lg bg-slate-100 border border-slate-200">
          <Zap size={14} /> High-frequency probes
        </span>
      </div>
    </header>
  );
}
