"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Activity, Home, Settings, Users } from 'lucide-react';
import clsx from 'clsx';

const links = [
  { href: '/', label: 'Home', icon: Home },
  { href: '/users', label: 'Nutzer', icon: Users },
  { href: '/settings', label: 'Settings', icon: Settings }
];

export function SideNav() {
  const pathname = usePathname();

  return (
    <>
      <aside className="hidden md:block w-64 shrink-0 h-screen sticky top-0 border-r border-slate-200/70 bg-white/80 backdrop-blur-xl">
        <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-200/70">
          <div className="h-10 w-10 rounded-2xl bg-gradient-to-br from-sky-400 to-blue-600 flex items-center justify-center text-white shadow-lift">
            <Activity size={20} />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Tracker</p>
            <p className="text-lg font-semibold text-slate-900">Telemetry</p>
          </div>
        </div>
        <nav className="p-4 space-y-2">
          {links.map(({ href, label, icon: Icon }) => {
            const active = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-semibold transition',
                  active
                    ? 'bg-slate-900 text-white shadow-lift'
                    : 'text-slate-700 hover:bg-slate-100'
                )}
              >
                <Icon size={16} />
                {label}
              </Link>
            );
          })}
        </nav>
      </aside>

      <div className="md:hidden sticky top-0 z-40 bg-white/90 backdrop-blur-xl border-b border-slate-200/70 px-4 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-sky-400 to-blue-600 flex items-center justify-center text-white shadow-lift">
              <Activity size={18} />
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Tracker</p>
              <p className="text-sm font-semibold text-slate-900">Telemetry</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {links.map(({ href, label, icon: Icon }) => {
              const active = pathname === href;
              return (
                <Link
                  key={href}
                  href={href}
                  className={clsx(
                    'inline-flex items-center gap-1 px-3 py-2 rounded-lg text-xs font-semibold border',
                    active
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white text-slate-700 border-slate-200'
                  )}
                >
                  <Icon size={14} /> {label}
                </Link>
              );
            })}
          </div>
        </div>
      </div>
    </>
  );
}
