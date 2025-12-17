"use client";

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Activity, Home, Settings, Users, LayoutDashboard, Menu, X, Shield } from 'lucide-react';
import clsx from 'clsx';
import { useAuth } from './AuthProvider';

const links = [
  { href: '/', label: 'Dashboard', icon: Home, adminOnly: false },
  { href: '/users', label: 'Kontakte', icon: Users, adminOnly: false },
  { href: '/settings', label: 'Einstellungen', icon: Settings, adminOnly: false },
  { href: '/account', label: 'Account', icon: Activity, adminOnly: false },
  { href: '/application', label: 'Application', icon: LayoutDashboard, adminOnly: true }
];

export function SideNav() {
  const pathname = usePathname();
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [open, setOpen] = useState(false);

  const filteredLinks = links.filter(link => !link.adminOnly || isAdmin);

  const NavItems = ({ onNavigate }: { onNavigate?: () => void }) => (
    <nav className="space-y-2">
      {filteredLinks.map(({ href, label, icon: Icon }) => {
        const active = pathname === href;
        return (
          <Link
            key={href}
            href={href}
            onClick={onNavigate}
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
  );

  return (
    <>
      <aside className="hidden lg:flex w-64 xl:w-72 shrink-0 h-screen sticky top-0 border-r border-slate-200/70 bg-white/90 backdrop-blur-xl flex-col">
        <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-200/70">
          <div className="h-10 w-10 rounded-2xl bg-gradient-to-br from-sky-400 to-blue-600 flex items-center justify-center text-white shadow-lift">
            <Activity size={20} />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Tracker</p>
            <p className="text-lg font-semibold text-slate-900">Telemetry</p>
          </div>
        </div>
        <div className="p-4 space-y-4">
          <NavItems />
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs text-slate-600">
            <p className="font-semibold text-slate-800">Status</p>
            <p className="mt-1 flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-emerald-500" />Kontrolliert</p>
            <p className="mt-1">Benutzer: {user?.username ?? 'unbekannt'}</p>
          </div>
        </div>
      </aside>

      <div className="lg:hidden sticky top-0 z-40 bg-white/90 backdrop-blur-xl border-b border-slate-200/70 px-4 py-3">
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
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold shadow-sm"
            onClick={() => setOpen(true)}
            aria-label="Navigation öffnen"
          >
            <Menu size={14} /> Menu
          </button>
        </div>
        <div className="mt-2 flex items-center gap-2 text-xs text-slate-500">
          <Shield size={14} /> Zugriff: {user?.role === 'admin' ? 'Admin' : 'Standard'}
        </div>
      </div>

      {open && (
        <div className="lg:hidden fixed inset-0 z-50">
          <div className="absolute inset-0 bg-slate-900/55" onClick={() => setOpen(false)} />
          <div className="absolute top-0 right-0 h-full w-80 max-w-[85%] bg-white shadow-2xl border-l border-slate-200 flex flex-col">
            <div className="flex items-center justify-between px-4 py-4 border-b border-slate-200">
              <div className="flex items-center gap-2">
                <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-sky-400 to-blue-600 flex items-center justify-center text-white shadow-lift">
                  <Activity size={18} />
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Tracker</p>
                  <p className="text-sm font-semibold text-slate-900">Navigation</p>
                </div>
              </div>
              <button
                className="rounded-full p-2 hover:bg-slate-100"
                onClick={() => setOpen(false)}
                aria-label="Navigation schließen"
              >
                <X size={18} />
              </button>
            </div>
            <div className="p-4 flex-1 overflow-y-auto space-y-4">
              <NavItems onNavigate={() => setOpen(false)} />
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <p className="font-semibold text-slate-900">Angemeldet</p>
                <p className="mt-1">{user?.username ?? 'unbekannter Nutzer'}</p>
                <p className="text-xs text-slate-500 mt-1">Rolle: {user?.role ?? 'standard'}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
