import { ReactNode } from 'react';

interface StatCardProps {
  title: string;
  value: string;
  hint?: string;
  icon?: ReactNode;
  accent?: 'blue' | 'green' | 'amber' | 'slate';
}

export function StatCard({ title, value, hint, icon, accent = 'slate' }: StatCardProps) {
  const palette: Record<'blue' | 'green' | 'amber' | 'slate', string> = {
    blue: 'from-sky-400/40 to-blue-600/40',
    green: 'from-emerald-400/40 to-teal-500/40',
    amber: 'from-amber-300/40 to-orange-500/40',
    slate: 'from-slate-200/60 to-slate-100/60'
  } as const;

  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-lift">
      <div className={`absolute inset-0 bg-gradient-to-br ${palette[accent]} opacity-60`} />
      <div className="relative p-5 flex items-center gap-4">
        <div className="h-12 w-12 rounded-xl bg-white/70 border border-white shadow-lift flex items-center justify-center">
          {icon}
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{title}</p>
          <p className="text-3xl font-bold text-slate-900">{value}</p>
          {hint && <p className="text-sm text-slate-600 mt-1">{hint}</p>}
        </div>
      </div>
    </div>
  );
}
