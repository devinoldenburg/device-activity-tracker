"use client";

import { ContactInfo } from '@/lib/types';
import clsx from 'clsx';
import { MessageCircle, Phone } from 'lucide-react';

interface ContactListProps {
  contacts: ContactInfo[];
  selectedJid: string | null;
  onSelect: (jid: string) => void;
}

export function ContactList({ contacts, selectedJid, onSelect }: ContactListProps) {
  return (
    <div className="h-full overflow-y-auto pr-2 space-y-2 scrollbar-thin">
      {contacts.map((contact) => {
        const online = contact.devices.some(d => (d.state || '').includes('Online'));
        const number = contact.displayNumber;
        return (
          <button
            key={contact.jid}
            onClick={() => onSelect(contact.jid)}
            className={clsx(
              'w-full text-left p-3 rounded-xl border flex items-center gap-3 transition shadow-sm',
              selectedJid === contact.jid
                ? 'border-slate-900 bg-slate-900 text-white'
                : 'border-slate-200 bg-white hover:border-slate-300'
            )}
          >
            <div className={clsx(
              'h-10 w-10 rounded-xl flex items-center justify-center text-white shadow-lift',
              'bg-gradient-to-br from-emerald-400 to-green-600'
            )}>
              <MessageCircle size={18} />
            </div>
            <div className="flex-1">
              <p className={clsx('text-sm font-semibold', selectedJid === contact.jid ? 'text-white' : 'text-slate-900')}>{number}</p>
              <p className={clsx('text-xs', selectedJid === contact.jid ? 'text-slate-200' : 'text-slate-500')}>
                {contact.contactName}
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs font-semibold">
              <span className={clsx('h-2 w-2 rounded-full', online ? 'bg-emerald-400' : 'bg-slate-300')} />
              <span className={selectedJid === contact.jid ? 'text-slate-100' : 'text-slate-600'}>
                {online ? 'Online' : contact.devices[0]?.state || '—'}
              </span>
            </div>
          </button>
        );
      })}
      {contacts.length === 0 && (
        <div className="p-4 rounded-xl border border-dashed border-slate-300 text-slate-600 text-sm bg-white/70">
          Noch keine Kontakte angelegt.
        </div>
      )}
    </div>
  );
}
