"use client";

import { useState } from 'react';
import { MessageCircle, Plus, Radio } from 'lucide-react';
import { TopBar } from '@/components/TopBar';
import { ContactList } from '@/components/ContactList';
import { ContactDetail } from '@/components/ContactDetail';
import { useTracker } from '@/components/TrackerProvider';
import { ContactTable } from '@/components/ContactTable';
import { Platform } from '@/lib/types';

export default function UsersPage() {
  const {
    connectionState,
    connected,
    contacts,
    selectedContact,
    selectedJid,
    setSelectedJid,
    addContact,
    removeContact,
    refreshHistory,
    probeMethod,
    setProbeMethod,
    setAliasFor,
    historyLoading
  } = useTracker();

  const [number, setNumber] = useState('');
  const [alias, setAlias] = useState('');
  const [platform, setPlatform] = useState<Platform>('whatsapp');

  const submit = () => {
    if (!number) return;
    addContact(number, platform, alias || undefined);
    setNumber('');
    setAlias('');
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-8 py-6">
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
          <aside className="xl:col-span-1 bg-white rounded-3xl border border-slate-200 p-5 shadow-lift h-[calc(100vh-140px)] flex flex-col">
            <div className="space-y-3 mb-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Kontakt hinzufügen</p>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setPlatform('whatsapp')}
                  className={`px-3 py-2 rounded-xl border text-sm font-semibold flex items-center gap-2 ${platform === 'whatsapp' ? 'bg-emerald-600 text-white border-emerald-600' : 'bg-slate-50 text-slate-700 border-slate-200'}`}
                >
                  <MessageCircle size={14} /> WhatsApp
                </button>
                <button
                  onClick={() => setPlatform('signal')}
                  className={`px-3 py-2 rounded-xl border text-sm font-semibold flex items-center gap-2 ${platform === 'signal' ? 'bg-sky-600 text-white border-sky-600' : 'bg-slate-50 text-slate-700 border-slate-200'}`}
                >
                  <Radio size={14} /> Signal
                </button>
              </div>
              <input
                value={number}
                onChange={(e) => setNumber(e.target.value)}
                placeholder="Nummer"
                className="w-full px-3 py-2 rounded-xl border border-slate-200 text-sm"
              />
              <input
                value={alias}
                onChange={(e) => setAlias(e.target.value)}
                placeholder="Alias (optional)"
                className="w-full px-3 py-2 rounded-xl border border-slate-200 text-sm"
              />
              <button
                onClick={submit}
                className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-xl bg-slate-900 text-white font-semibold shadow-lift hover:bg-black"
              >
                <Plus size={16} /> Start Tracking
              </button>
            </div>

            <div className="flex-1 overflow-hidden">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-500 mb-2">Nutzer</p>
              <ContactList contacts={contacts} selectedJid={selectedJid} onSelect={setSelectedJid} />
            </div>
          </aside>

          <section className="xl:col-span-3 h-[calc(100vh-140px)] overflow-y-auto pr-2">
            {!selectedContact ? (
              <div className="rounded-3xl border border-dashed border-slate-300 bg-white/80 p-10 text-center text-slate-600">
                Wähle einen Nutzer links aus, um Details zu sehen.
              </div>
            ) : (
              <ContactDetail
                contact={selectedContact}
                onRemove={() => removeContact(selectedContact.jid)}
                onRefresh={() => refreshHistory(selectedContact.jid, selectedContact.displayNumber, selectedContact.platform)}
                loading={!!historyLoading[selectedContact.jid]}
                probeMethod={probeMethod}
                onProbeChange={setProbeMethod}
                onAliasChange={(aliasValue) => setAliasFor(selectedContact.jid, aliasValue)}
              />
            )}
          </section>
        </div>

        <div className="mt-6">
          <ContactTable contacts={contacts} selectedJid={selectedJid} onSelect={setSelectedJid} />
        </div>
      </main>
    </div>
  );
}
