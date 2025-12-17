"use client";

import { useState } from 'react';
import { AlertTriangle, CheckCircle, MessageCircle, Plus } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { TopBar } from '@/components/TopBar';
import { ContactList } from '@/components/ContactList';
import { ContactDetail } from '@/components/ContactDetail';
import { useTracker } from '@/components/TrackerProvider';
import { ContactTable } from '@/components/ContactTable';

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
    historyLoading,
    error
  } = useTracker();

  const [number, setNumber] = useState('');
  const [alias, setAlias] = useState('');
  const submit = () => {
    if (!number) return;
    addContact(number, 'whatsapp', alias || undefined);
    setNumber('');
    setAlias('');
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-white via-slate-50 to-slate-100">
      <TopBar connection={connectionState} connected={connected} />

      <main className="px-4 md:px-8 py-6">
        {error && (
          <div className="mb-4 flex items-center gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
            <AlertTriangle size={16} /> {error}
          </div>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 md:gap-6">
          <aside className="xl:col-span-1 bg-white rounded-3xl border border-slate-200 p-4 md:p-5 shadow-lift flex flex-col xl:h-[calc(100vh-140px)]">
            <div className="space-y-3 mb-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Kontakt hinzufügen</p>
              <div className="grid grid-cols-1">
                <div className="px-3 py-2 rounded-xl border text-sm font-semibold flex items-center gap-2 bg-emerald-600 text-white border-emerald-600">
                  <MessageCircle size={14} /> WhatsApp
                </div>
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

            <div className="flex-1 overflow-hidden mt-2">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-500 mb-2">Nutzer</p>
              <ContactList contacts={contacts} selectedJid={selectedJid} onSelect={setSelectedJid} />
            </div>
          </aside>

          <section className="xl:col-span-3 xl:h-[calc(100vh-140px)] overflow-visible xl:overflow-y-auto xl:pr-2 space-y-4">
            {!connectionState.whatsapp ? (
              <div className="rounded-3xl border border-slate-200 bg-white shadow-lift p-6 flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Verbindung</p>
                    <p className="text-xl font-bold text-slate-900">WhatsApp noch nicht verbunden</p>
                    <p className="text-sm text-slate-600 mt-1">Öffne WhatsApp &gt; Einstellungen &gt; Verknüpfte Geräte und scanne den Code.</p>
                  </div>
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700">Verbinde zuerst</span>
                </div>
                <div className="rounded-2xl bg-slate-50 border border-dashed border-slate-200 p-6 flex items-center justify-center min-h-[260px]">
                  {connectionState.whatsappQr ? <QRCodeSVG value={connectionState.whatsappQr} size={200} /> : <p className="text-slate-500">Warte auf QR...</p>}
                </div>
              </div>
            ) : !selectedContact ? (
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
