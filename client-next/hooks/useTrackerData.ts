"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { API_BASE, getSocket, initialConnectionState } from '@/lib/socket';
import { ContactInfo, ConnectionState, Platform, ProbeMethod, TrackerData } from '@/lib/types';

function mergeHistory(existing: TrackerData[], incoming: TrackerData[]): TrackerData[] {
  const merged = [...existing, ...incoming];
  merged.sort((a, b) => a.timestamp - b.timestamp);
  return merged.slice(-HISTORY_LIMIT);
}

const HISTORY_LIMIT = 2000;

async function fetchHistory(contactKey: string): Promise<TrackerData[]> {
  const response = await fetch(`${API_BASE}/api/contacts/${encodeURIComponent(contactKey)}/pings?limit=${HISTORY_LIMIT}`);
  if (!response.ok) throw new Error('History request failed');
  const rows = await response.json();
  return rows
    .map((row: any) => ({
      rtt: row.rtt,
      avg: row.avg,
      median: row.median,
      threshold: row.threshold,
      state: row.state || 'Unknown',
      timestamp: row.timestamp
    }))
    .sort((a: TrackerData, b: TrackerData) => a.timestamp - b.timestamp);
}

export function useTrackerData() {
  const socket = useMemo(() => getSocket(), []);
  const [connected, setConnected] = useState(socket.connected);
  const [connectionState, setConnectionState] = useState<ConnectionState>(initialConnectionState);
  const [contacts, setContacts] = useState<Map<string, ContactInfo>>(new Map());
  const [selectedJid, setSelectedJid] = useState<string | null>(null);
  const [probeMethod, setProbeMethod] = useState<ProbeMethod>('delete');
  const [error, setError] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState<Record<string, boolean>>({});

  const initialAliases = useMemo(() => {
    try {
      const raw = typeof window !== 'undefined' ? localStorage.getItem('contactAliases') : null;
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {} as Record<string, string>;
    }
  }, []);

  const aliasMapRef = useRef<Record<string, string>>(initialAliases);

  const persistAlias = useCallback((key: string, alias: string) => {
    aliasMapRef.current = { ...aliasMapRef.current, [key]: alias };
    try {
      localStorage.setItem('contactAliases', JSON.stringify(aliasMapRef.current));
    } catch {
      /* ignore */
    }
  }, []);

  const proxifyProfilePic = useCallback((url: string | null) => {
    if (!url) return null;
    if (url.includes('/api/profile-pic')) return url.startsWith('http') ? url : `${API_BASE}${url}`;
    return `${API_BASE}/api/profile-pic?url=${encodeURIComponent(url)}`;
  }, []);

  const hydrateContact = useCallback(async (jid: string, fallbackNumber?: string, platform?: Platform) => {
    if (historyLoading[jid]) return;
    setHistoryLoading(prev => ({ ...prev, [jid]: true }));
    try {
      const history = await fetchHistory(jid);
      setContacts(prev => {
        const next = new Map(prev);
        const existing = next.get(jid) || {
          jid,
          displayNumber: fallbackNumber || jid,
          contactName: fallbackNumber || jid,
          data: [],
          devices: [],
          deviceCount: 0,
          presence: null,
          profilePic: null,
          platform: platform || 'whatsapp'
        };
        const merged = mergeHistory(existing.data, history);
        const lastTimestamp = merged.length ? merged[merged.length - 1].timestamp : Date.now();
        next.set(jid, {
          ...existing,
          data: merged,
          hydratedAt: Date.now(),
          updatedAt: lastTimestamp
        });
        return next;
      });
    } catch {
      setError('Historie konnte nicht geladen werden');
    } finally {
      setHistoryLoading(prev => {
        const clone = { ...prev };
        delete clone[jid];
        return clone;
      });
    }
  }, [historyLoading]);

  useEffect(() => {
    function onConnect() {
      setConnected(true);
    }

    function onDisconnect() {
      setConnected(false);
      setConnectionState(initialConnectionState);
      setContacts(new Map());
      setSelectedJid(null);
    }

    function onWhatsAppConnectionOpen() {
      setConnectionState(prev => ({ ...prev, whatsapp: true, whatsappQr: null }));
    }

    function onWhatsAppQr(qr: string) {
      setConnectionState(prev => ({ ...prev, whatsappQr: qr }));
    }

    function onSignalConnectionOpen(data: { number: string }) {
      setConnectionState(prev => ({ ...prev, signal: true, signalNumber: data.number }));
    }

    function onSignalDisconnected() {
      setConnectionState(prev => ({ ...prev, signal: false, signalNumber: null }));
    }

    function onSignalApiStatus(data: { available: boolean }) {
      setConnectionState(prev => ({ ...prev, signalApiAvailable: data.available }));
    }

    function onSignalQrImage(url: string) {
      setConnectionState(prev => ({ ...prev, signalQrImage: url }));
    }

    function onTrackerUpdate(update: any) {
      const { jid, ...data } = update;
      if (!jid) return;
      setContacts(prev => {
        const next = new Map(prev);
        const contact = next.get(jid);
        if (!contact) return prev;
        const updated = { ...contact };
        if (data.presence !== undefined) updated.presence = data.presence;
        if (data.deviceCount !== undefined) updated.deviceCount = data.deviceCount;
        if (data.devices !== undefined) updated.devices = data.devices;
        if (data.median !== undefined && data.devices && data.devices.length > 0) {
          const first = data.devices[0];
          const newPoint: TrackerData = {
            rtt: first.rtt,
            avg: first.avg,
            median: data.median,
            threshold: data.threshold,
            state: data.devices.find((d: any) => (d.state || '').includes('Online'))?.state || first.state,
            timestamp: Date.now()
          };
          updated.data = [...updated.data, newPoint].slice(-HISTORY_LIMIT);
          updated.updatedAt = Date.now();
        }
        if (!updated.updatedAt) {
          updated.updatedAt = Date.now();
        }
        next.set(jid, updated);
        return next;
      });
    }

    function onProfilePic(data: { jid: string; url: string | null }) {
      setContacts(prev => {
        const next = new Map(prev);
        const contact = next.get(data.jid);
        if (contact) next.set(data.jid, { ...contact, profilePic: proxifyProfilePic(data.url) });
        return next;
      });
    }

    function onContactName(data: { jid: string; name: string }) {
      setContacts(prev => {
        const next = new Map(prev);
        const contact = next.get(data.jid);
        if (contact) {
          const alias = aliasMapRef.current[data.jid];
          next.set(data.jid, { ...contact, contactName: alias || data.name, displayNumber: alias || data.name });
        }
        return next;
      });
    }

    function onContactAdded(data: { jid: string; number: string; platform?: Platform }) {
      setContacts(prev => {
        const next = new Map(prev);
        const alias = aliasMapRef.current[data.jid] || aliasMapRef.current[`${data.platform || 'whatsapp'}:${data.number}`];
        if (alias) {
          aliasMapRef.current[data.jid] = alias;
          persistAlias(data.jid, alias);
        }
        next.set(data.jid, {
          jid: data.jid,
          displayNumber: alias || data.number,
          contactName: alias || data.number,
          data: [],
          devices: [],
          deviceCount: 0,
          presence: null,
          profilePic: null,
          platform: data.platform || 'whatsapp',
          updatedAt: Date.now()
        });
        return next;
      });
      hydrateContact(data.jid, data.number, data.platform);
      setSelectedJid(prev => prev || data.jid);
    }

    function onContactRemoved(jid: string) {
      setContacts(prev => {
        const next = new Map(prev);
        next.delete(jid);
        return next;
      });
      setSelectedJid(prev => (prev === jid ? null : prev));
    }

    function onError(data: { message: string }) {
      setError(data.message);
      setTimeout(() => setError(null), 2500);
    }

    function onProbe(method: ProbeMethod) {
      setProbeMethod(method);
    }

    function onTracked(contactsList: { id: string; platform: Platform; number?: string }[]) {
      setContacts(prev => {
        const next = new Map(prev);
        contactsList.forEach(({ id, platform, number }) => {
          if (next.has(id)) return;
          const base = platform === 'signal' ? (id.replace('signal:', '') || number || id) : (id.split('@')[0] || id);
          const alias = aliasMapRef.current[id];
          next.set(id, {
            jid: id,
            displayNumber: alias || base,
            contactName: alias || base,
            data: [],
            devices: [],
            deviceCount: 0,
            presence: null,
            profilePic: null,
            platform,
            updatedAt: Date.now()
          });
          hydrateContact(id, base, platform);
        });
        return next;
      });
    }

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connection-open', onWhatsAppConnectionOpen);
    socket.on('qr', onWhatsAppQr);
    socket.on('signal-connection-open', onSignalConnectionOpen);
    socket.on('signal-disconnected', onSignalDisconnected);
    socket.on('signal-api-status', onSignalApiStatus);
    socket.on('signal-qr-image', onSignalQrImage);
    socket.on('tracker-update', onTrackerUpdate);
    socket.on('profile-pic', onProfilePic);
    socket.on('contact-name', onContactName);
    socket.on('contact-added', onContactAdded);
    socket.on('contact-removed', onContactRemoved);
    socket.on('error', onError);
    socket.on('probe-method', onProbe);
    socket.on('tracked-contacts', onTracked);

    if (!socket.connected) socket.connect();
    socket.emit('get-tracked-contacts');

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connection-open', onWhatsAppConnectionOpen);
      socket.off('qr', onWhatsAppQr);
      socket.off('signal-connection-open', onSignalConnectionOpen);
      socket.off('signal-disconnected', onSignalDisconnected);
      socket.off('signal-api-status', onSignalApiStatus);
      socket.off('signal-qr-image', onSignalQrImage);
      socket.off('tracker-update', onTrackerUpdate);
      socket.off('profile-pic', onProfilePic);
      socket.off('contact-name', onContactName);
      socket.off('contact-added', onContactAdded);
      socket.off('contact-removed', onContactRemoved);
      socket.off('error', onError);
      socket.off('probe-method', onProbe);
      socket.off('tracked-contacts', onTracked);
    };
  }, [hydrateContact, socket]);

  useEffect(() => {
    if (!selectedJid && contacts.size > 0) {
      setSelectedJid(Array.from(contacts.keys())[0]);
    }
  }, [contacts, selectedJid]);

  const setAliasFor = useCallback((jid: string, alias: string) => {
    persistAlias(jid, alias);
    setContacts(prev => {
      const next = new Map(prev);
      const contact = next.get(jid);
      if (contact) next.set(jid, { ...contact, contactName: alias, displayNumber: alias });
      return next;
    });
  }, [persistAlias]);

  const addContact = useCallback((number: string, platform: Platform, alias?: string) => {
    const cleanNumber = number.replace(/\D/g, '');
    if (alias) persistAlias(`${platform}:${cleanNumber}`, alias);
    socket.emit('add-contact', { number: cleanNumber, platform, alias: alias || undefined });
  }, [socket, persistAlias]);

  const removeContact = useCallback((jid: string) => {
    socket.emit('remove-contact', jid);
  }, [socket]);

  const changeProbeMethod = useCallback((method: ProbeMethod) => {
    setProbeMethod(method);
    socket.emit('set-probe-method', method);
  }, [socket]);

  const refreshHistory = useCallback((jid: string, fallback?: string, platform?: Platform) => {
    hydrateContact(jid, fallback, platform);
  }, [hydrateContact]);

  const contactList = useMemo(() => Array.from(contacts.values()).sort((a, b) => a.displayNumber.localeCompare(b.displayNumber)), [contacts]);

  const selectedContact = selectedJid ? contacts.get(selectedJid) || null : null;

  return {
    connected,
    connectionState,
    contacts: contactList,
    selectedContact,
    setSelectedJid,
    selectedJid,
    probeMethod,
    setProbeMethod: changeProbeMethod,
    addContact,
    removeContact,
    refreshHistory,
    setAliasFor,
    error,
    historyLoading
  };
}
