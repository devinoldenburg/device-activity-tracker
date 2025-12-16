import { io, Socket } from 'socket.io-client';
import { ConnectionState, Platform, ProbeMethod } from './types';

const DEFAULT_BASE = 'http://localhost:3005';

function resolveBase() {
  if (process.env.NEXT_PUBLIC_SOCKET_URL) return process.env.NEXT_PUBLIC_SOCKET_URL;
  if (process.env.NEXT_PUBLIC_API_BASE) return process.env.NEXT_PUBLIC_API_BASE;
  if (typeof window !== 'undefined') {
    // Prefer same host, swap client port 3002 to server port 3005 if present
    const url = new URL(window.location.origin);
    if (url.port === '3002') url.port = '3005';
    return url.toString();
  }
  return DEFAULT_BASE;
}

const SOCKET_URL = resolveBase();
export const API_BASE = SOCKET_URL.replace(/\/$/, '');

export type TrackerSocket = Socket<
  {
    'add-contact': (payload: { number: string; platform: Platform; alias?: string }) => void;
    'remove-contact': (jid: string) => void;
    'set-probe-method': (method: ProbeMethod) => void;
    'get-tracked-contacts': () => void;
  },
  {
    'tracker-update': (payload: any) => void;
    'profile-pic': (payload: { jid: string; url: string | null }) => void;
    'contact-name': (payload: { jid: string; name: string }) => void;
    'contact-added': (payload: { jid: string; number: string; platform?: Platform }) => void;
    'contact-removed': (jid: string) => void;
    'error': (payload: { jid?: string; message: string }) => void;
    'probe-method': (method: ProbeMethod) => void;
    'tracked-contacts': (contacts: { id: string; platform: Platform; number?: string }[]) => void;
    'qr': (qr: string) => void;
    'connection-open': () => void;
    'signal-connection-open': (payload: { number: string }) => void;
    'signal-disconnected': () => void;
    'signal-api-status': (payload: { available: boolean }) => void;
    'signal-qr-image': (url: string) => void;
  }
>;

let socketInstance: TrackerSocket | null = null;

export function getSocket(): TrackerSocket {
  if (socketInstance) return socketInstance as TrackerSocket;
  socketInstance = io(SOCKET_URL, { autoConnect: false, transports: ['websocket'] }) as TrackerSocket;
  return socketInstance;
}

export function resetSocket() {
  if (socketInstance) {
    socketInstance.disconnect();
    socketInstance = null;
  }
}

export const initialConnectionState: ConnectionState = {
  whatsapp: false,
  signal: false,
  signalNumber: null,
  signalApiAvailable: false,
  signalQrImage: null,
  whatsappQr: null
};
