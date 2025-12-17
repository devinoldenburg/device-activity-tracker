export type Platform = 'whatsapp';

export interface ConnectionState {
  whatsapp: boolean;
  whatsappQr: string | null;
}

export interface TrackerData {
  rtt: number;
  avg: number;
  median: number;
  threshold: number;
  state: string;
  timestamp: number;
}

export interface DeviceInfo {
  jid: string;
  state: string;
  rtt: number;
  avg: number;
}

export interface ContactInfo {
  jid: string;
  displayNumber: string;
  contactName: string;
  data: TrackerData[];
  devices: DeviceInfo[];
  deviceCount: number;
  presence: string | null;
  profilePic: string | null;
  platform: Platform;
  hydratedAt?: number;
  updatedAt?: number;
}

export type ProbeMethod = 'delete' | 'reaction';
