export interface PingEvent {
    contactId: string;
    deviceId: string;
    state: string;
    rtt: number;
    avg: number;
    median: number;
    threshold: number;
    timestamp: number;
}
