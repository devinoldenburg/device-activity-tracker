/**
 * Device Activity Tracker - Web Server
 *
 * HTTP server with Socket.IO for real-time tracking visualization.
 * Provides REST API and WebSocket interface for the React frontend.
 *
 * For educational and research purposes only.
 */

import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import makeWASocket, { DisconnectReason, useMultiFileAuthState } from '@whiskeysockets/baileys';
import { pino } from 'pino';
import { Boom } from '@hapi/boom';
import { WhatsAppTracker, ProbeMethod } from './tracker.js';
import { SignalTracker, getSignalAccounts, checkSignalNumber } from './signal-tracker.js';
import { activityStore } from './storage.js';

// Configuration
const SIGNAL_API_URL = process.env.SIGNAL_API_URL || 'http://localhost:8080';
const SIGNAL_API_PUBLIC_URL = process.env.SIGNAL_API_PUBLIC_URL || SIGNAL_API_URL;
const AUTH_DIR = process.env.AUTH_DIR || path.join(process.cwd(), 'auth_info_baileys');

fs.mkdirSync(AUTH_DIR, { recursive: true });

const app = express();
app.use(cors());
app.use(express.json());

const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "*", // Allow all origins for dev
        methods: ["GET", "POST"]
    }
});

let sock: any;
let isWhatsAppConnected = false;
let isSignalConnected = false;
let signalAccountNumber: string | null = null;
let globalProbeMethod: ProbeMethod = 'delete'; // Default to delete method
let currentWhatsAppQr: string | null = null; // Store current QR code for new clients
let restoredWhatsApp = false;
let restoredSignal = false;

// Platform type for contacts
type Platform = 'whatsapp' | 'signal';

interface TrackerEntry {
    tracker: WhatsAppTracker | SignalTracker;
    platform: Platform;
    number: string;
    contactKey: string;
}

const trackers: Map<string, TrackerEntry> = new Map(); // JID/Number -> Tracker entry

function normalizeNumber(raw: string): string {
    return raw.replace(/\D/g, '');
}

function ensurePlusPrefix(cleanNumber: string): string {
    return cleanNumber.startsWith('+') ? cleanNumber : `+${cleanNumber}`;
}

async function startWhatsAppTracking(cleanNumber: string, notifySocket?: any) {
    if (!sock || !isWhatsAppConnected) {
        notifySocket?.emit('error', { message: 'WhatsApp not connected yet' });
        return;
    }

    const targetJid = cleanNumber + '@s.whatsapp.net';
    if (trackers.has(targetJid)) {
        notifySocket?.emit('error', { jid: targetJid, message: 'Already tracking this contact' });
        return;
    }

    try {
        const results = await sock.onWhatsApp(targetJid);
        const result = results?.[0];

        if (!result?.exists) {
            notifySocket?.emit('error', { jid: targetJid, message: 'Number not on WhatsApp' });
            return;
        }

        const tracker = new WhatsAppTracker(sock, result.jid);
        tracker.setProbeMethod(globalProbeMethod);
        const contactKey = result.jid;
        const normalizedNumber = ensurePlusPrefix(cleanNumber);
        trackers.set(result.jid, { tracker, platform: 'whatsapp', number: normalizedNumber, contactKey });
        activityStore.upsertContact(contactKey, 'whatsapp', normalizedNumber);

        tracker.onPing = (ping) => {
            activityStore.recordPing({
                ...ping,
                platform: 'whatsapp'
            });
        };

        tracker.onUpdate = (updateData) => {
            io.emit('tracker-update', {
                jid: result.jid,
                platform: 'whatsapp',
                ...updateData
            });
        };

        tracker.startTracking();

        const ppUrl = await tracker.getProfilePicture();

        let contactName = cleanNumber;
        try {
            const contactInfo = await sock.onWhatsApp(result.jid);
            if (contactInfo && contactInfo[0]?.notify) {
                contactName = contactInfo[0].notify;
            }
        } catch {
            // ignore
        }

        if (notifySocket) {
            notifySocket.emit('contact-added', {
                jid: result.jid,
                number: cleanNumber,
                platform: 'whatsapp'
            });
        }

        if (ppUrl) {
            io.emit('profile-pic', { jid: result.jid, url: ppUrl });
        }
        io.emit('contact-name', { jid: result.jid, name: contactName });
    } catch (err) {
        console.error(err);
        notifySocket?.emit('error', { jid: targetJid, message: 'Verification failed' });
    }
}

async function startSignalTracking(cleanNumber: string, notifySocket?: any) {
    if (!isSignalConnected || !signalAccountNumber) {
        notifySocket?.emit('error', { message: 'Signal is not connected. Please link Signal first.' });
        return;
    }

    const signalId = `signal:${cleanNumber}`;
    if (trackers.has(signalId)) {
        notifySocket?.emit('error', { jid: signalId, message: 'Already tracking this contact on Signal' });
        return;
    }

    try {
        const targetNumber = ensurePlusPrefix(cleanNumber);
        const checkResult = await checkSignalNumber(SIGNAL_API_URL, signalAccountNumber, targetNumber);

        if (!checkResult.registered) {
            notifySocket?.emit('error', {
                jid: signalId,
                message: checkResult.error || 'Number is not registered on Signal'
            });
            return;
        }

        const tracker = new SignalTracker(SIGNAL_API_URL, signalAccountNumber, targetNumber);
        trackers.set(signalId, { tracker, platform: 'signal', number: targetNumber, contactKey: signalId });
        activityStore.upsertContact(signalId, 'signal', targetNumber);

        tracker.onPing = (ping) => {
            activityStore.recordPing({
                ...ping,
                platform: 'signal'
            });
        };

        tracker.onUpdate = (updateData) => {
            io.emit('tracker-update', {
                jid: signalId,
                platform: 'signal',
                ...updateData
            });
        };

        tracker.startTracking();

        if (notifySocket) {
            notifySocket.emit('contact-added', {
                jid: signalId,
                number: cleanNumber,
                platform: 'signal'
            });
        }

        io.emit('contact-name', { jid: signalId, name: cleanNumber });
    } catch (err) {
        console.error(err);
        notifySocket?.emit('error', { message: 'Failed to start Signal tracking' });
    }
}

async function restorePersistedContacts(platform: Platform) {
    const contacts = activityStore.listContacts().filter((c) => c.platform === platform);

    for (const contact of contacts) {
        const clean = normalizeNumber(contact.number);
        if (!clean) continue;
        if (platform === 'whatsapp') {
            await startWhatsAppTracking(clean);
        } else {
            await startSignalTracking(clean);
        }
    }
}

async function connectToWhatsApp() {
    const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);

    sock = makeWASocket({
        auth: state,
        logger: pino({ level: 'debug' }),
        markOnlineOnConnect: true,
        printQRInTerminal: false,
    });

    sock.ev.on('connection.update', async (update: any) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
            console.log('QR Code generated');
            currentWhatsAppQr = qr; // Store the QR code
            io.emit('qr', qr);
        }

        if (connection === 'close') {
            isWhatsAppConnected = false;
            currentWhatsAppQr = null; // Clear QR on close
            const shouldReconnect = (lastDisconnect?.error as Boom)?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log('connection closed, reconnecting ', shouldReconnect);
            if (shouldReconnect) {
                connectToWhatsApp();
            }
        } else if (connection === 'open') {
            isWhatsAppConnected = true;
            currentWhatsAppQr = null; // Clear QR on successful connection
            console.log('opened connection');
            io.emit('connection-open');
            if (!restoredWhatsApp) {
                restoredWhatsApp = true;
                restorePersistedContacts('whatsapp');
            }
        }
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('messaging-history.set', ({ chats, contacts, messages, isLatest }: any) => {
        console.log(`[SESSION] History sync - Chats: ${chats.length}, Contacts: ${contacts.length}, Messages: ${messages.length}, Latest: ${isLatest}`);
    });

    sock.ev.on('messages.update', (updates: any) => {
        for (const update of updates) {
            console.log(`[MSG UPDATE] JID: ${update.key.remoteJid}, ID: ${update.key.id}, Status: ${update.update.status}, FromMe: ${update.key.fromMe}`);
        }
    });
}

connectToWhatsApp();

// Signal linking state
let signalLinkingInProgress = false;
let signalApiAvailable = false;
let currentSignalQrUrl: string | null = null;

// Check Signal API availability
async function checkSignalApiAvailable(): Promise<boolean> {
    try {
        const response = await fetch(`${SIGNAL_API_URL}/v1/about`, {
            signal: AbortSignal.timeout(2000)
        });
        return response.ok;
    } catch {
        return false;
    }
}

// Check Signal connection status
async function checkSignalConnection() {
    try {
        const available = await checkSignalApiAvailable();
        if (available !== signalApiAvailable) {
            signalApiAvailable = available;
            console.log(`[SIGNAL] API available: ${available}`);
            io.emit('signal-api-status', { available });
        }

        if (!available) {
            if (isSignalConnected) {
                isSignalConnected = false;
                signalAccountNumber = null;
                io.emit('signal-disconnected');
            }
            return;
        }

        const accounts = await getSignalAccounts(SIGNAL_API_URL);
        if (accounts.length > 0) {
            if (!isSignalConnected) {
                isSignalConnected = true;
                signalAccountNumber = accounts[0];
                signalLinkingInProgress = false;
                console.log(`[SIGNAL] Connected with account: ${signalAccountNumber}`);
                io.emit('signal-connection-open', { number: signalAccountNumber });
                if (!restoredSignal) {
                    restoredSignal = true;
                    restorePersistedContacts('signal');
                }
            }
        } else {
            if (isSignalConnected) {
                isSignalConnected = false;
                signalAccountNumber = null;
                console.log('[SIGNAL] Disconnected');
                io.emit('signal-disconnected');
            }
            // No accounts - need to link, start QR code process
            if (!signalLinkingInProgress) {
                startSignalLinking();
            }
        }
    } catch (err) {
        console.log('[SIGNAL] Error checking connection:', err);
        if (isSignalConnected) {
            isSignalConnected = false;
            signalAccountNumber = null;
            io.emit('signal-disconnected');
        }
    }
}

// Start Signal device linking - signal-cli-rest-api returns QR as PNG image
async function startSignalLinking() {
    if (signalLinkingInProgress || isSignalConnected) return;

    signalLinkingInProgress = true;
    console.log('[SIGNAL] Starting device linking...');

    try {
        // Check if the QR endpoint is available
        const response = await fetch(`${SIGNAL_API_URL}/v1/qrcodelink?device_name=activity-tracker`);
        if (!response.ok) {
            console.log('[SIGNAL] Failed to start linking:', response.status);
            signalLinkingInProgress = false;
            return;
        }

        // signal-cli-rest-api returns the QR code as a PNG image directly
        // Send the PUBLIC URL to the frontend so the browser can load it
        currentSignalQrUrl = `${SIGNAL_API_PUBLIC_URL}/v1/qrcodelink?device_name=activity-tracker&t=${Date.now()}`;
        console.log('[SIGNAL] Emitting QR image URL:', currentSignalQrUrl);
        io.emit('signal-qr-image', currentSignalQrUrl);

        // Keep polling to check if linking completed
        pollSignalLinkingStatus();
    } catch (err) {
        console.log('[SIGNAL] Error starting linking:', err);
        signalLinkingInProgress = false;
    }
}

// Poll to check if Signal linking has completed
async function pollSignalLinkingStatus() {
    const checkInterval = setInterval(async () => {
        try {
            const accounts = await getSignalAccounts(SIGNAL_API_URL);
            if (accounts.length > 0) {
                // Linking completed!
                clearInterval(checkInterval);
                signalLinkingInProgress = false;
                currentSignalQrUrl = null;
                isSignalConnected = true;
                signalAccountNumber = accounts[0];
                console.log(`[SIGNAL] Linking completed! Account: ${signalAccountNumber}`);
                io.emit('signal-connection-open', { number: signalAccountNumber });
            }
        } catch (err) {
            // Keep polling
        }
    }, 2000);

    // Stop polling after 5 minutes
    setTimeout(() => {
        clearInterval(checkInterval);
        signalLinkingInProgress = false;
    }, 300000);
}

// Check Signal connection periodically
checkSignalConnection();
setInterval(checkSignalConnection, 5000);

io.on('connection', (socket) => {
    console.log('Client connected');

    // Send current WhatsApp QR code if available
    if (currentWhatsAppQr) {
        socket.emit('qr', currentWhatsAppQr);
    }

    if (isWhatsAppConnected) {
        socket.emit('connection-open');
    }

    if (isSignalConnected && signalAccountNumber) {
        socket.emit('signal-connection-open', { number: signalAccountNumber });
    }

    // Send Signal API availability status
    socket.emit('signal-api-status', { available: signalApiAvailable });

    // Send current Signal QR code if linking is in progress
    if (signalLinkingInProgress && currentSignalQrUrl) {
        socket.emit('signal-qr-image', currentSignalQrUrl);
    }

    // Send current probe method to client
    socket.emit('probe-method', globalProbeMethod);

    // Send tracked contacts with platform info
    const trackedContacts = Array.from(trackers.entries()).map(([id, entry]) => ({
        id,
        platform: entry.platform,
        number: entry.number
    }));

    // Handle request to get tracked contacts (for page refresh)
    socket.on('get-tracked-contacts', () => {
        const trackedContacts = Array.from(trackers.entries()).map(([id, entry]) => ({
            id,
            platform: entry.platform,
            number: entry.number
        }));
        socket.emit('tracked-contacts', trackedContacts);
    });

    // Add contact - supports both WhatsApp and Signal
    socket.on('add-contact', async (data: string | { number: string; platform: Platform }) => {
        // Support both old format (string) and new format (object)
        const { number, platform } = typeof data === 'string'
            ? { number: data, platform: 'whatsapp' as Platform }
            : data;

        console.log(`Request to track on ${platform}: ${number}`);
        const cleanNumber = number.replace(/\D/g, '');

        if (platform === 'signal') {
            // Signal tracking
            if (!isSignalConnected || !signalAccountNumber) {
                socket.emit('error', { message: 'Signal is not connected. Please link Signal first.' });
                return;
            }

            const signalId = `signal:${cleanNumber}`;
            if (trackers.has(signalId)) {
                socket.emit('error', { jid: signalId, message: 'Already tracking this contact on Signal' });
                return;
            }

            try {
                const targetNumber = cleanNumber.startsWith('+') ? cleanNumber : `+${cleanNumber}`;

                // Check if number is registered and discoverable on Signal
                console.log(`[SIGNAL] Checking if ${targetNumber} is registered...`);
                const checkResult = await checkSignalNumber(SIGNAL_API_URL, signalAccountNumber, targetNumber);

                if (!checkResult.registered) {
                    console.log(`[SIGNAL] Number ${targetNumber} is not discoverable: ${checkResult.error}`);
                    socket.emit('error', {
                        jid: signalId,
                        message: checkResult.error || 'Number is not registered on Signal'
                    });
                    return;
                }

                console.log(`[SIGNAL] Number ${targetNumber} is registered, starting tracking...`);
                const tracker = new SignalTracker(SIGNAL_API_URL, signalAccountNumber, targetNumber);
                const normalizedNumber = targetNumber;
                trackers.set(signalId, { tracker, platform: 'signal', number: normalizedNumber, contactKey: signalId });
                activityStore.upsertContact(signalId, 'signal', normalizedNumber);

                tracker.onPing = (ping) => {
                    activityStore.recordPing({
                        ...ping,
                        platform: 'signal'
                    });
                };

                tracker.onUpdate = (updateData) => {
                    io.emit('tracker-update', {
                        jid: signalId,
                        platform: 'signal',
                        ...updateData
                    });
                };

                tracker.startTracking();

                socket.emit('contact-added', {
                    jid: signalId,
                    number: cleanNumber,
                    platform: 'signal'
                });

                io.emit('contact-name', { jid: signalId, name: cleanNumber });
            } catch (err) {
                console.error(err);
                socket.emit('error', { message: 'Failed to start Signal tracking' });
            }
        } else {
            // WhatsApp tracking (original logic)
            const targetJid = cleanNumber + '@s.whatsapp.net';

            if (trackers.has(targetJid)) {
                socket.emit('error', { jid: targetJid, message: 'Already tracking this contact' });
                return;
            }

            try {
                const results = await sock.onWhatsApp(targetJid);
                const result = results?.[0];

                if (result?.exists) {
                    const tracker = new WhatsAppTracker(sock, result.jid);
                    tracker.setProbeMethod(globalProbeMethod);
                    const contactKey = result.jid;
                    const normalizedNumber = cleanNumber.startsWith('+') ? cleanNumber : `+${cleanNumber}`;
                    trackers.set(result.jid, { tracker, platform: 'whatsapp', number: normalizedNumber, contactKey });
                    activityStore.upsertContact(contactKey, 'whatsapp', normalizedNumber);

                    tracker.onPing = (ping) => {
                        activityStore.recordPing({
                            ...ping,
                            platform: 'whatsapp'
                        });
                    };

                    tracker.onUpdate = (updateData) => {
                        io.emit('tracker-update', {
                            jid: result.jid,
                            platform: 'whatsapp',
                            ...updateData
                        });
                    };

                    tracker.startTracking();

                    const ppUrl = await tracker.getProfilePicture();

                    let contactName = cleanNumber;
                    try {
                        const contactInfo = await sock.onWhatsApp(result.jid);
                        if (contactInfo && contactInfo[0]?.notify) {
                            contactName = contactInfo[0].notify;
                        }
                    } catch (err) {
                        console.log('[NAME] Could not fetch contact name, using number');
                    }

                    socket.emit('contact-added', {
                        jid: result.jid,
                        number: cleanNumber,
                        platform: 'whatsapp'
                    });

                    io.emit('profile-pic', { jid: result.jid, url: ppUrl });
                    io.emit('contact-name', { jid: result.jid, name: contactName });
                } else {
                    socket.emit('error', { jid: targetJid, message: 'Number not on WhatsApp' });
                }
            } catch (err) {
                console.error(err);
                socket.emit('error', { jid: targetJid, message: 'Verification failed' });
            }
        }
    });

    socket.on('remove-contact', (jid: string) => {
        console.log(`Request to stop tracking: ${jid}`);
        const entry = trackers.get(jid);
        if (entry) {
            entry.tracker.stopTracking();
            trackers.delete(jid);
            socket.emit('contact-removed', jid);
        }
    });

    socket.on('set-probe-method', (method: ProbeMethod) => {
        console.log(`Request to change probe method to: ${method}`);
        if (method !== 'delete' && method !== 'reaction') {
            socket.emit('error', { message: 'Invalid probe method' });
            return;
        }

        globalProbeMethod = method;

        for (const entry of trackers.values()) {
            // Only WhatsApp trackers support the delete method
            if (entry.platform === 'whatsapp') {
                (entry.tracker as WhatsAppTracker).setProbeMethod(method);
            }
            // Signal trackers always use reaction method
        }

        io.emit('probe-method', method);
        console.log(`Probe method changed to: ${method}`);
    });
});

// Historical data API
app.get('/api/contacts', (_req, res) => {
    res.json(activityStore.listContacts());
});

app.get('/api/contacts/:contactKey/pings', (req, res) => {
    const contactKey = req.params.contactKey;
    const limitParam = req.query.limit as string | undefined;
    const limit = limitParam ? Number(limitParam) : 500;

    try {
        const rows = activityStore.listPings(contactKey, limit);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: 'Failed to read history' });
    }
});

// Proxy profile pictures to avoid CORS/redirect issues in the browser
app.get('/api/profile-pic', async (req, res) => {
    const target = req.query.url as string | undefined;
    if (!target) {
        res.status(400).json({ message: 'Missing url query param' });
        return;
    }

    try {
        const response = await fetch(target);
        if (!response.ok || !response.body) {
            res.status(502).json({ message: 'Failed to fetch image' });
            return;
        }

        // Mirror content-type; default to jpeg if absent
        const contentType = response.headers.get('content-type') || 'image/jpeg';
        res.setHeader('Content-Type', contentType);
        response.body.pipe(res);
    } catch (err) {
        console.error('[PROFILE PIC PROXY] Error:', err);
        res.status(500).json({ message: 'Proxy error' });
    }
});

const PORT = 3001;
httpServer.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
