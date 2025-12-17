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
import crypto from 'crypto';
import makeWASocket, { DisconnectReason, useMultiFileAuthState } from '@whiskeysockets/baileys';
import { pino } from 'pino';
import { Boom } from '@hapi/boom';
import { WhatsAppTracker, ProbeMethod } from './tracker.js';
import { activityStore } from './storage.js';

// Configuration
const AUTH_DIR = process.env.AUTH_DIR || path.join(process.cwd(), 'auth_info_baileys');
const JWT_SECRET = process.env.JWT_SECRET || '';
const ALLOW_REGISTRATION = (process.env.ALLOW_REGISTRATION || '').toLowerCase() === 'true';
const TOKEN_TTL_MS = 1000 * 60 * 60 * 2; // 2 hours
const COOKIE_SECURE = (process.env.COOKIE_SECURE || 'true').toLowerCase() === 'true';

fs.mkdirSync(AUTH_DIR, { recursive: true });

if (!JWT_SECRET || JWT_SECRET.length < 24) {
    throw new Error('JWT_SECRET must be set to a strong value (min 24 chars)');
}

type ThrottleKey = string;
const loginAttempts: Map<ThrottleKey, { count: number; resetAt: number }> = new Map();
const MAX_ATTEMPTS = 7;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

function asyncHandler(fn: (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<any>) {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

// Auth endpoints
app.post('/api/auth/register', asyncHandler(async (req, res) => {
    if (!ALLOW_REGISTRATION) {
        return res.status(403).json({ message: 'Registration disabled' });
    }

    const { username, password } = req.body || {};
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    if (!passwordStrong(password)) {
        return res.status(400).json({ message: 'Passwort zu schwach (min. 10 Zeichen, Groß/klein, Zahl, Sonderzeichen)' });
    }

    const existing = await activityStore.findUser(username);
    if (existing) {
        return res.status(409).json({ message: 'User already exists' });
    }

    const passwordHash = hashPassword(password);
    const userId = await activityStore.createUser(username, passwordHash, 'user', 'pending');
    const token = signToken({ sub: userId, username, role: 'user', status: 'pending' });
    setAuthCookie(res, token);
    res.status(202).json({ id: userId, username, allowRegistration: ALLOW_REGISTRATION, role: 'user', status: 'pending' });
}));

app.post('/api/auth/request', asyncHandler(async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
        return res.status(400).json({ message: 'Username und Passwort erforderlich' });
    }
    if (!passwordStrong(password)) {
        return res.status(400).json({ message: 'Passwort zu schwach (min. 10 Zeichen, Groß/klein, Zahl, Sonderzeichen)' });
    }

    const throttleKey = `request:${username.toLowerCase()}`;
    if (!consumeLoginAttempt(throttleKey)) {
        return res.status(429).json({ message: 'Zu viele Anfragen. Bitte später erneut.' });
    }

    const existing = await activityStore.findUser(username);
    if (existing) {
        if (existing.status === 'pending') {
            return res.status(202).json({ message: 'Bereits in Prüfung' });
        }
        return res.status(409).json({ message: 'User exists' });
    }

    const passwordHash = hashPassword(password);
    const userId = await activityStore.createUser(username, passwordHash, 'user', 'pending');
    resetLoginAttempts(throttleKey);
    res.status(202).json({ id: userId, username, status: 'pending' });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    const throttleKey = `user:${username.toLowerCase()}`;
    if (!consumeLoginAttempt(throttleKey)) {
        return res.status(429).json({ message: 'Zu viele Versuche. Bitte später erneut.' });
    }

    const user = await activityStore.findUser(username);
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!verifyPassword(password, user.passwordHash)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    resetLoginAttempts(throttleKey);

    if (user.status !== 'approved') {
        return res.status(403).json({ message: 'Account pending approval' });
    }

    const token = signToken({ sub: user.id, username: user.username, role: user.role, status: user.status });
    setAuthCookie(res, token);
    res.json({ id: user.id, username: user.username, allowRegistration: ALLOW_REGISTRATION, role: user.role, status: user.status });
}));

app.post('/api/auth/logout', (_req, res) => {
    res.cookie('auth_token', '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0 });
    res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
    const ctx = getAuthContext(req);
    if (!ctx) return res.status(401).json({ message: 'Unauthorized' });
    res.json({ id: ctx.userId, username: ctx.username, allowRegistration: ALLOW_REGISTRATION, role: ctx.role, status: ctx.status });
});

app.post('/api/account/username', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ message: 'Username und Passwort erforderlich' });

    const current = await activityStore.findUserById(ctx.userId);
    if (!current) return res.status(404).json({ message: 'User not found' });
    if (!verifyPassword(password, current.passwordHash)) return res.status(401).json({ message: 'Falsches Passwort' });

    const existing = await activityStore.findUser(username);
    if (existing && existing.id !== ctx.userId) return res.status(409).json({ message: 'Benutzername bereits vergeben' });

    try {
        await activityStore.updateUsername(ctx.userId, username);
        const token = signToken({ sub: ctx.userId, username, role: current.role, status: current.status });
        setAuthCookie(res, token);
        res.json({ id: ctx.userId, username, allowRegistration: ALLOW_REGISTRATION, role: current.role, status: current.status });
    } catch (err) {
        res.status(500).json({ message: 'Konnte Benutzernamen nicht ändern' });
    }
}));

app.post('/api/account/password', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ message: 'Passwörter erforderlich' });

    if (!passwordStrong(newPassword)) return res.status(400).json({ message: 'Passwort zu schwach (min. 10 Zeichen, Groß/klein, Zahl, Sonderzeichen)' });

    const current = await activityStore.findUserById(ctx.userId);
    if (!current) return res.status(404).json({ message: 'User not found' });
    if (!verifyPassword(currentPassword, current.passwordHash)) return res.status(401).json({ message: 'Falsches Passwort' });

    const passwordHash = hashPassword(newPassword);
    try {
        await activityStore.updatePasswordHash(ctx.userId, passwordHash);
        res.json({ ok: true });
    } catch {
        res.status(500).json({ message: 'Konnte Passwort nicht ändern' });
    }
}));

app.post('/api/account/reset-data', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    try {
        stopUserTrackers(ctx.userId);
        await activityStore.clearUserData(ctx.userId);
        res.json({ ok: true });
    } catch {
        res.status(500).json({ message: 'Reset fehlgeschlagen' });
    }
}));

app.post('/api/whatsapp/disconnect', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    try {
        const session = whatsappSessions.get(ctx.userId);
        if (!session) {
            // No active session; still clear auth dir to be idempotent
            try {
                fs.rmSync(userAuthDir(ctx.userId), { recursive: true, force: true });
                fs.mkdirSync(userAuthDir(ctx.userId), { recursive: true });
            } catch (e) {
                console.error('[WHATSAPP] Disconnect fs cleanup (no session) failed', e);
            }
            io.to(`user:${ctx.userId}`).emit('qr', null);
            io.to(`user:${ctx.userId}`).emit('connection-close');
            return res.json({ ok: true, message: 'No active session' });
        }

        if (session.sock) {
            try {
                await session.sock.logout();
            } catch {
                /* ignore logout errors */
            }
            session.sock.ev.removeAllListeners();
            session.sock = null;
        }

        if (session) {
            session.isConnected = false;
            session.currentQr = null;
            session.restored = false;
        }
        stopPlatformTrackers(ctx.userId, 'whatsapp');

        try {
            fs.rmSync(session.authDir || userAuthDir(ctx.userId), { recursive: true, force: true });
            fs.mkdirSync(userAuthDir(ctx.userId), { recursive: true });
        } catch {
            /* ignore file cleanup errors */
        }

        io.to(`user:${ctx.userId}`).emit('qr', null);
        io.to(`user:${ctx.userId}`).emit('connection-close');
        await ensureWhatsAppSession(ctx.userId);
        res.json({ ok: true });
    } catch (err) {
        console.error('[WHATSAPP] Disconnect failed', err);
        res.status(500).json({ message: 'Disconnect fehlgeschlagen' });
    }
}));

// Explicitly trigger a fresh WhatsApp connect (clears conflict block and starts QR)
app.post('/api/whatsapp/connect', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    let session = whatsappSessions.get(ctx.userId);
    if (!session) {
        session = { sock: null, isConnected: false, currentQr: null, restored: false, authDir: userAuthDir(ctx.userId) };
        whatsappSessions.set(ctx.userId, session);
    }
    // Force a clean re-pair: drop auth files, clear conflict block, and start fresh QR
    resetWhatsAppAuth(ctx.userId, session, true);
    session.authDir = userAuthDir(ctx.userId);
    session.conflictCount = 0;
    session.lastConflictAt = undefined;
    session.blockedOnConflict = false;
    session.currentQr = null;
    await ensureWhatsAppSession(ctx.userId);
    res.json({ ok: true });
}));

// Admin endpoints
app.get('/api/admin/users', requireAdmin, asyncHandler(async (_req, res) => {
    const users = (await activityStore.listUsers()).map(u => ({
        id: u.id,
        username: u.username,
        createdAt: u.createdAt,
        role: u.role,
        status: u.status
    }));
    res.json(users);
}));

app.post('/api/admin/users/:id/approve', requireAdmin, asyncHandler(async (req, res) => {
    const userId = Number(req.params.id);
    const role = (req.body?.role === 'admin') ? 'admin' : 'user';
    if (!Number.isFinite(userId)) return res.status(400).json({ message: 'Invalid user id' });
    const target = await activityStore.findUserById(userId);
    if (!target) return res.status(404).json({ message: 'User not found' });
    await activityStore.updateUserRoleStatus(userId, role, 'approved');
    res.json({ id: userId, role, status: 'approved' });
}));

app.post('/api/admin/users/:id/pending', requireAdmin, asyncHandler(async (req, res) => {
    const userId = Number(req.params.id);
    const role = (req.body?.role === 'admin') ? 'admin' : 'user';
    if (!Number.isFinite(userId)) return res.status(400).json({ message: 'Invalid user id' });
    const target = await activityStore.findUserById(userId);
    if (!target) return res.status(404).json({ message: 'User not found' });
    await activityStore.updateUserRoleStatus(userId, role, 'pending');
    res.json({ id: userId, role, status: 'pending' });
}));

app.delete('/api/admin/users/:id', requireAdmin, asyncHandler(async (req, res) => {
    const userId = Number(req.params.id);
    if (!Number.isFinite(userId)) return res.status(400).json({ message: 'Invalid user id' });
    if (userId === 1) return res.status(400).json({ message: 'Cannot delete default admin' });
    const target = await activityStore.findUserById(userId);
    if (!target) return res.status(404).json({ message: 'User not found' });
    stopUserTrackers(userId);
    await activityStore.deleteUser(userId);
    res.json({ ok: true });
}));

const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: true,
        credentials: true,
        methods: ["GET", "POST"]
    }
});

interface WhatsAppSession {
    sock: any | null;
    isConnected: boolean;
    currentQr: string | null;
    restored: boolean;
    authDir: string;
    connectPromise?: Promise<void>;
    reconnectTimeout?: NodeJS.Timeout;
    conflictCount?: number;
    lastConflictAt?: number;
    blockedOnConflict?: boolean;
}

const whatsappSessions: Map<number, WhatsAppSession> = new Map();
let globalProbeMethod: ProbeMethod = 'delete'; // Default to delete method

// Platform type for contacts
type Platform = 'whatsapp';

interface TrackerEntry {
    tracker: WhatsAppTracker;
    platform: Platform;
    number: string;
    contactKey: string;
    userId: number;
}

interface AuthPayload {
    sub: number;
    username: string;
    role: 'admin' | 'user';
    status: 'pending' | 'approved';
    exp: number;
}

type AuthContext = { userId: number; username: string; role: 'admin' | 'user'; status: 'pending' | 'approved' };

const trackers: Map<string, TrackerEntry> = new Map(); // userId:contactKey -> Tracker entry

function trackerKey(userId: number, contactKey: string) {
    return `${userId}:${contactKey}`;
}

function parseCookies(header: string | undefined): Record<string, string> {
    if (!header) return {};
    return header.split(';').reduce((acc, part) => {
        const [k, v] = part.split('=').map((s) => s.trim());
        if (k && v) acc[k] = decodeURIComponent(v);
        return acc;
    }, {} as Record<string, string>);
}

function signToken(payload: Omit<AuthPayload, 'exp'>): string {
    const body: AuthPayload = {
        ...payload,
        exp: Date.now() + TOKEN_TTL_MS,
    };
    const encoded = Buffer.from(JSON.stringify(body)).toString('base64url');
    const sig = crypto.createHmac('sha256', JWT_SECRET).update(encoded).digest('base64url');
    return `${encoded}.${sig}`;
}

function verifyToken(token?: string): AuthPayload | null {
    if (!token) return null;
    const [encoded, sig] = token.split('.');
    if (!encoded || !sig) return null;
    try {
        const expected = crypto.createHmac('sha256', JWT_SECRET).update(encoded).digest('base64url');
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
        const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString()) as AuthPayload;
        if (payload.exp && Date.now() > payload.exp) return null;
        return payload;
    } catch {
        return null;
    }
}

function passwordStrong(password: string): boolean {
    if (!password || password.length < 10) return false;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    return hasUpper && hasLower && hasDigit && hasSpecial;
}

function consumeLoginAttempt(key: ThrottleKey): boolean {
    const now = Date.now();
    const entry = loginAttempts.get(key);
    if (!entry || entry.resetAt < now) {
        loginAttempts.set(key, { count: 1, resetAt: now + WINDOW_MS });
        return true;
    }
    if (entry.count >= MAX_ATTEMPTS) {
        return false;
    }
    entry.count += 1;
    return true;
}

function resetLoginAttempts(key: ThrottleKey) {
    loginAttempts.delete(key);
}

function hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
    if (!storedHash.includes(':')) {
        // Legacy plain text storage fallback
        if (password.length !== storedHash.length) return false;
        return crypto.timingSafeEqual(Buffer.from(password), Buffer.from(storedHash));
    }
    const [salt, key] = storedHash.split(':');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(derived, 'hex'));
}

function setAuthCookie(res: express.Response, token: string) {
    res.cookie('auth_token', token, {
        httpOnly: true,
        sameSite: 'strict',
        path: '/',
        maxAge: TOKEN_TTL_MS,
        secure: COOKIE_SECURE,
    });
}

function getAuthContext(req: express.Request): AuthContext | null {
    const cookies = parseCookies(req.headers.cookie);
    const headerAuth = req.headers.authorization?.replace('Bearer ', '') || cookies['auth_token'];
    const payload = verifyToken(headerAuth);
    if (!payload) return null;
    return { userId: payload.sub, username: payload.username, role: payload.role, status: payload.status };
}

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    const ctx = getAuthContext(req);
    if (!ctx) return res.status(401).json({ message: 'Unauthorized' });
    if (ctx.status !== 'approved') return res.status(403).json({ message: 'Account pending' });
    (req as any).auth = ctx;
    next();
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
    const ctx = getAuthContext(req);
    if (!ctx) return res.status(401).json({ message: 'Unauthorized' });
    if (ctx.status !== 'approved') return res.status(403).json({ message: 'Account pending' });
    if (ctx.role !== 'admin') return res.status(403).json({ message: 'Admin required' });
    (req as any).auth = ctx;
    next();
}

function stopUserTrackers(userId: number) {
    for (const [key, entry] of trackers.entries()) {
        if (entry.userId === userId) {
            entry.tracker.stopTracking();
            trackers.delete(key);
        }
    }
}

function stopPlatformTrackers(userId: number, platform: Platform) {
    for (const [key, entry] of trackers.entries()) {
        if (entry.userId === userId && entry.platform === platform) {
            entry.tracker.stopTracking();
            trackers.delete(key);
        }
    }
}

function userAuthDir(userId: number) {
    const dir = path.join(AUTH_DIR, `user-${userId}`);
    fs.mkdirSync(dir, { recursive: true });
    return dir;
}

function authDirHasFiles(authDir: string): boolean {
    try {
        const files = fs.readdirSync(authDir);
        return Array.isArray(files) && files.length > 0;
    } catch {
        return false;
    }
}

function resetWhatsAppAuth(userId: number, session: WhatsAppSession, clearConflictBlock = false) {
    try {
        fs.rmSync(session.authDir, { recursive: true, force: true });
    } catch {
        /* ignore fs errors */
    }
    fs.mkdirSync(session.authDir, { recursive: true });
    session.sock = null;
    session.isConnected = false;
    session.currentQr = null;
    session.restored = false;
    if (clearConflictBlock) {
        session.blockedOnConflict = false;
    }
    if (session.reconnectTimeout) {
        clearTimeout(session.reconnectTimeout);
        session.reconnectTimeout = undefined;
    }
    stopPlatformTrackers(userId, 'whatsapp');
}

async function ensureWhatsAppSession(userId: number, notifySocket?: any) {
    let session = whatsappSessions.get(userId);
    // Do not auto-connect while the session is blocked due to repeated conflicts/replacements.
    if (session?.blockedOnConflict) {
        notifySocket?.emit('error', { message: 'WhatsApp-Sitzung blockiert. Bitte QR neu scannen.' });
        return;
    }
    if (session?.connectPromise) return session.connectPromise;

    const authDir = session?.authDir || userAuthDir(userId);
    if (!session) {
        session = { sock: null, isConnected: false, currentQr: null, restored: false, authDir };
        whatsappSessions.set(userId, session);
    } else {
        session.authDir = authDir;
    }

    session.connectPromise = (async () => {
        const { state, saveCreds } = await useMultiFileAuthState(authDir);

        const sock = makeWASocket({
            auth: state,
            logger: pino({ level: 'debug' }),
            markOnlineOnConnect: true,
            printQRInTerminal: false,
            shouldReconnect: (lastDisconnect) => {
                const statusCode = (lastDisconnect?.error as Boom)?.output?.statusCode;
                const payload = (lastDisconnect?.error as Boom)?.output?.payload as any;
                const messageText = payload?.message?.toString().toLowerCase() || '';
                const isConflict = messageText.includes('conflict') || statusCode === DisconnectReason.conflict;
                const isReplaced = messageText.includes('replaced') || statusCode === DisconnectReason.connectionReplaced;
                const blocked = session?.blockedOnConflict;
                // Never auto-reconnect on conflict/replaced, force a fresh pairing.
                const allow = !blocked && statusCode !== DisconnectReason.loggedOut && !isConflict && !isReplaced;
                return allow;
            },
        });

        session!.sock = sock;

        sock.ev.on('connection.update', async (update: any) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                session!.currentQr = qr;
                io.to(`user:${userId}`).emit('qr', qr);
                notifySocket?.emit('qr', qr);
            }

            if (connection === 'close') {
                session!.isConnected = false;
                session!.currentQr = null;
                const statusCode = (lastDisconnect?.error as Boom)?.output?.statusCode;
                const payload = (lastDisconnect?.error as Boom)?.output?.payload as any;
                const messageText = payload?.message?.toString().toLowerCase() || '';
                const isConflict = messageText.includes('conflict') || statusCode === DisconnectReason.conflict;
                const isReplaced = messageText.includes('replaced') || statusCode === DisconnectReason.connectionReplaced;
                const isConnectionClosed = messageText.includes('connection closed');
                const now = Date.now();
                if (isConflict) {
                    session!.conflictCount = (session!.conflictCount || 0) + 1;
                    session!.lastConflictAt = now;
                }

                // Always hard-close the underlying socket to prevent overlapping connections
                try { session!.sock?.ws?.close(); } catch { /* ignore */ }
                try { session!.sock?.end?.(); } catch { /* ignore */ }
                try { session!.sock?.ev?.removeAllListeners(); } catch { /* ignore */ }
                session!.sock = null;

                const shouldResetAuth = statusCode === DisconnectReason.loggedOut;
                if (shouldResetAuth) {
                    resetWhatsAppAuth(userId, session!, true);
                    session!.sock = undefined;
                    session!.restored = false;
                }

                if (isConflict || isReplaced) {
                    // Another device/session took over. Clear auth, block auto-reconnect, and force a fresh QR.
                    resetWhatsAppAuth(userId, session!, true);
                    session!.blockedOnConflict = true;
                    session!.sock = undefined;
                    session!.restored = false;
                    stopPlatformTrackers(userId, 'whatsapp');
                    io.to(`user:${userId}`).emit('qr', null);
                    io.to(`user:${userId}`).emit('error', { message: 'WhatsApp-Sitzung wurde ersetzt. Bitte neu koppeln.' });
                    notifySocket?.emit('qr', null);
                    notifySocket?.emit('error', { message: 'WhatsApp-Sitzung wurde ersetzt. Bitte neu koppeln.' });
                    return;
                }
                io.to(`user:${userId}`).emit('connection-close');
                notifySocket?.emit('connection-close');
                const tooManyConflicts = (session!.conflictCount || 0) >= 3 && session!.lastConflictAt && (now - session!.lastConflictAt) < 2 * 60 * 1000;

                const shouldReconnect = !tooManyConflicts;
                if (shouldReconnect) {
                    const delayMs = isConnectionClosed ? 5000 : 1000;
                    if (session!.reconnectTimeout) clearTimeout(session!.reconnectTimeout);
                    session!.reconnectTimeout = setTimeout(() => {
                        session!.reconnectTimeout = undefined;
                        void ensureWhatsAppSession(userId);
                    }, delayMs);
                } else if (tooManyConflicts) {
                    notifySocket?.emit('error', { message: 'Zu viele Verbindungs-Konflikte. Bitte QR erneut scannen.' });
                    io.to(`user:${userId}`).emit('qr', null);
                }
            } else if (connection === 'open') {
                session!.isConnected = true;
                session!.currentQr = null;
                session!.conflictCount = 0;
                session!.lastConflictAt = undefined;
                io.to(`user:${userId}`).emit('connection-open');
                notifySocket?.emit('connection-open');
                if (!session!.restored) {
                    session!.restored = true;
                    await restoreUserContacts(userId, 'whatsapp');
                }
            }
        });

        sock.ev.on('creds.update', saveCreds);
    })().finally(() => {
        session!.connectPromise = undefined;
    });

    return session.connectPromise;
}

function normalizeNumber(raw: string): string {
    return raw.replace(/\D/g, '');
}

function ensurePlusPrefix(cleanNumber: string): string {
    return cleanNumber.startsWith('+') ? cleanNumber : `+${cleanNumber}`;
}

async function startWhatsAppTracking(cleanNumber: string, userId: number, notifySocket?: any) {
    const session = whatsappSessions.get(userId);
    if (!session || !session.sock || !session.isConnected) {
        notifySocket?.emit('error', { message: 'WhatsApp not connected yet' });
        void ensureWhatsAppSession(userId, notifySocket);
        return;
    }

    const targetJid = cleanNumber + '@s.whatsapp.net';
    const key = trackerKey(userId, targetJid);
    if (trackers.has(key)) {
        notifySocket?.emit('error', { jid: targetJid, message: 'Already tracking this contact' });
        return;
    }

    try {
        const results = await session.sock.onWhatsApp(targetJid);
        const result = results?.[0];

        if (!result?.exists) {
            notifySocket?.emit('error', { jid: targetJid, message: 'Number not on WhatsApp' });
            return;
        }

        const tracker = new WhatsAppTracker(session.sock, result.jid);
        tracker.setProbeMethod(globalProbeMethod);
        const contactKey = result.jid;
        const normalizedNumber = ensurePlusPrefix(cleanNumber);
        trackers.set(key, { tracker, platform: 'whatsapp', number: normalizedNumber, contactKey, userId });
        await activityStore.upsertContact(contactKey, 'whatsapp', normalizedNumber, userId);

        tracker.onPing = (ping) => {
            void activityStore.recordPing({
                ...ping,
                platform: 'whatsapp',
                userId,
            }).catch((err) => console.error('[DB] Failed to record WhatsApp ping', err));
        };

        tracker.onUpdate = (updateData) => {
            io.to(`user:${userId}`).emit('tracker-update', {
                jid: result.jid,
                platform: 'whatsapp',
                ...updateData
            });
        };

        tracker.startTracking();

        const ppUrl = await tracker.getProfilePicture();

        let contactName = cleanNumber;
        try {
            const contactInfo = await session.sock.onWhatsApp(result.jid);
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
            io.to(`user:${userId}`).emit('profile-pic', { jid: result.jid, url: ppUrl });
        }
        io.to(`user:${userId}`).emit('contact-name', { jid: result.jid, name: contactName });
    } catch (err) {
        console.error(err);
        notifySocket?.emit('error', { jid: targetJid, message: 'Verification failed' });
    }
}

async function restoreUserContacts(userId: number, platform: Platform) {
    const contacts = (await activityStore.listContacts(userId)).filter((c) => c.platform === platform);

    for (const contact of contacts) {
        const clean = normalizeNumber(contact.number);
        if (!clean) continue;
        await startWhatsAppTracking(clean, userId);
    }
}
io.use(async (socket, next) => {
    const cookieHeader = socket.handshake.headers.cookie as string | undefined;
    const cookies = parseCookies(cookieHeader);
    const token = (socket.handshake.auth as any)?.token || cookies['auth_token'];
    const payload = verifyToken(token);
    if (!payload) {
        return next(new Error('unauthorized'));
    }
    const user = await activityStore.findUserById(payload.sub);
    if (!user || user.status !== 'approved') {
        return next(new Error('unauthorized'));
    }
    socket.data.auth = { userId: payload.sub, username: payload.username, role: user.role, status: user.status } satisfies AuthContext;
    socket.join(`user:${payload.sub}`);
    next();
});

io.on('connection', (socket) => {
    const auth = socket.data.auth as AuthContext;
    console.log(`Client connected as ${auth?.username || 'unknown'}`);

    if (!auth) {
        socket.disconnect(true);
        return;
    }

    const waSession = whatsappSessions.get(auth.userId);
    if (waSession?.currentQr) {
        socket.emit('qr', waSession.currentQr);
    }
    if (waSession?.isConnected) {
        socket.emit('connection-open');
    }

    // Only auto-start session if not conflict-blocked
    const existingSession = whatsappSessions.get(auth.userId);
    if (!existingSession?.blockedOnConflict) {
        void ensureWhatsAppSession(auth.userId, socket);
    } else {
        socket.emit('qr', null);
        socket.emit('error', { message: 'WhatsApp-Sitzung blockiert. Bitte QR neu scannen.' });
    }

    // Send current probe method to client
    socket.emit('probe-method', globalProbeMethod);

    const trackedContacts = Array.from(trackers.entries())
        .filter(([, entry]) => entry.userId === auth.userId)
        .map(([, entry]) => ({
            id: entry.contactKey,
            platform: entry.platform,
            number: entry.number
        }));

    socket.emit('tracked-contacts', trackedContacts);

    socket.on('get-tracked-contacts', () => {
        const tracked = Array.from(trackers.entries())
            .filter(([, entry]) => entry.userId === auth.userId)
            .map(([, entry]) => ({ id: entry.contactKey, platform: entry.platform, number: entry.number }));
        socket.emit('tracked-contacts', tracked);
    });

    // Add contact - WhatsApp only
    socket.on('add-contact', async (data: string | { number: string; platform: Platform }) => {
        const { number } = typeof data === 'string'
            ? { number: data, platform: 'whatsapp' as Platform }
            : data;

        console.log(`Request to track on whatsapp: ${number} by user ${auth.userId}`);
        const cleanNumber = number.replace(/\D/g, '');

        const targetJid = cleanNumber + '@s.whatsapp.net';
        const key = trackerKey(auth.userId, targetJid);

        if (trackers.has(key)) {
            socket.emit('error', { jid: targetJid, message: 'Already tracking this contact' });
            return;
        }

        const session = whatsappSessions.get(auth.userId);
        if (!session || !session.sock || !session.isConnected) {
            socket.emit('error', { message: 'WhatsApp noch nicht verbunden. Bitte koppeln.' });
            void ensureWhatsAppSession(auth.userId, socket);
            return;
        }

        try {
            const results = await session.sock.onWhatsApp(targetJid);
            const result = results?.[0];

            if (result?.exists) {
                const tracker = new WhatsAppTracker(session.sock, result.jid);
                tracker.setProbeMethod(globalProbeMethod);
                const contactKey = result.jid;
                const normalizedNumber = cleanNumber.startsWith('+') ? cleanNumber : `+${cleanNumber}`;
                trackers.set(key, { tracker, platform: 'whatsapp', number: normalizedNumber, contactKey, userId: auth.userId });
                await activityStore.upsertContact(contactKey, 'whatsapp', normalizedNumber, auth.userId);

                tracker.onPing = (ping) => {
                    void activityStore.recordPing({
                        ...ping,
                        platform: 'whatsapp',
                        userId: auth.userId,
                    }).catch((err) => console.error('[DB] Failed to record WhatsApp ping', err));
                };

                tracker.onUpdate = (updateData) => {
                    io.to(`user:${auth.userId}`).emit('tracker-update', {
                        jid: result.jid,
                        platform: 'whatsapp',
                        ...updateData
                    });
                };

                tracker.startTracking();

                const ppUrl = await tracker.getProfilePicture();

                let contactName = cleanNumber;
                try {
                    const contactInfo = await session.sock.onWhatsApp(result.jid);
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

                io.to(`user:${auth.userId}`).emit('profile-pic', { jid: result.jid, url: ppUrl });
                io.to(`user:${auth.userId}`).emit('contact-name', { jid: result.jid, name: contactName });
            } else {
                socket.emit('error', { jid: targetJid, message: 'Number not on WhatsApp' });
            }
        } catch (err) {
            console.error(err);
            socket.emit('error', { jid: targetJid, message: 'Verification failed' });
        }
    });

    socket.on('remove-contact', (jid: string) => {
        console.log(`Request to stop tracking: ${jid}`);
        const key = trackerKey(auth.userId, jid);
        const entry = trackers.get(key);
        if (entry) {
            entry.tracker.stopTracking();
            trackers.delete(key);
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
            if (entry.platform === 'whatsapp') {
                (entry.tracker as WhatsAppTracker).setProbeMethod(method);
            }
        }

        io.to(`user:${auth.userId}`).emit('probe-method', method);
        console.log(`Probe method changed to: ${method}`);
    });
});

// Historical data API (per-user scoped)
app.get('/api/contacts', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    const contacts = await activityStore.listContacts(ctx.userId);
    res.json(contacts);
}));

app.get('/api/contacts/:contactKey/pings', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    const contactKey = req.params.contactKey;
    const limitParam = req.query.limit as string | undefined;
    const limit = limitParam ? Number(limitParam) : 500;

    const rows = await activityStore.listPings(contactKey, ctx.userId, limit);
    res.json(rows);
}));

app.get('/api/stats/metrics', requireAuth, asyncHandler(async (req, res) => {
    const ctx = (req as any).auth as AuthContext;
    const total = await activityStore.countPings(ctx.userId);
    res.json({ total });
}));

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
