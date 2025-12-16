import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import { PingEvent } from './ping-events.js';

type Platform = 'whatsapp' | 'signal';

export interface ContactRecord {
    contactKey: string;
    platform: Platform;
    number: string;
    createdAt: number;
}

export interface StoredPing extends PingEvent {
    platform: Platform;
}

export class ActivityStore {
    private db: Database.Database;
    private upsertContactStmt: Database.Statement;
    private insertPingStmt: Database.Statement;
    private listContactsStmt: Database.Statement;
    private listPingsStmt: Database.Statement;

    constructor(dbFilePath: string = path.resolve(process.cwd(), 'data', 'tracker.sqlite')) {
        fs.mkdirSync(path.dirname(dbFilePath), { recursive: true });

        this.db = new Database(dbFilePath);
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('foreign_keys = ON');

        this.db.exec(`
            CREATE TABLE IF NOT EXISTS contacts (
                contact_key TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                number TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_key TEXT NOT NULL,
                platform TEXT NOT NULL,
                device_id TEXT NOT NULL,
                state TEXT NOT NULL,
                rtt INTEGER NOT NULL,
                avg INTEGER NOT NULL,
                median INTEGER NOT NULL,
                threshold INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                FOREIGN KEY (contact_key) REFERENCES contacts(contact_key) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_pings_contact_ts ON pings(contact_key, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_pings_platform ON pings(platform);
        `);

        this.upsertContactStmt = this.db.prepare(`
            INSERT INTO contacts (contact_key, platform, number, created_at)
            VALUES (@contactKey, @platform, @number, @createdAt)
            ON CONFLICT(contact_key) DO UPDATE SET
                platform = excluded.platform,
                number = excluded.number
        `);

        this.insertPingStmt = this.db.prepare(`
            INSERT INTO pings (
                contact_key, platform, device_id, state, rtt, avg, median, threshold, ts
            ) VALUES (
                @contactKey, @platform, @deviceId, @state, @rtt, @avg, @median, @threshold, @timestamp
            )
        `);

        this.listContactsStmt = this.db.prepare(`
            SELECT contact_key as contactKey, platform, number, created_at as createdAt
            FROM contacts
            ORDER BY created_at DESC
        `);

        this.listPingsStmt = this.db.prepare(`
            SELECT contact_key as contactKey, platform, device_id as deviceId, state, rtt, avg, median, threshold, ts as timestamp
            FROM pings
            WHERE contact_key = @contactKey
            ORDER BY ts DESC
            LIMIT @limit
        `);
    }

    public upsertContact(contactKey: string, platform: Platform, number: string) {
        const createdAt = Date.now();
        this.upsertContactStmt.run({ contactKey, platform, number, createdAt });
    }

    public recordPing(input: StoredPing) {
        this.insertPingStmt.run({
            contactKey: input.contactId,
            platform: input.platform,
            deviceId: input.deviceId,
            state: input.state,
            rtt: Math.round(input.rtt),
            avg: Math.round(input.avg),
            median: Math.round(input.median),
            threshold: Math.round(input.threshold),
            timestamp: input.timestamp,
        });
    }

    public listContacts(): ContactRecord[] {
        return this.listContactsStmt.all() as ContactRecord[];
    }

    public listPings(contactKey: string, limit: number = 500): StoredPing[] {
        const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 5000) : 500;
        return this.listPingsStmt.all({ contactKey, limit: safeLimit }) as StoredPing[];
    }
}

export const activityStore = new ActivityStore();
