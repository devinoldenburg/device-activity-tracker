import { createPool, Pool, ResultSetHeader, RowDataPacket } from 'mysql2/promise';
import { PingEvent } from './ping-events.js';

type Platform = 'whatsapp';

export interface ContactRecord {
    contactKey: string;
    platform: Platform;
    number: string;
    createdAt: number;
    userId: number;
}

export interface StoredPing extends PingEvent {
    platform: Platform;
    userId: number;
}

export interface UserRecord {
    id: number;
    username: string;
    passwordHash: string;
    createdAt: number;
    role: 'admin' | 'user';
    status: 'pending' | 'approved';
}

const {
    MYSQL_HOST = 'localhost',
    MYSQL_PORT = '3306',
    MYSQL_USER = 'tracker',
    MYSQL_PASSWORD = 'tracker',
    MYSQL_DATABASE = 'tracker',
} = process.env;

export class ActivityStore {
    private pool: Pool;
    private ready: Promise<void>;
    private defaultUserId: number | null = null;

    constructor() {
        this.pool = createPool({
            host: MYSQL_HOST,
            port: Number(MYSQL_PORT),
            user: MYSQL_USER,
            password: MYSQL_PASSWORD,
            database: MYSQL_DATABASE,
            waitForConnections: true,
            connectionLimit: 10,
        });

        this.ready = this.init();
    }

    private async init() {
        await this.ensureConnection();
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at BIGINT NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                status VARCHAR(20) NOT NULL DEFAULT 'approved'
            );
        `);

        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS contacts (
                contact_key VARCHAR(255) PRIMARY KEY,
                platform VARCHAR(20) NOT NULL,
                number VARCHAR(255) NOT NULL,
                created_at BIGINT NOT NULL,
                user_id INT NOT NULL,
                CONSTRAINT fk_contacts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `);

        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS pings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                contact_key VARCHAR(255) NOT NULL,
                platform VARCHAR(20) NOT NULL,
                device_id VARCHAR(255) NOT NULL,
                state VARCHAR(50) NOT NULL,
                rtt INT NOT NULL,
                avg INT NOT NULL,
                median INT NOT NULL,
                threshold INT NOT NULL,
                ts BIGINT NOT NULL,
                user_id INT NOT NULL,
                CONSTRAINT fk_pings_contact FOREIGN KEY (contact_key) REFERENCES contacts(contact_key) ON DELETE CASCADE,
                CONSTRAINT fk_pings_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `);

        await this.ensureIndex('idx_pings_contact_ts', 'pings', '(contact_key, ts DESC)');
        await this.ensureIndex('idx_pings_platform', 'pings', '(platform)');
        await this.ensureIndex('idx_contacts_user', 'contacts', '(user_id)');
        await this.ensureIndex('idx_pings_user', 'pings', '(user_id)');

        const [userCountRows] = await this.pool.query<RowDataPacket[]>('SELECT COUNT(*) as c FROM users');
        const userCount = Number(userCountRows[0]?.c || 0);
        if (userCount === 0) {
            const now = Date.now();
            const [result] = await this.pool.query<ResultSetHeader>(
                'INSERT INTO users (username, password_hash, created_at, role, status) VALUES (?, ?, ?, ?, ?)',
                ['admin', 'changeme', now, 'admin', 'approved']
            );
            this.defaultUserId = Number(result.insertId);
        }

        await this.backfillUserIds();
    }

    private async ensureReady() {
        await this.ready;
    }

    private async ensureConnection(attempts: number = 5) {
        for (let i = 0; i < attempts; i++) {
            try {
                await this.pool.query('SELECT 1');
                return;
            } catch (err) {
                if (i === attempts - 1) throw err;
                const delay = 500 * (i + 1);
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    private async ensureIndex(indexName: string, table: string, definition: string) {
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT COUNT(*) as cnt
             FROM information_schema.statistics
             WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`,
            [table, indexName]
        );
        const exists = Number(rows[0]?.cnt || 0) > 0;
        if (!exists) {
            await this.pool.query(`CREATE INDEX ${indexName} ON ${table} ${definition}`);
        }
    }

    private async backfillUserIds() {
        const uid = this.defaultUserId || 1;
        await this.pool.query('UPDATE contacts SET user_id = ? WHERE user_id IS NULL', [uid]);
        await this.pool.query('UPDATE pings SET user_id = ? WHERE user_id IS NULL', [uid]);
    }

    public async upsertContact(contactKey: string, platform: Platform, number: string, userId: number) {
        await this.ensureReady();
        const createdAt = Date.now();
        await this.pool.query(
            `INSERT INTO contacts (contact_key, platform, number, created_at, user_id)
             VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE platform = VALUES(platform), number = VALUES(number), user_id = VALUES(user_id)`,
            [contactKey, platform, number, createdAt, userId]
        );
    }

    public async recordPing(input: StoredPing) {
        await this.ensureReady();
        await this.pool.query(
            `INSERT INTO pings (contact_key, platform, device_id, state, rtt, avg, median, threshold, ts, user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                input.contactId,
                input.platform,
                input.deviceId,
                input.state,
                Math.round(input.rtt),
                Math.round(input.avg),
                Math.round(input.median),
                Math.round(input.threshold),
                input.timestamp,
                input.userId,
            ]
        );
    }

    public async listContacts(userId: number): Promise<ContactRecord[]> {
        await this.ensureReady();
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT contact_key as contactKey, platform, number, created_at as createdAt, user_id as userId
             FROM contacts
             WHERE user_id = ?
             ORDER BY created_at DESC`,
            [userId]
        );
        return rows as ContactRecord[];
    }

    public async listPings(contactKey: string, userId: number, limit: number = 500): Promise<StoredPing[]> {
        await this.ensureReady();
        const safeLimit = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 5000) : 500;
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT contact_key as contactKey, platform, device_id as deviceId, state, rtt, avg, median, threshold, ts as timestamp, user_id as userId
             FROM pings
             WHERE contact_key = ? AND user_id = ?
             ORDER BY ts DESC
             LIMIT ?`,
            [contactKey, userId, safeLimit]
        );
        return rows as StoredPing[];
    }

    public async listAllContacts(): Promise<ContactRecord[]> {
        await this.ensureReady();
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT contact_key as contactKey, platform, number, created_at as createdAt, user_id as userId
             FROM contacts
             ORDER BY created_at DESC`
        );
        return rows as ContactRecord[];
    }

    public async countPings(userId?: number): Promise<number> {
        await this.ensureReady();
        if (typeof userId === 'number') {
            const [rows] = await this.pool.query<RowDataPacket[]>('SELECT COUNT(*) as cnt FROM pings WHERE user_id = ?', [userId]);
            return Number(rows[0]?.cnt || 0);
        }
        const [rows] = await this.pool.query<RowDataPacket[]>('SELECT COUNT(*) as cnt FROM pings');
        return Number(rows[0]?.cnt || 0);
    }

    public async createUser(
        username: string,
        passwordHash: string,
        role: 'admin' | 'user' = 'user',
        status: 'pending' | 'approved' = 'pending'
    ): Promise<number> {
        await this.ensureReady();
        const createdAt = Date.now();
        const [result] = await this.pool.query<ResultSetHeader>(
            `INSERT INTO users (username, password_hash, created_at, role, status)
             VALUES (?, ?, ?, ?, ?)`,
            [username, passwordHash, createdAt, role, status]
        );
        return Number(result.insertId);
    }

    public async findUser(username: string): Promise<UserRecord | null> {
        await this.ensureReady();
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT id, username, password_hash as passwordHash, created_at as createdAt, role, status
             FROM users
             WHERE username = ?
             LIMIT 1`,
            [username]
        );
        return (rows[0] as UserRecord) || null;
    }

    public async findUserById(userId: number): Promise<UserRecord | null> {
        await this.ensureReady();
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT id, username, password_hash as passwordHash, created_at as createdAt, role, status
             FROM users
             WHERE id = ?
             LIMIT 1`,
            [userId]
        );
        return (rows[0] as UserRecord) || null;
    }

    public async updateUsername(userId: number, username: string): Promise<void> {
        await this.ensureReady();
        await this.pool.query('UPDATE users SET username = ? WHERE id = ?', [username, userId]);
    }

    public async updatePasswordHash(userId: number, passwordHash: string): Promise<void> {
        await this.ensureReady();
        await this.pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, userId]);
    }

    public async clearUserData(userId: number): Promise<void> {
        await this.ensureReady();
        const conn = await this.pool.getConnection();
        try {
            await conn.beginTransaction();
            await conn.query('DELETE FROM pings WHERE user_id = ?', [userId]);
            await conn.query('DELETE FROM contacts WHERE user_id = ?', [userId]);
            await conn.commit();
        } catch (err) {
            await conn.rollback();
            throw err;
        } finally {
            conn.release();
        }
    }

    public async listUsers(): Promise<UserRecord[]> {
        await this.ensureReady();
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT id, username, password_hash as passwordHash, created_at as createdAt, role, status
             FROM users
             ORDER BY created_at ASC`
        );
        return rows as UserRecord[];
    }

    public async updateUserRoleStatus(userId: number, role: 'admin' | 'user', status: 'pending' | 'approved'): Promise<void> {
        await this.ensureReady();
        await this.pool.query('UPDATE users SET role = ?, status = ? WHERE id = ?', [role, status, userId]);
    }

    public async deleteUser(userId: number): Promise<void> {
        await this.ensureReady();
        await this.pool.query('DELETE FROM users WHERE id = ?', [userId]);
    }
}

export const activityStore = new ActivityStore();
