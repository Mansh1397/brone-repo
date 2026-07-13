"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyReputationSignature = verifyReputationSignature;
exports.checkAndRecordNonce = checkAndRecordNonce;
exports.queueReputationDelta = queueReputationDelta;
exports.flushQueue = flushQueue;
exports.getReputation = getReputation;
exports.startQuantizedQueue = startQuantizedQueue;
exports.stopQuantizedQueue = stopQuantizedQueue;
exports.resetReputationDatabase = resetReputationDatabase;
const crypto_1 = require("crypto");
const nullifierRegistry_1 = require("./nullifierRegistry");
const { subtle } = crypto_1.webcrypto;
const mockLedger = [];
const mockNonces = new Set();
const queue = [];
const MAX_QUEUE_SIZE = 10000;
let useMemoryDb = false;
let schemaInitialized = false;
let intervalId = null;
async function ensureSchema() {
    if (schemaInitialized || !process.env.DATABASE_URL || useMemoryDb)
        return;
    let client = null;
    try {
        client = await nullifierRegistry_1.pool.connect();
        await client.query(`
      CREATE TABLE IF NOT EXISTS reputation_ledger_entries (
        id SERIAL PRIMARY KEY,
        reputation_key TEXT NOT NULL,
        metric_type TEXT NOT NULL CHECK (metric_type IN ('posts', 'verifications', 'rewards')),
        delta_value INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_reputation_ledger_key ON reputation_ledger_entries(reputation_key);

      CREATE TABLE IF NOT EXISTS used_nonces (
        nonce TEXT PRIMARY KEY,
        used_at TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE OR REPLACE VIEW reputation_aggregates AS
      SELECT
        reputation_key,
        COALESCE(SUM(CASE WHEN metric_type = 'posts' THEN delta_value ELSE 0 END), 0) AS total_posts,
        COALESCE(SUM(CASE WHEN metric_type = 'verifications' THEN delta_value ELSE 0 END), 0) AS total_verifications,
        COALESCE(SUM(CASE WHEN metric_type = 'rewards' THEN delta_value ELSE 0 END), 0) AS rewards_balance
      FROM reputation_ledger_entries
      GROUP BY reputation_key;
    `);
        schemaInitialized = true;
    }
    catch (err) {
        console.warn("[REPUTATION MANAGER] Failed to initialize DB schemas, falling back to memory:", err);
        useMemoryDb = true;
    }
    finally {
        if (client) {
            try {
                client.release();
            }
            catch (_) { }
        }
    }
}
async function verifyReputationSignature(reputationKeyHex, signatureHex, message) {
    try {
        const publicKeyBuffer = Buffer.from(reputationKeyHex, "hex");
        const signatureBuffer = Buffer.from(signatureHex, "hex");
        const messageBuffer = new TextEncoder().encode(message);
        const cryptoKey = await subtle.importKey("spki", publicKeyBuffer, {
            name: "ECDSA",
            namedCurve: "P-256",
        }, true, ["verify"]);
        return await subtle.verify({
            name: "ECDSA",
            hash: { name: "SHA-256" },
        }, cryptoKey, signatureBuffer, messageBuffer);
    }
    catch (err) {
        return false;
    }
}
async function checkAndRecordNonce(nonce) {
    if (useMemoryDb || !process.env.DATABASE_URL) {
        if (mockNonces.has(nonce)) {
            throw new Error("Nonce already spent");
        }
        mockNonces.add(nonce);
        return;
    }
    await ensureSchema();
    let client = null;
    try {
        client = await nullifierRegistry_1.pool.connect();
        await client.query("INSERT INTO used_nonces (nonce) VALUES ($1);", [nonce]);
    }
    catch (err) {
        if (err.code === "23505") {
            throw new Error("Nonce already spent");
        }
        throw err;
    }
    finally {
        if (client) {
            try {
                client.release();
            }
            catch (_) { }
        }
    }
}
async function queueReputationDelta(reputationKey, metricType, deltaValue) {
    if (queue.length >= MAX_QUEUE_SIZE) {
        throw new Error("Reputation queue buffer limit exceeded");
    }
    queue.push({
        reputation_key: reputationKey,
        metric_type: metricType,
        delta_value: deltaValue,
    });
}
async function flushQueue() {
    if (queue.length === 0)
        return;
    const batch = [...queue];
    queue.length = 0;
    if (useMemoryDb || !process.env.DATABASE_URL) {
        mockLedger.push(...batch);
        return;
    }
    await ensureSchema();
    let client = null;
    try {
        client = await nullifierRegistry_1.pool.connect();
        await client.query("BEGIN");
        const valuePlaceholders = batch
            .map((_, i) => `($${i * 3 + 1}, $${i * 3 + 2}, $${i * 3 + 3})`)
            .join(", ");
        const values = batch.flatMap((entry) => [
            entry.reputation_key,
            entry.metric_type,
            entry.delta_value,
        ]);
        await client.query(`INSERT INTO reputation_ledger_entries (reputation_key, metric_type, delta_value) VALUES ${valuePlaceholders}`, values);
        await client.query("COMMIT");
    }
    catch (err) {
        if (client) {
            await client.query("ROLLBACK").catch(() => { });
        }
        console.error("[REPUTATION MANAGER] Failed to flush reputation queue to Postgres, falling back to memory:", err);
        mockLedger.push(...batch);
        useMemoryDb = true;
    }
    finally {
        if (client) {
            try {
                client.release();
            }
            catch (_) { }
        }
    }
}
async function getReputation(reputationKey) {
    if (useMemoryDb || !process.env.DATABASE_URL) {
        const entries = mockLedger.filter((e) => e.reputation_key === reputationKey);
        const total_posts = entries
            .filter((e) => e.metric_type === "posts")
            .reduce((sum, e) => sum + e.delta_value, 0);
        const total_verifications = entries
            .filter((e) => e.metric_type === "verifications")
            .reduce((sum, e) => sum + e.delta_value, 0);
        const rewards_balance = entries
            .filter((e) => e.metric_type === "rewards")
            .reduce((sum, e) => sum + e.delta_value, 0);
        return {
            reputation_key: reputationKey,
            total_posts,
            total_verifications,
            rewards_balance,
        };
    }
    await ensureSchema();
    let client = null;
    try {
        client = await nullifierRegistry_1.pool.connect();
        const res = await client.query("SELECT total_posts, total_verifications, rewards_balance FROM reputation_aggregates WHERE reputation_key = $1", [reputationKey]);
        if (res.rows.length === 0) {
            return {
                reputation_key: reputationKey,
                total_posts: 0,
                total_verifications: 0,
                rewards_balance: 0,
            };
        }
        const row = res.rows[0];
        return {
            reputation_key: reputationKey,
            total_posts: parseInt(row.total_posts, 10) || 0,
            total_verifications: parseInt(row.total_verifications, 10) || 0,
            rewards_balance: parseInt(row.rewards_balance, 10) || 0,
        };
    }
    catch (err) {
        console.error("[REPUTATION MANAGER] Failed to fetch reputation from Postgres:", err);
        const entries = mockLedger.filter((e) => e.reputation_key === reputationKey);
        const total_posts = entries
            .filter((e) => e.metric_type === "posts")
            .reduce((sum, e) => sum + e.delta_value, 0);
        const total_verifications = entries
            .filter((e) => e.metric_type === "verifications")
            .reduce((sum, e) => sum + e.delta_value, 0);
        const rewards_balance = entries
            .filter((e) => e.metric_type === "rewards")
            .reduce((sum, e) => sum + e.delta_value, 0);
        return {
            reputation_key: reputationKey,
            total_posts,
            total_verifications,
            rewards_balance,
        };
    }
    finally {
        if (client) {
            try {
                client.release();
            }
            catch (_) { }
        }
    }
}
function startQuantizedQueue(intervalMs = 30000) {
    if (intervalId)
        return;
    intervalId = setInterval(flushQueue, intervalMs);
    if (intervalId.unref) {
        intervalId.unref();
    }
}
function stopQuantizedQueue() {
    if (intervalId) {
        clearInterval(intervalId);
        intervalId = null;
    }
}
async function resetReputationDatabase() {
    mockLedger.length = 0;
    mockNonces.clear();
    queue.length = 0;
    useMemoryDb = false;
    schemaInitialized = false;
    if (process.env.DATABASE_URL) {
        let client = null;
        try {
            client = await nullifierRegistry_1.pool.connect();
            await client.query("TRUNCATE TABLE reputation_ledger_entries RESTART IDENTITY CASCADE;");
            await client.query("TRUNCATE TABLE used_nonces RESTART IDENTITY CASCADE;");
        }
        catch (err) {
            console.warn("[REPUTATION MANAGER] Failed to truncate reputation tables:", err);
        }
        finally {
            if (client) {
                try {
                    client.release();
                }
                catch (_) { }
            }
        }
    }
}
// Automatically start the background processor
startQuantizedQueue();
