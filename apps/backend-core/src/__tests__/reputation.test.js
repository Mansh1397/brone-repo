"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const index_1 = __importDefault(require("../index"));
const crypto_1 = require("crypto");
const reputationManager_1 = require("../services/reputationManager");
const { subtle } = crypto_1.webcrypto;
// Setup env variables for testing
process.env.ORIGIN_SIGNATURE_SECRET = "test_origin_secret_12345";
describe("Decoupled Authenticated Reputation Ledger - API & Queue Tests", () => {
    const originSignature = "test_origin_secret_12345";
    let keyPair;
    let publicKeyHex;
    beforeAll(async () => {
        // Generate standard ECDSA P-256 key pair
        keyPair = await subtle.generateKey({
            name: "ECDSA",
            namedCurve: "P-256",
        }, true, ["sign", "verify"]);
        const exportedPublic = await subtle.exportKey("spki", keyPair.publicKey);
        publicKeyHex = Buffer.from(exportedPublic).toString("hex");
    });
    afterAll(async () => {
        // Teardown the background timer to prevent process hanging
        (0, reputationManager_1.stopQuantizedQueue)();
    });
    beforeEach(async () => {
        // Reset test database states
        await (0, reputationManager_1.resetReputationDatabase)();
    });
    async function createSignature(message) {
        const encoder = new TextEncoder();
        const sigBuffer = await subtle.sign({
            name: "ECDSA",
            hash: { name: "SHA-256" },
        }, keyPair.privateKey, encoder.encode(message));
        return Buffer.from(sigBuffer).toString("hex");
    }
    describe("POST /api/v1/reputation/increment", () => {
        it("should successfully queue reputation increment with valid signature, epoch, and nonce", async () => {
            const epoch = Date.now();
            const nonce = "test-nonce-123";
            const message = [
                publicKeyHex,
                "posts",
                "1",
                nonce,
                epoch.toString(),
            ].join(":");
            const signature = await createSignature(message);
            const res = await (0, supertest_1.default)(index_1.default)
                .post("/api/v1/reputation/increment")
                .set("X-Brone-Origin-Signature", originSignature)
                .send({
                reputation_key: publicKeyHex,
                metric_updates: {
                    metric_type: "posts",
                    delta_value: 1,
                },
                nonce,
                epoch,
                signature,
            });
            expect(res.status).toBe(200);
            expect(res.body).toEqual({ status: "queued" });
        });
        it("should reject requests when signature is invalid/mutated", async () => {
            const epoch = Date.now();
            const nonce = "test-nonce-invalid";
            const message = [
                publicKeyHex,
                "posts",
                "1",
                nonce,
                epoch.toString(),
            ].join(":");
            const signature = await createSignature(message);
            // Mutate payload metric to invalidate signature verification
            const res = await (0, supertest_1.default)(index_1.default)
                .post("/api/v1/reputation/increment")
                .set("X-Brone-Origin-Signature", originSignature)
                .send({
                reputation_key: publicKeyHex,
                metric_updates: {
                    metric_type: "posts",
                    delta_value: 2, // mutated from 1 to invalidate sig
                },
                nonce,
                epoch,
                signature,
            });
            expect(res.status).toBe(401);
            expect(res.body).toEqual({ error: "Invalid cryptographic signature" });
        });
        it("should reject requests when epoch timestamp is skewed beyond 5 seconds", async () => {
            const epoch = Date.now() - 6000; // skewed by 6 seconds in the past
            const nonce = "test-nonce-skewed";
            const message = [
                publicKeyHex,
                "posts",
                "1",
                nonce,
                epoch.toString(),
            ].join(":");
            const signature = await createSignature(message);
            const res = await (0, supertest_1.default)(index_1.default)
                .post("/api/v1/reputation/increment")
                .set("X-Brone-Origin-Signature", originSignature)
                .send({
                reputation_key: publicKeyHex,
                metric_updates: {
                    metric_type: "posts",
                    delta_value: 1,
                },
                nonce,
                epoch,
                signature,
            });
            expect(res.status).toBe(400);
            expect(res.body).toEqual({ error: "Timestamp deviation exceeds 5 seconds" });
        });
        it("should reject replayed requests with the same nonce", async () => {
            const epoch = Date.now();
            const nonce = "test-nonce-replay";
            const message = [
                publicKeyHex,
                "posts",
                "1",
                nonce,
                epoch.toString(),
            ].join(":");
            const signature = await createSignature(message);
            const payload = {
                reputation_key: publicKeyHex,
                metric_updates: {
                    metric_type: "posts",
                    delta_value: 1,
                },
                nonce,
                epoch,
                signature,
            };
            // First request (successful)
            const res1 = await (0, supertest_1.default)(index_1.default)
                .post("/api/v1/reputation/increment")
                .set("X-Brone-Origin-Signature", originSignature)
                .send(payload);
            expect(res1.status).toBe(200);
            // Replay request (rejected)
            const res2 = await (0, supertest_1.default)(index_1.default)
                .post("/api/v1/reputation/increment")
                .set("X-Brone-Origin-Signature", originSignature)
                .send(payload);
            expect(res2.status).toBe(409);
            expect(res2.body).toEqual({ error: "Replay detected: Nonce already spent" });
        });
    });
    describe("Quantized Queue Processing & Aggregation", () => {
        it("should accumulate delta values in memory and commit/aggregate them only after queue flush", async () => {
            // 1. Initially aggregates are all 0
            const initRes = await (0, supertest_1.default)(index_1.default)
                .get(`/api/v1/reputation/${publicKeyHex}`)
                .set("X-Brone-Origin-Signature", originSignature);
            expect(initRes.status).toBe(200);
            expect(initRes.body).toEqual({
                reputation_key: publicKeyHex,
                total_posts: 0,
                total_verifications: 0,
                rewards_balance: 0,
            });
            // 2. Queue updates
            const sendUpdate = async (type, val, nonce) => {
                const epoch = Date.now();
                const msg = [publicKeyHex, type, val.toString(), nonce, epoch.toString()].join(":");
                const sig = await createSignature(msg);
                return (0, supertest_1.default)(index_1.default)
                    .post("/api/v1/reputation/increment")
                    .set("X-Brone-Origin-Signature", originSignature)
                    .send({
                    reputation_key: publicKeyHex,
                    metric_updates: { metric_type: type, delta_value: val },
                    nonce,
                    epoch,
                    signature: sig,
                });
            };
            await sendUpdate("posts", 1, "n1");
            await sendUpdate("posts", 2, "n2");
            await sendUpdate("verifications", 5, "n3");
            await sendUpdate("rewards", 100, "n4");
            await sendUpdate("rewards", -10, "n5");
            // 3. Before queue flush, aggregates should still be 0 (queued but not flushed)
            const preFlushRes = await (0, supertest_1.default)(index_1.default)
                .get(`/api/v1/reputation/${publicKeyHex}`)
                .set("X-Brone-Origin-Signature", originSignature);
            expect(preFlushRes.body.total_posts).toBe(0);
            // 4. Manually trigger flushQueue
            await (0, reputationManager_1.flushQueue)();
            // 5. After flush, aggregates should be calculated correctly
            const postFlushRes = await (0, supertest_1.default)(index_1.default)
                .get(`/api/v1/reputation/${publicKeyHex}`)
                .set("X-Brone-Origin-Signature", originSignature);
            expect(postFlushRes.status).toBe(200);
            expect(postFlushRes.body).toEqual({
                reputation_key: publicKeyHex,
                total_posts: 3, // 1 + 2
                total_verifications: 5,
                rewards_balance: 90, // 100 - 10
            });
        });
        it("should throw error if queue size exceeds maximum limit", async () => {
            // Exceed queue limit (max 10000)
            let thrown = false;
            try {
                for (let i = 0; i < 10005; i++) {
                    await (0, reputationManager_1.queueReputationDelta)(publicKeyHex, "posts", 1);
                }
            }
            catch (err) {
                thrown = true;
                expect(err.message).toBe("Reputation queue buffer limit exceeded");
            }
            expect(thrown).toBe(true);
        });
    });
});
