"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = __importStar(require("crypto"));
class Miniflare {
    env;
    constructor(options) {
        this.env = options.bindings;
    }
    async dispatchFetch(url, init) {
        const request = new Request(url, init);
        const worker = require("../ipMasker").default;
        return worker.fetch(request, this.env, {});
    }
    async dispose() { }
}
describe("Cloudflare Edge IP Masking Script Sandbox Tests", () => {
    let mf;
    let forwardedHeaders = {};
    let forwardedBody = "";
    const hmacSecret = "test_hmac_secret_key";
    let originalFetch;
    beforeAll(() => {
        originalFetch = globalThis.fetch;
        globalThis.fetch = jest.fn().mockImplementation(async (req) => {
            const actualReq = typeof req === "string" ? new Request(req) : req;
            forwardedHeaders = {};
            actualReq.headers.forEach((value, key) => {
                forwardedHeaders[key.toLowerCase()] = value;
            });
            forwardedBody = await actualReq.text();
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        });
        mf = new Miniflare({
            bindings: {
                EDGE_SECRET_HMAC: hmacSecret
            }
        });
    });
    afterAll(async () => {
        globalThis.fetch = originalFetch;
        await mf.dispose();
    });
    beforeEach(() => {
        forwardedHeaders = {};
        forwardedBody = "";
    });
    it("should strip identifying client headers and copy only whitelisted ones", async () => {
        const payload = JSON.stringify({ test: "data" });
        await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "CF-Connecting-IP": "198.51.100.1",
                "X-Forwarded-For": "203.0.113.195",
                "True-Client-IP": "198.51.100.2",
                "X-Real-IP": "198.51.100.3",
                "CF-Ray": "ray-123456",
                "CF-Visitor": "visitor-123",
                "CF-Device-Type": "desktop"
            },
            body: payload
        });
        // Whitelisted headers should be present
        expect(forwardedHeaders["content-type"]).toBe("application/json");
        expect(forwardedHeaders["content-length"]).toBe(String(payload.length));
        // Stripped headers must be absent
        expect(forwardedHeaders["cf-connecting-ip"]).toBeUndefined();
        expect(forwardedHeaders["x-forwarded-for"]).toBeUndefined();
        expect(forwardedHeaders["true-client-ip"]).toBeUndefined();
        expect(forwardedHeaders["x-real-ip"]).toBeUndefined();
        expect(forwardedHeaders["cf-ray"]).toBeUndefined();
        expect(forwardedHeaders["cf-visitor"]).toBeUndefined();
        expect(forwardedHeaders["cf-device-type"]).toBeUndefined();
        // Standardized/Obfuscated User-Agent must be present
        expect(forwardedHeaders["user-agent"]).toContain("Mozilla/5.0");
    });
    it("should inject a cryptographically signed edge-verification HMAC token", async () => {
        const payload = JSON.stringify({ secure: "transaction" });
        await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: payload
        });
        const headerValue = forwardedHeaders["x-brone-edge-signature"];
        expect(headerValue).toBeDefined();
        const parts = headerValue.split(".");
        expect(parts.length).toBe(2);
        const [tsStr, signature] = parts;
        expect(signature.length).toBe(64); // SHA-256 Hex length
        // Calculate expected HMAC locally to verify signature validity
        const encoder = new TextEncoder();
        const tsBuffer = encoder.encode(tsStr);
        const payloadBuffer = encoder.encode(payload);
        const combined = new Uint8Array(tsBuffer.byteLength + payloadBuffer.byteLength);
        combined.set(tsBuffer, 0);
        combined.set(payloadBuffer, tsBuffer.byteLength);
        const expectedSignature = crypto
            .createHmac("sha256", hmacSecret)
            .update(combined)
            .digest("hex");
        expect(signature).toBe(expectedSignature);
    });
    it("should aggressively block non-POST requests and oversized payloads directly at the edge", async () => {
        // Non-POST request
        const responseGet = await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "GET"
        });
        expect(responseGet.status).toBe(400);
        // Oversized request (> 50KB)
        const largePayload = "a".repeat(51201);
        const responseLarge = await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "POST",
            headers: {
                "Content-Type": "text/plain"
            },
            body: largePayload
        });
        expect(responseLarge.status).toBe(400);
    });
    it("should return uniform response times (±2ms) for both early rejections and backend evaluations", async () => {
        // Warm up execution to bypass dynamic JS loading and Jest module caching
        await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "GET"
        });
        // Test early rejection (GET request)
        const startGet = performance.now();
        await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "GET"
        });
        const endGet = performance.now();
        const elapsedGet = endGet - startGet;
        // Test successful verification (POST request)
        const payload = JSON.stringify({ test: "timing" });
        const startPost = performance.now();
        await mf.dispatchFetch("http://localhost/api/v1/verify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: payload
        });
        const endPost = performance.now();
        const elapsedPost = endPost - startPost;
        // Assert that the edge-to-client response intervals flat-line around 60ms
        expect(elapsedGet).toBeGreaterThanOrEqual(58);
        expect(elapsedPost).toBeGreaterThanOrEqual(58);
        // Assert flat-line latency uniformity within the strict ±2ms variance threshold
        const delta = Math.abs(elapsedGet - elapsedPost);
        expect(delta).toBeLessThanOrEqual(2);
    });
});
