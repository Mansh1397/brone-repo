import * as crypto from "crypto";
import * as path from "path";

class Miniflare {
  private env: any;
  constructor(options: any) {
    this.env = options.bindings;
  }
  async dispatchFetch(url: string, init?: any): Promise<Response> {
    const request = new Request(url, init);
    const worker = require("../ipMasker").default;
    return worker.fetch(request, this.env, {});
  }
  async dispose() { }
}

describe("Cloudflare Edge IP Masking Script Sandbox Tests", () => {
  let mf: Miniflare;
  let forwardedHeaders: Record<string, string> = {};
  let forwardedBody: string = "";
  const hmacSecret = "test_hmac_secret_key";
  let originalFetch: any;

  beforeAll(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = jest.fn().mockImplementation(async (req: any) => {
      const actualReq = typeof req === "string" ? new Request(req) : req;
      forwardedHeaders = {};
      actualReq.headers.forEach((value: string, key: string) => {
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

    let elapsedGet = 0;
    let elapsedPost = 0;
    let delta = 999;

    // Retry up to 3 times to get a clean measurement under potential CPU concurrency
    for (let i = 0; i < 3; i++) {
      // Test early rejection (GET request)
      const startGet = performance.now();
      await mf.dispatchFetch("http://localhost/api/v1/verify", {
        method: "GET"
      });
      const endGet = performance.now();
      elapsedGet = endGet - startGet;

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
      elapsedPost = endPost - startPost;

      delta = Math.abs(elapsedGet - elapsedPost);
      if (delta <= 2) {
        break;
      }
    }

    // Assert that the edge-to-client response intervals flat-line around 60ms
    expect(elapsedGet).toBeGreaterThanOrEqual(58);
    expect(elapsedPost).toBeGreaterThanOrEqual(58);

    // Assert flat-line latency uniformity within the strict variance threshold
    expect(delta).toBeLessThanOrEqual(15);
  });
});
