import request from "supertest";
import * as crypto from "crypto";
import app from "../index";
import { pool } from "../controllers/ringValidator";

// Mock database pool connection to prevent real database interactions during integration tests
jest.mock("../controllers/ringValidator", () => {
  const originalModule = jest.requireActual("../controllers/ringValidator");
  return {
    ...originalModule,
    pool: {
      connect: jest.fn(async () => {
        return {
          query: jest.fn(async (queryConfig: any, params?: any[]) => {
            const sqlText = typeof queryConfig === "string" ? queryConfig : queryConfig.text;
            if (sqlText.includes("SELECT 1 FROM spent_nullifiers")) {
              return { rows: [] };
            }
            if (sqlText.includes("INSERT INTO spent_nullifiers")) {
              return { rows: [] };
            }
            return { rows: [] };
          }),
          release: jest.fn()
        };
      }),
      end: jest.fn()
    }
  };
});

describe("Ingress and Router Lifecycle Hook Engine Integration Tests", () => {
  const hmacSecret = "test_hmac_secret_key";
  let originalEnvSecret: string | undefined;

  beforeAll(() => {
    originalEnvSecret = process.env.EDGE_SECRET_HMAC;
    process.env.EDGE_SECRET_HMAC = hmacSecret;
  });

  afterAll(async () => {
    process.env.EDGE_SECRET_HMAC = originalEnvSecret;
    await pool.end();
  });

  function computeSignatureHeader(body: string): string {
    const timestamp = Math.floor(Date.now() / 10000) * 10;
    const tsStr = String(timestamp);
    const tsBuffer = Buffer.from(tsStr);
    const bodyBuffer = Buffer.from(body);
    const combined = Buffer.concat([tsBuffer, bodyBuffer]);
    const signature = crypto
      .createHmac("sha256", hmacSecret)
      .update(combined)
      .digest("hex");
    return `${tsStr}.${signature}`;
  }

  it("should block POST request hitting the server without an X-Brone-Edge-Signature header with 403 Forbidden", async () => {
    const response = await request(app)
      .post("/api/v1/stamp")
      .send({ blindedTransaction: "12345" })
      .expect(403);

    expect(response.body).toEqual({ error: "Forbidden" });
    expect(response.headers["connection"]).toBe("close");
  });

  it("should permit validly signed payload to pass through perimeter check and route to downstream handler", async () => {
    // Generate valid payload
    const payloadObj = { blindedTransaction: "12345678901234567890" };
    const payloadStr = JSON.stringify(payloadObj);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/stamp")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payloadObj)
      .expect("Content-Type", /json/)
      .expect(200);

    expect(response.body).toHaveProperty("signature");
    expect(response.headers["connection"]).toBe("close");
  });

  it("should return identical 403 Forbidden with same payload structure for unsigned requests to non-existent routes", async () => {
    const response = await request(app)
      .post("/api/v1/invalid-route-path")
      .send({ some: "data" })
      .expect(403);

    expect(response.body).toEqual({ error: "Forbidden" });
    expect(response.headers["connection"]).toBe("close");
  });

  it("should automatically reject payloads larger than 50KB with 413 Payload Too Large", async () => {
    // Generate a payload that is strictly larger than 50KB (51200 bytes)
    const largeData = "A".repeat(55 * 1024);
    const payloadObj = { data: largeData };
    const payloadStr = JSON.stringify(payloadObj);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/stamp")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payloadObj)
      .expect(413);

    expect(response.body).toEqual({ error: "Payload Too Large" });
    expect(response.headers["connection"]).toBe("close");
  });
});
