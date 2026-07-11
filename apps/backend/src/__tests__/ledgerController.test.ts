import express from "express";
import request from "supertest";
import crypto from "crypto";
import { handleMetricIncrement } from "../controllers/ledgerController";
import { pool } from "../controllers/ringValidator";

// Mock the database pool
jest.mock("../controllers/ringValidator", () => {
  const originalModule = jest.requireActual("../controllers/ringValidator");
  let mockQueryFn = jest.fn(async () => ({ rows: [] }));
  
  return {
    ...originalModule,
    pool: {
      connect: jest.fn(async () => {
        return {
          query: mockQueryFn,
          release: jest.fn()
        };
      })
    }
  };
});

const app = express();
app.use(express.json());
app.post("/api/v1/reputation/increment", handleMetricIncrement);

describe("ECDSA Reputation Telemetry Ledger Controller Unit Tests", () => {
  let ecPrivateKey: crypto.KeyObject;
  let ecPublicKeyHex: string;

  beforeAll(() => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    ecPrivateKey = privateKey;
    ecPublicKeyHex = publicKey.export({ format: "der", type: "spki" }).toString("hex");
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  function generateValidPayload() {
    const nonce = crypto.randomUUID();
    const epoch = Date.now();
    const metric_updates: Record<string, number> = { posts: 1 };
    
    // Sort metrics alphabetically to match canonical serialization
    const sortedMetrics = Object.keys(metric_updates).sort().reduce((obj: any, key) => {
      obj[key] = metric_updates[key];
      return obj;
    }, {});

    const msg = JSON.stringify({
      reputation_key: ecPublicKeyHex,
      metric_updates: sortedMetrics,
      nonce,
      epoch
    });

    const signature = crypto.sign(
      "SHA256",
      Buffer.from(msg),
      {
        key: ecPrivateKey,
        dsaEncoding: "ieee-p1363"
      }
    ).toString("hex");

    return {
      reputation_key: ecPublicKeyHex,
      metric_updates,
      nonce,
      epoch,
      signature
    };
  }

  it("should successfully process and persist valid metric updates", async () => {
    const payload = generateValidPayload();
    
    // Setup query mocks
    const clientMockQuery = jest.fn(async () => ({ rows: [] }));
    (pool.connect as jest.Mock).mockImplementationOnce(async () => {
      return {
        query: clientMockQuery,
        release: jest.fn()
      };
    });

    const response = await request(app)
      .post("/api/v1/reputation/increment")
      .send(payload)
      .expect(200);

    expect(response.body).toEqual({
      success: true,
      message: "Ledger transaction committed successfully."
    });

    // Check transaction flow: BEGIN -> INSERT signature -> INSERT reputation_ledger -> COMMIT
    expect(clientMockQuery).toHaveBeenCalledWith("BEGIN");
    expect(clientMockQuery).toHaveBeenCalledWith(expect.objectContaining({
      text: expect.stringContaining("INSERT INTO signatures")
    }));
    expect(clientMockQuery).toHaveBeenCalledWith(expect.objectContaining({
      text: expect.stringContaining("INSERT INTO reputation_ledger")
    }));
    expect(clientMockQuery).toHaveBeenCalledWith("COMMIT");
  });

  it("should return 401 Unauthorized for an invalid signature", async () => {
    const payload = generateValidPayload();
    payload.signature = "abcd" + payload.signature.substring(4); // corrupt signature

    const response = await request(app)
      .post("/api/v1/reputation/increment")
      .send(payload)
      .expect(401);

    expect(response.body).toEqual({
      error: "Security Denial: ECDSA payload validation mismatch."
    });
  });

  it("should roll back and return 409 Conflict when a duplicate signature is submitted (replay protection)", async () => {
    const payload = generateValidPayload();
    
    // Simulate unique constraint violation error (code 23505) in Postgres
    const clientMockQuery = jest.fn(async (sql: any) => {
      const sqlText = typeof sql === "string" ? sql : sql.text;
      if (sqlText && sqlText.includes("INSERT INTO signatures")) {
        const err = new Error("duplicate key value violates unique constraint") as any;
        err.code = "23505";
        throw err;
      }
      return { rows: [] };
    });
    
    (pool.connect as jest.Mock).mockImplementationOnce(async () => {
      return {
        query: clientMockQuery,
        release: jest.fn()
      };
    });

    const response = await request(app)
      .post("/api/v1/reputation/increment")
      .send(payload)
      .expect(409);

    expect(response.body).toEqual({
      error: "Security Collision: Signature replay state detected."
    });

    expect(clientMockQuery).toHaveBeenCalledWith("BEGIN");
    expect(clientMockQuery).toHaveBeenCalledWith("ROLLBACK");
    expect(clientMockQuery).not.toHaveBeenCalledWith("COMMIT");
  });

  it("should return 400 Bad Request if structural fields are missing", async () => {
    const response = await request(app)
      .post("/api/v1/reputation/increment")
      .send({ reputation_key: ecPublicKeyHex })
      .expect(400);

    expect(response.body).toEqual({
      error: "Missing required tracking parameters inside payload wrapper."
    });
  });
});
