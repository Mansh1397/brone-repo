import request from "supertest";
import * as crypto from "crypto";
import app from "../index";
import { pool } from "../controllers/ringValidator";

// Clean, isolated mock of the database pool and ring validator handler
const mockQuery = jest.fn();
jest.mock("../controllers/ringValidator", () => {
  return {
    verifyRingHandler: jest.fn((req: any, res: any) => res.sendStatus(200)),
    pool: {
      query: (config: any, values?: any[]) => mockQuery(config, values),
      connect: jest.fn(),
      end: jest.fn()
    }
  };
});

describe("Arbitration Endpoint Structural & Database Integration Tests", () => {
  const { publicKey: testPostPubKey, privateKey: testPostPrivKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  const validKey = testPostPubKey.export({ type: "spki", format: "der" }).toString("hex");
  const validCIDv0 = "Qm" + "c".repeat(44); // valid CIDv0 of length 46
  const validCIDv1 = "bafy" + "d".repeat(55); // valid CIDv1 of length 59
  const validBlindedTx = "12345678901234567890";
  const validNonce = "test-nonce-123";

  const hmacSecret = "test_hmac_secret_key";
  let originalEnvSecret: string | undefined;

  beforeAll(() => {
    originalEnvSecret = process.env.EDGE_SECRET_HMAC;
    process.env.EDGE_SECRET_HMAC = hmacSecret;
  });

  afterAll(async () => {
    process.env.EDGE_SECRET_HMAC = originalEnvSecret;
    if (pool && typeof pool.end === "function") {
      await pool.end();
    }
  });

  beforeEach(() => {
    mockQuery.mockReset();
    mockQuery.mockResolvedValue({ rows: [] });
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

  function signPostPayload(content: string, nonce: string, epoch: number): string {
    const msg = `${content}${nonce}${epoch}`;
    return crypto.sign(
      "SHA256",
      Buffer.from(msg),
      {
        key: testPostPrivKey,
        dsaEncoding: "ieee-p1363"
      }
    ).toString("hex");
  }

  const getValidPayload = (cid = validCIDv0, epoch = Date.now()) => {
    const payload: any = {
      reputation_key: validKey,
      content: cid,
      blindedTransaction: validBlindedTx,
      nonce: validNonce,
      epoch
    };
    payload.signature = signPostPayload(payload.content, payload.nonce, payload.epoch);
    return payload;
  };

  it("should successfully register arbitration and query database when payload is valid (CIDv0)", async () => {
    const payload = getValidPayload();
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(201);

    expect(response.body).toEqual({
      success: true,
      message: "Arbitration task successfully registered."
    });

    expect(mockQuery).toHaveBeenCalledTimes(1);
    expect(mockQuery.mock.calls[0][0].text).toContain("INSERT INTO decentralized_posts");
    expect(mockQuery.mock.calls[0][0].values).toEqual([payload.content, payload.blindedTransaction]);
  });

  it("should successfully register arbitration and query database when payload is valid (CIDv1)", async () => {
    const payload = getValidPayload(validCIDv1);
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/jury/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(201);

    expect(response.body).toEqual({
      success: true,
      message: "Arbitration task successfully registered."
    });

    expect(mockQuery).toHaveBeenCalledTimes(1);
    expect(mockQuery.mock.calls[0][0].values).toEqual([payload.content, payload.blindedTransaction]);
  });

  it("should return 400 error on clock-skew validation failure and not query database", async () => {
    const payload = getValidPayload(validCIDv0, Date.now() - 70000); // 70 seconds skew
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(400);

    expect(response.body).toEqual({
      error: "Security Deviation: Epoch timestamp out of synchronization bounds."
    });

    expect(mockQuery).not.toHaveBeenCalled();
  });

  it("should return 400 error on invalid IPFS CID formatting and not query database", async () => {
    const payload = getValidPayload("QmInvalidCIDLength"); // Invalid length
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(400);

    expect(response.body).toEqual({
      error: "Security Denial: Cryptographic verification failed structural integrity checks"
    });

    expect(mockQuery).not.toHaveBeenCalled();
  });

  it("should return 400 error on invalid reputation key hexadecimal format and not query database", async () => {
    const payload = getValidPayload();
    payload.reputation_key = "z".repeat(182); // non-hex character 'z'
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(400);

    expect(response.body).toEqual({
      error: "Security Denial: Cryptographic verification failed structural integrity checks"
    });

    expect(mockQuery).not.toHaveBeenCalled();
  });

  it("should return 400 error on invalid signature length and not query database", async () => {
    const payload = getValidPayload();
    payload.signature = "b".repeat(100); // invalid signature length (expected 128-144)
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(400);

    expect(response.body).toEqual({
      error: "Security Denial: Cryptographic verification failed structural integrity checks"
    });

    expect(mockQuery).not.toHaveBeenCalled();
  });

  it("should return 400 error on cryptographic signature mismatch and not query database", async () => {
    const payload = getValidPayload();
    payload.signature = "f".repeat(128); // mathematically incorrect signature
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(400);

    expect(response.body).toEqual({
      error: "Security Denial: Cryptographic signature mismatch"
    });

    expect(mockQuery).not.toHaveBeenCalled();
  });

  it("should return 400 error on missing required properties and not query database", async () => {
    const payload = {
      reputation_key: validKey,
      content: validCIDv0
    } as any;
    const payloadStr = JSON.stringify(payload);
    const sigHeader = computeSignatureHeader(payloadStr);

    const response = await request(app)
      .post("/api/v1/arbitration")
      .set("X-Brone-Edge-Signature", sigHeader)
      .set("Authorization", "Bearer mock-token")
      .set("Content-Type", "application/json")
      .send(payload)
      .expect(400);

    expect(response.body).toEqual({
      error: "Security Denial: Cryptographic verification failed structural integrity checks"
    });

    expect(mockQuery).not.toHaveBeenCalled();
  });

  describe("Jury Ballot Voting & IPFS Extraction Extensions", () => {
    const { publicKey: testPubKey, privateKey: testPrivKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256"
    });
    const keyHex = testPubKey.export({ type: "spki", format: "der" }).toString("hex");

    function signVotePayload(payload: any): string {
      const msg = `${payload.ipfs_hash}${payload.blind_ballot_token}${payload.vote_decision}${payload.epoch}`;
      return crypto.sign(
        "SHA256",
        Buffer.from(msg),
        {
          key: testPrivKey,
          dsaEncoding: "ieee-p1363"
        }
      ).toString("hex");
    }

    const getValidVotePayload = (decision = "UPHOLD", epoch = Date.now()) => {
      const payload: any = {
        reputation_key: keyHex,
        ipfs_hash: validCIDv0,
        blind_ballot_token: "test-blind-token-12345",
        vote_decision: decision,
        epoch
      };
      payload.signature = signVotePayload(payload);
      return payload;
    };

    it("should successfully register UPHOLD vote decision and perform atomic DB increment", async () => {
      const payload = getValidVotePayload("UPHOLD");
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      mockQuery.mockResolvedValue({ rowCount: 1, rows: [] });

      const response = await request(app)
        .post("/api/v1/arbitration/vote")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        status: "success",
        message: "Vote successfully registered."
      });

      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0].text).toContain("UPDATE reputation_ledger");
      expect(mockQuery.mock.calls[0][0].text).toContain("value = value + 1");
      expect(mockQuery.mock.calls[0][0].values).toEqual(["arbitration_uphold"]);
    });

    it("should successfully register DISMISS vote decision and perform upsert fallback if rowCount is 0", async () => {
      const payload = getValidVotePayload("DISMISS");
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      mockQuery.mockResolvedValueOnce({ rowCount: 0 });
      mockQuery.mockResolvedValueOnce({ rows: [] });

      const response = await request(app)
        .post("/api/v1/jury/arbitration/vote")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(200);

      expect(response.body.status).toBe("success");
      expect(mockQuery).toHaveBeenCalledTimes(2);
      expect(mockQuery.mock.calls[1][0].text).toContain("INSERT INTO reputation_ledger");
      expect(mockQuery.mock.calls[1][0].values).toEqual(["arbitration_dismiss"]);
    });

    it("should return 400 when vote clock skew exceeds 60 seconds", async () => {
      const payload = getValidVotePayload("UPHOLD", Date.now() - 70000);
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      const response = await request(app)
        .post("/api/v1/arbitration/vote")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(400);

      expect(response.body.error).toContain("bounds");
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it("should return 400 on invalid public key length in vote payload", async () => {
      const payload = getValidVotePayload();
      payload.reputation_key = "a".repeat(10);
      payload.signature = signVotePayload(payload);
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      const response = await request(app)
        .post("/api/v1/arbitration/vote")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(400);

      expect(response.body.error).toContain("integrity");
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it("should return 400 on invalid IPFS CID in vote payload", async () => {
      const payload = getValidVotePayload();
      payload.ipfs_hash = "InvalidHash";
      payload.signature = signVotePayload(payload);
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      const response = await request(app)
        .post("/api/v1/arbitration/vote")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(400);

      expect(response.body.error).toContain("integrity");
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it("should return 400 on invalid signature in vote payload", async () => {
      const payload = getValidVotePayload();
      payload.signature = "a".repeat(128);
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      const response = await request(app)
        .post("/api/v1/arbitration/vote")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(400);

      expect(response.body.error).toContain("signature mismatch");
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it("should extract IPFS payload metadata successfully via GET/POST", async () => {
      const sigHeaderGet = computeSignatureHeader("");
      const getResponse = await request(app)
        .get(`/api/v1/posts/extract?ipfs_hash=${validCIDv0}`)
        .set("X-Brone-Edge-Signature", sigHeaderGet)
        .set("Authorization", "Bearer mock-token")
        .expect(200);

      expect(getResponse.body.ipfs_hash).toBe(validCIDv0);
      expect(getResponse.body.encrypted_payload).toBeDefined();

      const payload = { ipfs_hash: validCIDv0 };
      const payloadStr = JSON.stringify(payload);
      const sigHeader = computeSignatureHeader(payloadStr);

      const postResponse = await request(app)
        .post("/api/v1/posts/extract")
        .set("X-Brone-Edge-Signature", sigHeader)
        .set("Authorization", "Bearer mock-token")
        .set("Content-Type", "application/json")
        .send(payload)
        .expect(200);

      expect(postResponse.body.ipfs_hash).toBe(validCIDv0);
      expect(postResponse.body.encrypted_payload).toBeDefined();
    });

    it("should return 400 when attempting to extract with invalid IPFS CID", async () => {
      const sigHeaderGet = computeSignatureHeader("");
      await request(app)
        .get("/api/v1/posts/extract?ipfs_hash=invalid-cid-hash")
        .set("X-Brone-Edge-Signature", sigHeaderGet)
        .set("Authorization", "Bearer mock-token")
        .expect(400);
    });
  });
});
