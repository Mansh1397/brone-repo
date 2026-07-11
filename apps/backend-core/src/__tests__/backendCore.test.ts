import request from "supertest";
import app from "../index";
import { blindSignToken } from "../services/cryptoEngine";

// Set required environment variables for testing
process.env.ORIGIN_SIGNATURE_SECRET = "test_origin_secret_12345";
process.env.SERVER_PRIVATE_KEY_D = "2753";
process.env.SERVER_PRIVATE_KEY_N = "3233";
process.env.SERVER_PUBLIC_KEY_E = "17";

// Mock the Nullifier Registry to avoid hitting a real PostgreSQL database
jest.mock("../services/nullifierRegistry", () => {
  const original = jest.requireActual("../services/nullifierRegistry");
  const spentNullifiers = new Set<string>();
  return {
    ...original,
    processNullifier: jest.fn(async (nullifier: string) => {
      if (spentNullifiers.has(nullifier)) {
        throw new original.DoubleSpendException(`Nullifier ${nullifier} has already been spent.`);
      }
      spentNullifiers.add(nullifier);
    }),
  };
});

describe("Hardened Backend Origin Core - Security & Routing Tests", () => {
  const validSignature = "test_origin_secret_12345";

  describe("Origin Signature Gateway Middleware", () => {
    it("should drop connections with 401 when the signature header is missing", async () => {
      const res = await request(app)
        .post("/api/v1/stamp")
        .send({ blindedTransaction: "12345" });
      
      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: "Unauthorized" });
    });

    it("should drop connections with 401 when the signature header is invalid", async () => {
      const res = await request(app)
        .post("/api/v1/stamp")
        .set("X-Brone-Origin-Signature", "wrong_signature")
        .send({ blindedTransaction: "12345" });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: "Unauthorized" });
    });

    it("should allow request to proceed when the signature header is correct", async () => {
      const res = await request(app)
        .post("/api/v1/stamp")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({ blindedTransaction: "12345" });

      // We expect the request to bypass signature verification middleware
      expect(res.status).not.toBe(401);
    });
  });

  describe("STAMP Endpoint (POST /api/v1/stamp)", () => {
    it("should sign a valid blinded transaction successfully", async () => {
      const res = await request(app)
        .post("/api/v1/stamp")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({ blindedTransaction: "100" });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("signature");
      expect(typeof res.body.signature).toBe("string");
    });

    it("should fail with 400 if the payload parameter is not numeric", async () => {
      const res = await request(app)
        .post("/api/v1/stamp")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({ blindedTransaction: "abc" });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: "Invalid payload parameters" });
    });

    it("should fail with 400 if the payload parameter is too long", async () => {
      const longTx = "1".repeat(1001);
      const res = await request(app)
        .post("/api/v1/stamp")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({ blindedTransaction: longTx });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: "Invalid payload parameters" });
    });
  });

  describe("VERIFY Endpoint (POST /api/v1/verify)", () => {
    const validNullifier = "999";
    let validSig: string;

    beforeAll(() => {
      // Create a mathematically valid signature using our private key
      // Under modPow for RSA: s = m^d mod n. Since d=1025, n=2047.
      // S = 999^1025 mod 2047
      // Let's compute it via blindSignToken helper directly
      validSig = blindSignToken(validNullifier);
    });

    it("should verify a valid signature and nullifier combination successfully on first spend", async () => {
      const res = await request(app)
        .post("/api/v1/verify")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({
          nullifier: validNullifier,
          signature: validSig,
        });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "verified" });
    });

    it("should reject with 409 Conflict if a double spend is attempted with the same nullifier", async () => {
      const res = await request(app)
        .post("/api/v1/verify")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({
          nullifier: validNullifier,
          signature: validSig,
        });

      expect(res.status).toBe(409);
      expect(res.body).toEqual({ error: "Double Spend Detected" });
    });

    it("should reject with 401 if the cryptographic signature is invalid", async () => {
      const res = await request(app)
        .post("/api/v1/verify")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({
          nullifier: "123",
          signature: "99999", // wrong signature
        });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: "Invalid cryptographic signature" });
    });

    it("should reject with 400 for malformed parameters", async () => {
      const res = await request(app)
        .post("/api/v1/verify")
        .set("X-Brone-Origin-Signature", validSignature)
        .send({
          nullifier: "abc",
          signature: "123",
        });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: "Invalid payload parameters" });
    });
  });
});
