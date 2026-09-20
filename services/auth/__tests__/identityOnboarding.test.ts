// Global mock placeholders
(global as any).mockRedisGet = jest.fn();
(global as any).mockRedisSet = jest.fn();
(global as any).mockRedisDel = jest.fn();
(global as any).mockPgQuery = jest.fn();

import { createHash } from "crypto";
import { requestOtp, verifyOtp, registerAnonymousKey } from "../identityProvider";
import { sessionManager, BlindVoucher } from "../../../apps/mobile/src/native/sessionManager";
import { Request, Response } from "express";

jest.mock("ioredis", () => {
  return jest.fn().mockImplementation(() => ({
    get: (global as any).mockRedisGet,
    set: (global as any).mockRedisSet,
    del: (global as any).mockRedisDel
  }));
}, { virtual: true });

const mockQueryFn = jest.fn();
const mockConnectFn = jest.fn().mockResolvedValue({
  query: mockQueryFn,
  release: jest.fn()
});

jest.mock("pg", () => ({
  Pool: jest.fn().mockImplementation(() => ({
    connect: mockConnectFn,
    query: mockQueryFn
  }))
}), { virtual: true });

jest.mock("argon2", () => ({
  hash: jest.fn().mockResolvedValue("$argon2id$v=19$m=65536,t=3,p=4$mockedhash"),
  argon2id: "argon2id"
}), { virtual: true });

// Utility to generate a valid PoW nonce for '0000' prefix
function generateMockNonce(phone: string): string {
  let nonce = 0;
  while (true) {
    const hash = createHash("sha256").update(phone + nonce).digest("hex");
    if (hash.startsWith("0000")) {
      return nonce.toString();
    }
    nonce++;
  }
}

const mockRedisGet = (global as any).mockRedisGet;
const mockRedisSet = (global as any).mockRedisSet;
const mockRedisDel = (global as any).mockRedisDel;

describe("Identity Onboarding, Stateless Express OTP, and Phase 1 Blind Auth", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
    req = { body: {} };
    res = { status: statusMock } as any;
  });

  describe("Block 1: Stateless Express OTP & Blind OTP Handshake", () => {
    it("should reject OTP request with 400 if the Anti-DoS Proof-of-Work gate validation fails", async () => {
      req.body = { phoneNumber: "+1234567890", powNonce: "invalid-nonce" };

      await requestOtp(req as any, res as any);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({ error: "Invalid Proof-of-Work token." });
    });

    it("should accept OTP request when a valid PoW nonce is supplied, store in Redis, and return 200", async () => {
      const phone = "+1234567890";
      const validNonce = generateMockNonce(phone);
      req.body = { phoneNumber: phone, powNonce: validNonce };

      await requestOtp(req as any, res as any);

      expect(mockRedisSet).toHaveBeenCalledWith(`otp:${phone}`, expect.any(String), "EX", 300);
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: "OTP generated successfully"
      });
    });

    it("should return 401 on incorrect/expired OTP during verification", async () => {
      const phone = "+1234567890";
      req.body = { phoneNumber: phone, otpCode: "000000", blindedTokenT: "12345" };
      mockRedisGet.mockResolvedValue(null);

      await verifyOtp(req as Request, res as Response);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ error: "Invalid or expired OTP credentials." });
    });

    it("should verify correct OTP, atomic check verified_phones_hashes, and return signed blinded token S'", async () => {
      const phone = "+1234567890";
      req.body = { phoneNumber: phone, otpCode: "123456", blindedTokenT: "12345" };
      mockQueryFn.mockResolvedValue({ rows: [] });

      await verifyOtp(req as Request, res as Response);

      expect(mockRedisDel).toHaveBeenCalledWith(`otp:${phone}`);
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          signedBlindedTokenSPrime: expect.any(String)
        })
      );
    });
  });

  describe("Block 2: Anonymous Key Registration & Hardware Persistence", () => {
    it("should store blind vouchers using NativeModules wrappers", async () => {
      const vouchers: BlindVoucher[] = [
        { blindedSignature: "sig1", publicKey: "pub1" }
      ];

      await sessionManager.storeSessionCredentials(vouchers);
      const { NativeModules } = require("react-native");
      expect(NativeModules.MainActivity.saveSecureSessionElement).toHaveBeenCalledWith(
        "vouchers",
        JSON.stringify(vouchers)
      );
    });
  });
});
