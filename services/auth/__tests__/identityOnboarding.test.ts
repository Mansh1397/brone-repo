// Global mock placeholders to bypass Jest hoisting limitations
(global as any).mockRedisGet = jest.fn();
(global as any).mockRedisSet = jest.fn();
(global as any).mockRedisDel = jest.fn();
(global as any).mockPgQuery = jest.fn();

import { createHash, randomBytes } from "crypto";
import { requestOtp, verifyOtp } from "../identityProvider";
import { sessionManager, BlindVoucher } from "../../../apps/mobile/src/native/sessionManager";
import { Request, Response } from "express";

jest.mock("ioredis", () => {
  return jest.fn().mockImplementation(() => ({
    get: (global as any).mockRedisGet,
    set: (global as any).mockRedisSet,
    del: (global as any).mockRedisDel
  }));
}, { virtual: true });

jest.mock("pg", () => ({
  Client: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    query: (global as any).mockPgQuery
  }))
}), { virtual: true });

jest.mock("argon2", () => ({
  hash: jest.fn().mockResolvedValue("$argon2id$v=19$m=65536,t=3,p=4$mockedhash"),
  argon2id: "argon2id"
}), { virtual: true });

jest.mock("axios", () => ({
  post: jest.fn().mockResolvedValue({ status: 200 })
}), { virtual: true });

// Mock React Native platforms and NativeModules
jest.mock("react-native", () => ({
  Platform: { OS: "android" },
  NativeModules: {
    MainActivity: {
      saveSecureSessionElement: jest.fn(),
      purgeSecureSession: jest.fn()
    },
    AppDelegate: {
      saveSecureKeychainItem: jest.fn(),
      purgeSecureKeychain: jest.fn()
    }
  }
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
const mockPgQuery = (global as any).mockPgQuery;

describe("Identity Onboarding, Stateless Express OTP, and Hardware Session Persistence (Phase 11G v2 / 11H)", () => {
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

  describe("Block 1: Stateless Express OTP & Argon2id Identity Provider", () => {
    it("should reject OTP request with 400 if the Anti-DoS Proof-of-Work gate validation fails", async () => {
      req.body = { phoneNumber: "+1234567890", powNonce: "invalid-nonce" };

      await requestOtp(req as Request, res as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({ error: "Invalid Proof-of-Work token." });
    });

    it("should accept OTP request when a valid PoW nonce is supplied, store in Redis, and return 200", async () => {
      const phone = "+1234567890";
      const validNonce = generateMockNonce(phone);
      req.body = { phoneNumber: phone, powNonce: validNonce };

      await requestOtp(req as Request, res as Response);

      expect(mockRedisSet).toHaveBeenCalledWith(`otp:${phone}`, expect.any(String), "EX", 120);
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        success: true,
        message: "Verification token dispatched."
      });
    });

    it("should enforce timing-padding delays and return 401 on incorrect/expired OTP during verification", async () => {
      const phone = "+1234567890";
      req.body = { phoneNumber: phone, otpCode: "123456", clientPublicKey: "mocked-public-key" };
      mockRedisGet.mockResolvedValue(null); // Simulated cache miss

      const start = Date.now();
      await verifyOtp(req as Request, res as Response);
      const duration = Date.now() - start;

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ error: "Invalid or expired credentials." });
      expect(duration).networkTimingCloseTo(200);
    });

    it("should verify correct OTP, persist client public key, and issue blind voucher envelope", async () => {
      const phone = "+1234567890";
      req.body = { phoneNumber: phone, otpCode: "999999", clientPublicKey: "mocked-public-key" };
      mockRedisGet.mockResolvedValue("999999");
      mockPgQuery.mockResolvedValue({ rows: [] });

      await verifyOtp(req as Request, res as Response);

      expect(mockRedisGet).toHaveBeenCalledWith(`otp:${phone}`);
      expect(mockRedisDel).toHaveBeenCalledWith(`otp:${phone}`);
      expect(mockPgQuery).toHaveBeenCalledWith(
        expect.stringContaining("INSERT INTO user_identities"),
        expect.arrayContaining(["mocked-public-key"])
      );
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          blindVoucherEnvelope: expect.any(String)
        })
      );
    });
  });

  describe("Block 2: Hardware-Backed Device Session Persistence", () => {
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

    it("should dynamically derive a secure SQLCipher key from hardware boundaries on request", async () => {
      const key1 = await sessionManager.deriveSqlCipherKey();
      const key2 = await sessionManager.deriveSqlCipherKey();
      
      expect(key1).toBeDefined();
      expect(key1.length).toBe(64); // 32-byte hex key representation
      expect(key1).toBe(key2); // Cached key returns consistently
    });

    it("should violently destroy active socket descriptors and apply randomized delay offsets upon session severing", async () => {
      const mockSocket = {
        destroy: jest.fn()
      };

      const start = Date.now();
      await sessionManager.severAndRotateSession(mockSocket);
      const duration = Date.now() - start;

      expect(mockSocket.destroy).toHaveBeenCalled();
      expect(duration).toBeGreaterThanOrEqual(200); // verify delay applied
    });

    it("should clean all local arrays, purge enclaves, and revoke backend sessions on User Logout", async () => {
      const mockFetch = jest.fn().mockResolvedValue({ status: 200 });
      global.fetch = mockFetch as any;

      const vouchers: BlindVoucher[] = [
        { blindedSignature: "sig1", publicKey: "pub1" }
      ];

      await sessionManager.storeSessionCredentials(vouchers);
      await sessionManager.executeLogoutPurge("https://api.brone/auth/logout");

      expect(mockFetch).toHaveBeenCalledWith("https://api.brone/auth/logout", expect.any(Object));
      
      const { NativeModules } = require("react-native");
      expect(NativeModules.MainActivity.purgeSecureSession).toHaveBeenCalled();
    });
  });
});

// Custom expectation helper to verify network timing padding
expect.extend({
  networkTimingCloseTo(received: number, expected: number) {
    const pass = received >= expected - 30; // allows margin of timing variance in node runner
    if (pass) {
      return {
        message: () => `expected timing not to be close to ${expected} ms`,
        pass: true
      };
    } else {
      return {
        message: () => `expected timing to be at least close to ${expected} ms, received ${received} ms`,
        pass: false
      };
    }
  }
});

declare global {
  namespace jest {
    interface Matchers<R> {
      networkTimingCloseTo(expected: number): R;
    }
  }
}
