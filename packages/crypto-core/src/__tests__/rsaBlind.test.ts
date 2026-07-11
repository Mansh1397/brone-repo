import {
  modPow,
  modInverse,
  blindMessage,
  serverBlindSign,
  unblindSignature,
  verifyUnblindedSignature,
  RSAPublicKey,
  RSAPrivateKey
} from "../rsaBlind";

// Helper to dynamically calculate d given primes p, q and public exponent e
function deriveKeys(p: bigint, q: bigint, e: bigint): { publicKey: RSAPublicKey; privateKey: RSAPrivateKey } {
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const d = modInverse(e, phi);
  return {
    publicKey: { e, n },
    privateKey: { d, n }
  };
}

describe("RSA Blind Signatures Unit Tests", () => {
  // Test Case 1: Small Prime Parameters (N = 3233)
  describe("Small Prime Vector (N = 3233)", () => {
    const p = 61n;
    const q = 53n;
    const e = 17n;
    const { publicKey, privateKey } = deriveKeys(p, q, e);

    it("should match derived keys constraints", () => {
      expect(publicKey.n).toBe(3233n);
      expect(privateKey.d).toBe(2753n);
    });

    it("should correctly execute end-to-end blind signature flow", () => {
      const message = 123n;
      const blindingFactor = 7n;

      // 1. Blind message T = (x * r^e) % N
      const blinded = blindMessage(message, blindingFactor, publicKey);

      // 2. Server signs blinded message S' = T^d % N
      const blindSignature = serverBlindSign(blinded, privateKey);

      // 3. Client unblinds signature S = (S' * r^-1) % N
      const unblinded = unblindSignature(blindSignature, blindingFactor, publicKey.n);

      // 4. Verify unblinded signature S^e % N == x
      const isValid = verifyUnblindedSignature(message, unblinded, publicKey);
      expect(isValid).toBe(true);

      // Verify invalid message fails
      const isInvalidMsgValid = verifyUnblindedSignature(999n, unblinded, publicKey);
      expect(isInvalidMsgValid).toBe(false);
    });
  });

  // Test Case 2: Cryptographically Large Primes (approx. 80-bit integers for speed & safety)
  describe("Larger Prime Vector (80-bit range)", () => {
    // Verified primes
    const p = 100000000003n;
    const q = 100000000019n;
    const e = 65537n;
    const { publicKey, privateKey } = deriveKeys(p, q, e);

    it("should correctly execute end-to-end blind signature flow", () => {
      const message = 12345678901234567890n;
      const blindingFactor = 98765432109876543210n;

      // 1. Blind message
      const blinded = blindMessage(message, blindingFactor, publicKey);

      // 2. Server signs
      const blindSignature = serverBlindSign(blinded, privateKey);

      // 3. Client unblinds
      const unblinded = unblindSignature(blindSignature, blindingFactor, publicKey.n);

      // 4. Verify
      const isValid = verifyUnblindedSignature(message, unblinded, publicKey);
      expect(isValid).toBe(true);
    });
  });

  describe("Edge Cases and Validation Failures", () => {
    const p = 61n;
    const q = 53n;
    const e = 17n;
    const { publicKey, privateKey } = deriveKeys(p, q, e);

    it("should throw error if message is out of bounds (>= N)", () => {
      expect(() => {
        blindMessage(3500n, 7n, publicKey);
      }).toThrow("rawMessage must be non-negative and strictly less than the modulus N");
    });

    it("should throw error if message is negative", () => {
      expect(() => {
        blindMessage(-5n, 7n, publicKey);
      }).toThrow("rawMessage must be non-negative and strictly less than the modulus N");
    });

    it("should throw error if blinded message for server signature is out of bounds (>= N)", () => {
      expect(() => {
        serverBlindSign(3233n, privateKey);
      }).toThrow("blindedMessage must be non-negative and strictly less than the modulus N");
    });

    it("should fail validation if verification public key differs", () => {
      const message = 42n;
      const blindingFactor = 11n;
      const blinded = blindMessage(message, blindingFactor, publicKey);
      const blindSignature = serverBlindSign(blinded, privateKey);
      const unblinded = unblindSignature(blindSignature, blindingFactor, publicKey.n);

      const badPublicKey: RSAPublicKey = {
        e: 17n,
        n: 3239n // incorrect modulus
      };

      const isValid = verifyUnblindedSignature(message, unblinded, badPublicKey);
      expect(isValid).toBe(false);
    });

    it("should throw error if attempting to calculate inverse of non-coprime elements", () => {
      // 61 is a factor of N = 3233. 61 is not coprime to N, so inverse modulo N does not exist.
      expect(() => {
        modInverse(61n, 3233n);
      }).toThrow();
    });
  });

  describe("Helper Functions", () => {
    it("modPow should compute modular exponentiation correctly", () => {
      expect(modPow(2n, 10n, 1000n)).toBe(24n); // 1024 % 1000 = 24
      expect(modPow(5n, 3n, 13n)).toBe(8n);     // 125 % 13 = 8 (13*9=117, 125-117=8)
      expect(modPow(-3n, 3n, 10n)).toBe(3n);    // (-27) % 10 = -7 -> 3
    });
  });
});
