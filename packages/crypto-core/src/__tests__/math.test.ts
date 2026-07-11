import { gcd, safeModularInverse } from "../utils/math";

describe("Mathematical Cryptographic Utilities", () => {
  describe("gcd", () => {
    it("should compute the greatest common divisor of positive numbers", () => {
      expect(gcd(12n, 18n)).toBe(6n);
      expect(gcd(101n, 103n)).toBe(1n); // Coprime primes
      expect(gcd(0n, 5n)).toBe(5n);
      expect(gcd(5n, 0n)).toBe(5n);
    });

    it("should handle negative inputs correctly by taking absolute values", () => {
      expect(gcd(-12n, 18n)).toBe(6n);
      expect(gcd(12n, -18n)).toBe(6n);
      expect(gcd(-12n, -18n)).toBe(6n);
    });
  });

  describe("safeModularInverse", () => {
    it("should calculate correct modular inverse for coprime inputs", () => {
      // 3 * 7 = 21 = 1 mod 10 -> inverse of 3 mod 10 is 7
      expect(safeModularInverse(3n, 10n)).toBe(7n);
      // 7 * 3 = 21 = 1 mod 10 -> inverse of 7 mod 10 is 3
      expect(safeModularInverse(7n, 10n)).toBe(3n);
      // 9 * 9 = 81 = 1 mod 10 -> inverse of 9 mod 10 is 9
      expect(safeModularInverse(9n, 10n)).toBe(9n);
    });

    it("should normalize negative 'a' parameter correctly", () => {
      // -3 mod 10 is 7; inverse of 7 mod 10 is 3
      expect(safeModularInverse(-3n, 10n)).toBe(3n);
    });

    it("should throw mathematical panic if modulus is less than or equal to zero", () => {
      expect(() => safeModularInverse(3n, 0n)).toThrow("Mathematical Panic: Modulus must be greater than zero.");
      expect(() => safeModularInverse(3n, -5n)).toThrow("Mathematical Panic: Modulus must be greater than zero.");
    });

    it("should throw mathematical panic if 'a' is a multiple of the modulus", () => {
      expect(() => safeModularInverse(10n, 10n)).toThrow("Cannot calculate modular inverse of zero or a multiple of the modulus.");
      expect(() => safeModularInverse(0n, 10n)).toThrow("Cannot calculate modular inverse of zero or a multiple of the modulus.");
    });

    it("should throw mathematical panic if inputs are not coprime", () => {
      // gcd(6, 10) = 2 !== 1
      expect(() => safeModularInverse(6n, 10n)).toThrow("Modular inverse does not exist. Inputs are not coprime");
    });
  });
});
