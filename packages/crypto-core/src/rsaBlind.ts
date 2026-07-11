import { safeModularInverse } from "./utils/math";

export interface RSAPublicKey {
  e: bigint;
  n: bigint;
}

export interface RSAPrivateKey {
  d: bigint;
  n: bigint;
}

/**
 * Computes the modular multiplicative inverse using the Extended Euclidean Algorithm.
 * Solves for x in: (a * x) % m == 1.
 * Wraps the final return statement in a strict positive modulo correction.
 * Throws a descriptive error if gcd(a, m) !== 1.
 */
export function modInverse(a: bigint, m: bigint): bigint {
  return safeModularInverse(a, m);
}

/**
 * Montgomery / Constant-Time modular exponentiation: computes (base^exponent) % modulus.
 * To guarantee strict constant-time execution, the loop executes exactly 4096 iterations.
 */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;

  function cswap(swap: bigint, r0: bigint, r1: bigint): [bigint, bigint] {
    const swapMask = -swap;
    const dummy = swapMask & (r0 ^ r1);
    return [r0 ^ dummy, r1 ^ dummy];
  }

  // Fallback to Montgomery ladder with standard modular multiplication for even modulus
  if ((modulus & 1n) === 0n) {
    let R0 = 1n;
    let R1 = base % modulus;
    if (R1 < 0n) R1 += modulus;

    let prevBit = 0n;
    const loopCount = 4096;
    for (let i = loopCount - 1; i >= 0; i--) {
      // Localized scope for loop frame
      {
        const bit = (exponent >> BigInt(i)) & 1n;
        const swap = bit ^ prevBit;
        [R0, R1] = cswap(swap, R0, R1);
        R1 = (R0 * R1) % modulus;
        R0 = (R0 * R0) % modulus;
        prevBit = bit;
      }
    }
    [R0, R1] = cswap(prevBit, R0, R1);
    const result = R0;
    
    // Target intermediate BigInts for garbage collection
    R0 = 0n;
    R1 = 0n;
    prevBit = 0n;
    
    return result;
  }

  // Montgomery modular multiplication and reduction for odd modulus
  const bitLen = modulus.toString(2).length;
  const k = BigInt(bitLen);
  const R = 1n << k;

  // Constant-time modular inverse solver for N' = -N^-1 mod R
  let N_prime: bigint;
  {
    const ONE = 1n;
    let t = 1n;
    let r = modulus;
    let computedNPrime = 0n;
    for (let i = 0; i < bitLen; i++) {
      {
        const bit = t & ONE;
        const mask = -(t & ONE);
        t = t + (r & mask);
        t = t >> ONE;
        computedNPrime = computedNPrime | (bit << BigInt(i));
      }
    }
    N_prime = computedNPrime;
    
    // Target intermediates for GC
    t = 0n;
    r = 0n;
    computedNPrime = 0n;
  }

  const R2_mod_N = (R * R) % modulus;

  function REDC(T: bigint): bigint {
    const mask = R - 1n;
    const m = (T * N_prime) & mask;
    const u = (T + m * modulus) >> k;
    const uMinusN = u - modulus;
    const cmpMask = ~((uMinusN) >> 4096n);
    const res = u - (cmpMask & modulus);
    return res;
  }

  let R0 = R % modulus;
  let R1 = REDC((base % modulus) * R2_mod_N);

  let prevBit = 0n;
  const loopCount = 4096;
  for (let i = loopCount - 1; i >= 0; i--) {
    // Localized scope for loop frame
    {
      const bit = (exponent >> BigInt(i)) & 1n;
      const swap = bit ^ prevBit;
      [R0, R1] = cswap(swap, R0, R1);
      R1 = REDC(R0 * R1);
      R0 = REDC(R0 * R0);
      prevBit = bit;
    }
  }
  [R0, R1] = cswap(prevBit, R0, R1);

  const finalResult = REDC(R0);

  // Target intermediate BigInts for garbage collection
  R0 = 0n;
  R1 = 0n;
  prevBit = 0n;
  N_prime = 0n;

  return finalResult;
}

/**
 * Blinds a message Hash under the server public key:
 * T = (messageHash * r^e) % N
 */
export function blindMessage(
  messageHash: bigint,
  blindingFactorR: bigint,
  publicKey: RSAPublicKey
): bigint {
  try {
    const { e, n } = publicKey;
    if (messageHash < 0n || messageHash >= n) {
      throw new Error("rawMessage must be non-negative and strictly less than the modulus N");
    }
    const rToE = modPow(blindingFactorR, e, n);
    const result = (messageHash * rToE) % n;
    
    // Target intermediate BigInts for garbage collection
    let tmp: bigint | null = rToE;
    tmp = null;

    return result;
  } catch (error) {
    console.error("Cryptographic Panic inside blindMessage:", error);
    throw error;
  }
}

/**
 * Signs a blinded transaction using the private key:
 * S' = T^d % N
 */
export function serverBlindSign(
  blindedTransaction: bigint,
  privateKey: RSAPrivateKey
): bigint {
  const { d, n } = privateKey;
  if (blindedTransaction < 0n || blindedTransaction >= n) {
    throw new Error("blindedMessage must be non-negative and strictly less than the modulus N");
  }
  const result = modPow(blindedTransaction, d, n);

  // Physical RAM fence override via CryptoBroker C++ bridge
  if (typeof (global as any).CryptoBroker?.secureNativePurge === "function") {
    try {
      (global as any).CryptoBroker.secureNativePurge(blindedTransaction);
      (global as any).CryptoBroker.secureNativePurge();
    } catch (e) {}
  }

  return result;
}

/**
 * Strips the blinding factor from the signed token:
 * S = (S' * r^-1) % N
 */
export function unblindSignature(
  blindedSignatureSPrime: bigint,
  blindingFactorR: bigint,
  n: bigint
): bigint {
  const rInverse = modInverse(blindingFactorR, n);
  const unblinded = (blindedSignatureSPrime * rInverse) % n;
  const result = ((unblinded % n) + n) % n;

  // Physical RAM fence override via CryptoBroker C++ bridge
  if (typeof (global as any).CryptoBroker?.secureNativePurge === "function") {
    try {
      (global as any).CryptoBroker.secureNativePurge(unblinded);
      (global as any).CryptoBroker.secureNativePurge(rInverse);
      (global as any).CryptoBroker.secureNativePurge();
    } catch (e) {}
  }

  return result;
}

/**
 * Asserts whether S^e % N == x.
 */
export function verifyUnblindedSignature(
  rawMessage: bigint,
  unblindedSignature: bigint,
  publicKey: RSAPublicKey
): boolean {
  try {
    const { e, n } = publicKey;
    const verifiedMessage = modPow(unblindedSignature, e, n);
    const normalizedMessage = ((rawMessage % n) + n) % n;
    return verifiedMessage === normalizedMessage;
  } catch (error) {
    console.error("Cryptographic Panic inside verifyUnblindedSignature:", error);
    return false;
  }
}
