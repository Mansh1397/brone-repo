import { createHash, randomBytes } from "crypto";

// 512-bit safe prime parameters for mathematically correct modular arithmetic LSAG ring signatures
export const SECP256K1_P = BigInt("0xc762af24c09d83172a44796ef8ae2c817eab414dd4981be11a0f66e94917a78d6bdd978f6286e2d216099048271a7f880c20e751bfebe1676a5f237d501039b7"); // Safe Prime p
export const SECP256K1_Q = BigInt("0x63b15792604ec18b95223cb77c571640bf55a0a6ea4c0df08d07b374a48bd3c6b5eecbc7b14371690b04c824138d3fc4061073a8dff5f0b3b52f91bea8081cdb"); // Subgroup Order q = (p - 1) / 2
export const SECP256K1_G = 2n; // Generator base g of order q modulo p

// Positive modulo helper
export function mod(n: bigint, m: bigint): bigint {
  return ((n % m) + m) % m;
}

// Modular Inverse using Extended Euclidean Algorithm
export function modInverse(a: bigint, m: bigint): bigint {
  let [m0, y, x] = [m, 0n, 1n];
  if (m === 1n) return 0n;
  while (a > 1n) {
    const q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = y;
    y = x - q * y;
    x = t;
  }
  if (x < 0n) x += m0;
  return x;
}

// Modular Exponentiation
export function modExp(base: bigint, exp: bigint, modVal: bigint): bigint {
  if (exp === 0n) return 1n;
  if (exp < 0n) {
    return modExp(modInverse(base, modVal), -exp, modVal);
  }
  let res = 1n;
  base = base % modVal;
  while (exp > 0n) {
    if (exp & 1n) res = (res * base) % modVal;
    base = (base * base) % modVal;
    exp >>= 1n;
  }
  return res;
}

// Hash mapping string to bigint
export function hash(message: string): bigint {
  const h = createHash("sha256").update(message).digest("hex");
  return BigInt("0x" + h);
}

// Helper to map public key to a group generator point H_p(y)
export function getHp(yVal: bigint, p: bigint): bigint {
  return modExp(SECP256K1_G, hash(yVal.toString(16)), p);
}

/**
 * Verifies a Linkable Ring Signature.
 * 
 * @param message The signed message payload.
 * @param ring Array of public keys (hex strings) representing the ring.
 * @param signature Signature object containing c0 (hex), s (hex array), and keyImage (hex).
 */
export function verifyRingSignature(
  message: string,
  ring: string[],
  signature: { c0: string; s: string[]; keyImage: string }
): boolean {
  try {
    const n = ring.length;
    if (n < 2) return false;
    if (signature.s.length !== n) return false;

    const p = SECP256K1_P;
    const q = SECP256K1_Q;
    const g = SECP256K1_G;

    const c0 = BigInt("0x" + signature.c0);
    const s = signature.s.map((si) => BigInt("0x" + si));
    const keyImage = BigInt("0x" + signature.keyImage);
    const y = ring.map((yi) => BigInt("0x" + yi));

    // Get group generators H_p(y_i)
    const h = y.map((yi) => getHp(yi, p));

    let c = c0;
    for (let i = 0; i < n; i++) {
      const L = (modExp(g, s[i], p) * modExp(y[i], c, p)) % p;
      const R = (modExp(h[i], s[i], p) * modExp(keyImage, c, p)) % p;
      c = mod(hash(message + L.toString(16) + R.toString(16)), q);
    }

    return c === c0;
  } catch (err) {
    console.error("[RING SIG] Verification failed due to exception:", err);
    return false;
  }
}

/**
 * Generates a Linkable Ring Signature.
 * 
 * @param message The message to sign.
 * @param ring Array of public keys (hex strings) representing the ring.
 * @param signerPrivateKey The private key (hex string) of the signer.
 * @param signerIndex The index of the signer's public key in the ring.
 */
export function generateRingSignature(
  message: string,
  ring: string[],
  signerPrivateKey: string,
  signerIndex: number
): { c0: string; s: string[]; keyImage: string } {
  const n = ring.length;
  if (n < 2) throw new Error("Ring size must be at least 2.");
  if (signerIndex < 0 || signerIndex >= n) throw new Error("Invalid signer index.");

  const p = SECP256K1_P;
  const q = SECP256K1_Q;
  const g = SECP256K1_G;

  const x = BigInt("0x" + signerPrivateKey);
  const y = ring.map((yi) => BigInt("0x" + yi));
  const h = y.map((yi) => getHp(yi, p));

  // Key Image I = h[signerIndex]^x % p
  const keyImage = modExp(h[signerIndex], x, p);

  // 1. Choose random u
  const u = mod(BigInt("0x" + randomBytes(32).toString("hex")), q);

  // 2. Compute L_pi, R_pi
  const L_pi = modExp(g, u, p);
  const R_pi = modExp(h[signerIndex], u, p);

  const challenges = new Array<bigint>(n);

  // 3. Compute c_next
  let c = mod(hash(message + L_pi.toString(16) + R_pi.toString(16)), q);
  challenges[(signerIndex + 1) % n] = c;

  const s = new Array<bigint>(n);
  let nextIndex = (signerIndex + 1) % n;

  for (let count = 1; count < n; count++) {
    const i = nextIndex;
    const si = mod(BigInt("0x" + randomBytes(32).toString("hex")), q);
    s[i] = si;

    const L = (modExp(g, si, p) * modExp(y[i], c, p)) % p;
    const R = (modExp(h[i], si, p) * modExp(keyImage, c, p)) % p;

    c = mod(hash(message + L.toString(16) + R.toString(16)), q);
    challenges[(i + 1) % n] = c;
    nextIndex = (nextIndex + 1) % n;
  }

  // Solve for s_pi
  const c_pi = c;
  const s_pi = mod(u - (c_pi * x), q);
  s[signerIndex] = s_pi;
  console.log(`[SIGN] s_pi computed: ${s_pi.toString(16)} for pi=${signerIndex} with c_pi=${c_pi.toString(16)}`);

  return {
    c0: challenges[0].toString(16),
    s: s.map((si) => si.toString(16)),
    keyImage: keyImage.toString(16)
  };
}
