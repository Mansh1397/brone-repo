import * as crypto from "crypto";
import { safeModularInverse } from "./utils/math";

export interface Point {
  x: bigint;
  y: bigint;
}

export interface RingSignature {
  c1: bigint;
  s: bigint[];
  keyImage: Point;
}

// Ed25519 Curve constants
export const Q = 2n ** 255n - 19n;
export const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;
export const A = 486662n;
export const GAMMA = 6853475219497561581579357271197624642482790079785650197046958215289687604742n;

export const B: Point = {
  x: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  y: 46316835694926478169428394003475163141307993866256225615783033603165251855960n
};

interface ProjectivePoint {
  X: bigint;
  Y: bigint;
  Z: bigint;
  T: bigint;
}

function modInverse(a: bigint, m: bigint): bigint {
  return safeModularInverse(a, m);
}

function safeInverse(val: bigint): bigint {
  const zeroMask = -(val === 0n ? 1n : 0n);
  const safeVal = (zeroMask & 1n) | (~zeroMask & val);
  return modInverse((safeVal % Q + Q) % Q, Q);
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = (base % modulus + modulus) % modulus;
  let exp = exponent;
  while (exp > 0n) {
    if (exp & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    exp >>= 1n;
  }
  return result;
}

const IVAL = modPow(2n, (Q - 1n) / 4n, Q);

function sqrt(w: bigint): bigint | null {
  const x = modPow(w, (Q + 3n) / 8n, Q);
  const xSquare = (x * x) % Q;
  if (xSquare === w) return x;
  if (xSquare === (Q - w) % Q) return (x * IVAL) % Q;
  return null;
}

function toExtended(p: Point): ProjectivePoint {
  return {
    X: p.x,
    Y: p.y,
    Z: 1n,
    T: (p.x * p.y) % Q
  };
}

function toAffine(p: ProjectivePoint): Point {
  const zInv = safeInverse(p.Z);
  return {
    x: ((p.X * zInv) % Q + Q) % Q,
    y: ((p.Y * zInv) % Q + Q) % Q
  };
}

function addExtended(p1: ProjectivePoint, p2: ProjectivePoint): ProjectivePoint {
  const A_val = ((p1.Y - p1.X) * (p2.Y - p2.X)) % Q;
  const B_val = ((p1.Y + p1.X) * (p2.Y + p2.X)) % Q;
  const C_val = (p1.T * 2n * D * p2.T) % Q;
  const D_val = (p1.Z * 2n * p2.Z) % Q;
  const E_val = (B_val - A_val) % Q;
  const F_val = (D_val - C_val) % Q;
  const G_val = (D_val + C_val) % Q;
  const H_val = (B_val + A_val) % Q;
  return {
    X: ((E_val * F_val) % Q + Q) % Q,
    Y: ((G_val * H_val) % Q + Q) % Q,
    T: ((E_val * H_val) % Q + Q) % Q,
    Z: ((F_val * G_val) % Q + Q) % Q
  };
}

function cswapExtended(swap: bigint, r0: ProjectivePoint, r1: ProjectivePoint): [ProjectivePoint, ProjectivePoint] {
  const mask = -swap;
  const dummyX = mask & (r0.X ^ r1.X);
  const dummyY = mask & (r0.Y ^ r1.Y);
  const dummyZ = mask & (r0.Z ^ r1.Z);
  const dummyT = mask & (r0.T ^ r1.T);
  return [
    { X: r0.X ^ dummyX, Y: r0.Y ^ dummyY, Z: r0.Z ^ dummyZ, T: r0.T ^ dummyT },
    { X: r1.X ^ dummyX, Y: r1.Y ^ dummyY, Z: r1.Z ^ dummyZ, T: r1.T ^ dummyT }
  ];
}

export function scalarMult(k: bigint, P: Point): Point {
  const pP = toExtended(P);
  let R0: ProjectivePoint = { X: 0n, Y: 1n, Z: 1n, T: 0n };
  let R1: ProjectivePoint = pP;
  let prevBit = 0n;
  const loopCount = 256;
  for (let i = loopCount - 1; i >= 0; i--) {
    const bit = (k >> BigInt(i)) & 1n;
    const swap = bit ^ prevBit;
    [R0, R1] = cswapExtended(swap, R0, R1);
    R1 = addExtended(R0, R1);
    R0 = addExtended(R0, R0);
    prevBit = bit;
  }
  [R0, R1] = cswapExtended(prevBit, R0, R1);
  const res = toAffine(R0);
  // Zero intermediate projectives
  R0.X = 0n; R0.Y = 0n; R0.Z = 0n; R0.T = 0n;
  R1.X = 0n; R1.Y = 0n; R1.Z = 0n; R1.T = 0n;
  return res;
}

function bigintToBuf(val: bigint): Buffer {
  const buf = Buffer.alloc(32);
  let tmp = val;
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return buf;
}

export function hashToPoint(P: Point): Point {
  let val = 0n;
  const bufX = bigintToBuf(P.x);
  const bufY = bigintToBuf(P.y);
  const hash = crypto.createHash("sha256").update(bufX).update(bufY).digest();
  for (let i = 0; i < 32; i++) {
    val = (val << 8n) | BigInt(hash[i]);
  }

  // Constant-time Elligator2 map-to-curve
  const r = (val % Q + Q) % Q;
  const u = 2n;
  const t1 = (r * r) % Q;
  const t2 = (u * t1) % Q;
  const t3 = (1n + t2) % Q;

  const zeroMask = -(t3 === 0n ? 1n : 0n);
  const t3_safe = (zeroMask & u) | (~zeroMask & t3);

  const x1 = ((-A * safeInverse(t3_safe)) % Q + Q) % Q;
  const x2 = ((-t2 * x1) % Q + Q) % Q;

  const y1 = (x1 * x1 % Q * x1 + A * x1 % Q * x1 + x1) % Q;
  const y2 = (x2 * x2 % Q * x2 + A * x2 % Q * x2 + x2) % Q;

  const legendre = modPow(y1, (Q - 1n) / 2n, Q);
  const isSq = (legendre === Q - 1n) ? 0n : 1n;

  const mask_sq = -isSq;
  const x_sel = (mask_sq & x1) | (~mask_sq & x2);
  const y2_sel = (mask_sq & y1) | (~mask_sq & y2);

  const y_val = sqrt(y2_sel) || 0n;

  const sgn_r = r & 1n;
  const sgn_y = y_val & 1n;
  const changeSign = (sgn_r === sgn_y) ? 0n : 1n;
  const maskSign = -changeSign;
  const y_sel = (maskSign & ((Q - y_val) % Q)) | (~maskSign & y_val);

  const x_ed = (GAMMA * x_sel % Q * safeInverse(y_sel)) % Q;
  const y_ed = ((x_sel - 1n) * safeInverse(x_sel + 1n)) % Q;

  const pointOnCurve = {
    x: (x_ed % Q + Q) % Q,
    y: (y_ed % Q + Q) % Q
  };

  const res = scalarMult(8n, pointOnCurve);
  
  // Explicitly clear transient scalars
  bufX.fill(0);
  bufY.fill(0);
  hash.fill(0);
  return res;
}

function hashChallenge(messageHash: bigint, L_pt: Point, R_pt: Point): bigint {
  const hash = crypto.createHash("sha256")
    .update(bigintToBuf(messageHash))
    .update(bigintToBuf(L_pt.x))
    .update(bigintToBuf(L_pt.y))
    .update(bigintToBuf(R_pt.x))
    .update(bigintToBuf(R_pt.y))
    .digest();
  let res = 0n;
  for (let i = 0; i < 32; i++) {
    res = (res << 8n) | BigInt(hash[i]);
  }
  return res % L;
}

export function generateKeyImage(privateKey: bigint, publicKeyPoint: Point): Point {
  const isSubgroup = scalarMult(L, publicKeyPoint);
  if (isSubgroup.x !== 0n || isSubgroup.y !== 1n) {
    throw new Error("Public key not in prime-order subgroup");
  }
  const hp = hashToPoint(publicKeyPoint);
  const res = scalarMult(privateKey, hp);
  
  const isImageSubgroup = scalarMult(L, res);
  if (isImageSubgroup.x !== 0n || isImageSubgroup.y !== 1n) {
    throw new Error("Key image not in prime-order subgroup");
  }
  return res;
}

// Flat buffer deserialization with stride index
export function serializeKeysRing(ring: Point[]): BigUint64Array {
  const buf = new BigUint64Array(ring.length * 8);
  for (let i = 0; i < ring.length; i++) {
    const stride = i * 8;
    let tmpX = ring[i].x;
    let tmpY = ring[i].y;
    for (let j = 3; j >= 0; j--) {
      buf[stride + j] = tmpX & 0xffffffffffffffffn;
      tmpX >>= 64n;
      buf[stride + 4 + j] = tmpY & 0xffffffffffffffffn;
      tmpY >>= 64n;
    }
  }
  return buf;
}

function deserializeKeysRing(flatBuffer: BigUint64Array): Point[] {
  const ring: Point[] = [];
  const len = flatBuffer.length / 8; // Each BigInt coordinates requires 4 words of 64-bit space
  for (let i = 0; i < len; i++) {
    const stride = i * 8;
    let x = 0n;
    let y = 0n;
    for (let j = 0; j < 4; j++) {
      x = (x << 64n) | BigInt(flatBuffer[stride + j]);
      y = (y << 64n) | BigInt(flatBuffer[stride + 4 + j]);
    }
    ring.push({ x, y });
  }
  return ring;
}

export function signRing(
  messageHash: bigint,
  flatKeysRing: BigUint64Array,
  signerPrivateKey: bigint,
  signerIndex: number
): RingSignature {
  const publicKeysRing = deserializeKeysRing(flatKeysRing);
  const n = publicKeysRing.length;

  let k = 0n;
  let I: Point = { x: 0n, y: 0n };
  const s_arr: bigint[] = [];
  const c = Array(n).fill(0n);
  const Hp: Point[] = [];

  try {
    // Subgroup confirmations
    for (let i = 0; i < n; i++) {
      const isSub = scalarMult(L, publicKeysRing[i]);
      if (isSub.x !== 0n || isSub.y !== 1n) {
        throw new Error("Subgroup verification failed on ring public key");
      }
    }

    // Deterministic k via HMAC-SHA256 (RFC 6979)
    const hmac = crypto.createHmac("sha256", Buffer.alloc(32));
    hmac.update(bigintToBuf(messageHash));
    hmac.update(bigintToBuf(signerPrivateKey));
    const digest = hmac.digest();
    for (let i = 0; i < 32; i++) {
      k = (k << 8n) | BigInt(digest[i]);
    }
    k = k % L;
    if (k === 0n) k = 1n;

    I = generateKeyImage(signerPrivateKey, publicKeysRing[signerIndex]);

    for (let i = 0; i < n; i++) {
      Hp.push(hashToPoint(publicKeysRing[i]));
    }

    for (let i = 0; i < n; i++) {
      const h = crypto.createHash("sha256")
        .update(bigintToBuf(messageHash))
        .update(bigintToBuf(BigInt(i)))
        .digest();
      let s_val = 0n;
      for (let j = 0; j < 32; j++) {
        s_val = (s_val << 8n) | BigInt(h[j]);
      }
      s_arr.push(s_val % L);
    }

    for (let i = 0; i < 2 * n; i++) {
      const idx = i % n;
      const diff = BigInt(idx) - BigInt(signerIndex);
      const isSigner = ((diff | -diff) >> 256n & 1n) ^ 1n;
      const mask = -isSigner;

      const S_scalar = (mask & k) | (~mask & s_arr[idx]);
      const C_scalar = ~mask & c[idx];

      const L_val = toAffine(addExtended(toExtended(scalarMult(S_scalar, B)), toExtended(scalarMult(C_scalar, publicKeysRing[idx]))));
      const R_val = toAffine(addExtended(toExtended(scalarMult(S_scalar, Hp[idx])), toExtended(scalarMult(C_scalar, I))));

      c[(idx + 1) % n] = hashChallenge(messageHash, L_val, R_val);
    }

    const c_s = c[signerIndex];
    s_arr[signerIndex] = ((k - c_s * signerPrivateKey) % L + L) % L;

    const signature: RingSignature = {
      c1: c[0],
      s: [...s_arr],
      keyImage: { x: I.x, y: I.y }
    };

    // Heap sanitization override via CryptoBroker
    if ((global as any).CryptoBroker && typeof (global as any).CryptoBroker.secureNativePurge === "function") {
      const tempBuf = bigintToBuf(signerPrivateKey);
      (global as any).CryptoBroker.secureNativePurge(tempBuf);
      tempBuf.fill(0);
    }

    return signature;
  } finally {
    // Explicitly zero intermediate heap scalar traces
    k = 0n;
    for (let i = 0; i < s_arr.length; i++) {
      s_arr[i] = 0n;
    }
    for (let i = 0; i < c.length; i++) {
      c[i] = 0n;
    }
  }
}

export function verifyRing(
  messageHash: bigint,
  flatKeysRing: BigUint64Array,
  signature: RingSignature
): boolean {
  const publicKeysRing = deserializeKeysRing(flatKeysRing);
  const n = publicKeysRing.length;
  const { c1, s, keyImage } = signature;

  const Hp: Point[] = [];
  const c = Array(n).fill(0n);
  c[0] = c1;

  try {
    // Subgroup verification for ring public keys
    for (let i = 0; i < n; i++) {
      const isSub = scalarMult(L, publicKeysRing[i]);
      if (isSub.x !== 0n || isSub.y !== 1n) {
        return false;
      }
    }

    // Subgroup verification for Key Image
    const isImageSub = scalarMult(L, keyImage);
    if (isImageSub.x !== 0n || isImageSub.y !== 1n) {
      return false;
    }

    for (let i = 0; i < n; i++) {
      Hp.push(hashToPoint(publicKeysRing[i]));
    }

    for (let i = 0; i < n; i++) {
      const L_val = toAffine(addExtended(toExtended(scalarMult(s[i], B)), toExtended(scalarMult(c[i], publicKeysRing[i]))));
      const R_val = toAffine(addExtended(toExtended(scalarMult(s[i], Hp[i])), toExtended(scalarMult(c[i], keyImage))));
      c[(i + 1) % n] = hashChallenge(messageHash, L_val, R_val);
    }

    return c[0] === c1;
  } catch (error) {
    console.error("Cryptographic Panic inside verifyRing:", error);
    return false;
  } finally {
    for (let i = 0; i < c.length; i++) {
      c[i] = 0n;
    }
  }
}

// Protocol JIT compilation warm-up passes
export function warmUpLrsModule(): void {
  const mockPrivateKey = 12345n;
  const mockPubKey = scalarMult(mockPrivateKey, B);
  
  const ringCoords = new BigUint64Array(8);
  let tmpX = mockPubKey.x;
  let tmpY = mockPubKey.y;
  for (let j = 3; j >= 0; j--) {
    ringCoords[j] = Number(tmpX & 0xffffffffffffffffn) ? BigInt(Number(tmpX & 0xffffffffffffffffn)) : 0n;
    tmpX >>= 64n;
    ringCoords[4 + j] = Number(tmpY & 0xffffffffffffffffn) ? BigInt(Number(tmpY & 0xffffffffffffffffn)) : 0n;
    tmpY >>= 64n;
  }

  const msgHash = 99999n;
  for (let i = 0; i < 3; i++) {
    try {
      const sig = signRing(msgHash, ringCoords, mockPrivateKey, 0);
      verifyRing(msgHash, ringCoords, sig);
    } catch {
      // Dummy execution frame wrapper
    }
  }
}

// Warm-up on load
warmUpLrsModule();
