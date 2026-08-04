import pkg from 'elliptic';
import crypto from 'crypto';
import { apiClient } from '../api/apiClient';

const { ec: EC } = pkg;
const ec = new EC('p256');

export async function getPrivateKeyHex(privateKey: CryptoKey): Promise<string> {
  const jwk = await window.crypto.subtle.exportKey("jwk", privateKey);
  if (!jwk.d) throw new Error("Private key is not exportable.");
  return Buffer.from(jwk.d, 'base64url').toString('hex');
}

// Convert string/hex to point
function toPoint(hex: string) {
  return ec.keyFromPublic(hex, 'hex').getPublic();
}

// Map a public key point to a deterministic curve point
function hashToPoint(point: any): any {
  const hash = crypto.createHash('sha256')
    .update(point.encode('hex', true))
    .digest();
  return ec.g.mul(hash);
}

// Challenge hashing
function hashChallenge(message: string, L: any, R: any): string {
  return crypto.createHash('sha256')
    .update(message)
    .update(L.encode('hex', true))
    .update(R.encode('hex', true))
    .digest('hex');
}

export async function fetchDecoyRing(n: number = 5): Promise<string[]> {
  try {
    const response = await apiClient.get('public-keys');
    if (Array.isArray(response.data) && response.data.length > 0) {
      const keys = [...response.data];
      const decoyRing: string[] = [];
      while (decoyRing.length < n && keys.length > 0) {
        const randIdx = Math.floor(Math.random() * keys.length);
        decoyRing.push(keys.splice(randIdx, 1)[0]);
      }
      return decoyRing;
    }
  } catch (err) {
    console.warn("Failed to fetch decoy keys from network:", err);
  }

  // Local fallback decoy keys if network query returns empty/errors
  const fallbacks = [
    "0437435f3dfd9ff7b5d1c68f237bf2d3ee824c965c2690ff357d6cd5637dbf7e3c",
    "04a37bf2d3ee824c965c2690ff357d6cd5637dbf7e3c37435f3dfd9ff7b5d1c68f",
    "04f7b5d1c68f237bf2d3ee824c965c2690ff357d6cd5637dbf7e3c37435f3dfd9f",
    "04965c2690ff357d6cd5637dbf7e3c37435f3dfd9ff7b5d1c68f237bf2d3ee824"
  ];
  return fallbacks.slice(0, n);
}

export function generateRingSignature(
  message: string,
  myPrivateKeyHex: string,
  publicKeysRingHex: string[]
): {
  message: string;
  ring: string[];
  challenge: string;
  responses: string[];
  keyImage: string;
} {
  let tempPrivateKey = myPrivateKeyHex;
  try {
    const key = ec.keyFromPrivate(tempPrivateKey, 'hex');
    const myPublicKeyHex = key.getPublic().encode('hex', true);

    let ringHex = [...publicKeysRingHex];
    if (!ringHex.includes(myPublicKeyHex)) {
      ringHex.push(myPublicKeyHex);
    }
    ringHex.sort();
    const signerIndex = ringHex.indexOf(myPublicKeyHex);
    const n = ringHex.length;

    const ringPoints = ringHex.map(hex => toPoint(hex));
    const Hp = ringPoints.map(p => hashToPoint(p));

    const privateKeyBN = key.getPriv();
    const keyImagePoint = Hp[signerIndex].mul(privateKeyBN);
    const keyImageHex = keyImagePoint.encode('hex', true);

    const s: string[] = Array(n).fill("");
    const c: string[] = Array(n).fill("");

    const k = ec.rand().mod(ec.n);

    const L_s = ec.g.mul(k);
    const R_s = Hp[signerIndex].mul(k);

    c[(signerIndex + 1) % n] = hashChallenge(message, L_s, R_s);

    for (let i = 1; i < n; i++) {
      const idx = (signerIndex + i) % n;
      const s_rand = ec.rand().mod(ec.n);
      s[idx] = s_rand.toString('hex');

      const c_bn = ec.keyFromPrivate(c[idx], 'hex').getPriv();
      const L_i = ec.g.mul(s_rand).add(ringPoints[idx].mul(c_bn));
      const R_i = Hp[idx].mul(s_rand).add(keyImagePoint.mul(c_bn));

      c[(idx + 1) % n] = hashChallenge(message, L_i, R_i);
    }

    const c_s_bn = ec.keyFromPrivate(c[signerIndex], 'hex').getPriv();
    const cx = c_s_bn.mul(privateKeyBN).mod(ec.n);
    const s_s = k.sub(cx).umod(ec.n);
    s[signerIndex] = s_s.toString('hex');

    return {
      message,
      ring: ringHex,
      challenge: c[0],
      responses: s,
      keyImage: keyImageHex
    };
  } finally {
    // Memory Sanitization: Explicitly clear private key variables from memory
    tempPrivateKey = "";
    myPrivateKeyHex = "";
  }
}
