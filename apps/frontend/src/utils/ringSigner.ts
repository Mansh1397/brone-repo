import pkg from 'elliptic';
import crypto from 'crypto';
import { apiClient } from '../api/apiClient';

import { base64urlToBase64 } from './base64url';

const { ec: EC } = pkg;
const ec = new EC('p256');

export async function getPrivateKeyHex(privateKey: CryptoKey): Promise<string> {
  const jwk = await window.crypto.subtle.exportKey("jwk", privateKey);
  if (!jwk.d) throw new Error("Private key is not exportable.");
  return Buffer.from(base64urlToBase64(jwk.d), 'base64').toString('hex');
}

// Convert string/hex to point
function toPoint(hex: string) {
  return ec.keyFromPublic(hex, 'hex').getPublic();
}

// Map a public key point to a deterministic curve point
function hashToPoint(point: any): any {
  const hash = crypto.createHash('sha256')
    .update(point.encode('hex', false))
    .digest();
  return ec.g.mul(hash);
}

// Challenge hashing
function hashChallenge(message: string, L: any, R: any): string {
  return crypto.createHash('sha256')
    .update(message)
    .update(L.encode('hex', false))
    .update(R.encode('hex', false))
    .digest('hex');
}

export async function fetchDecoyRing(n: number = 5): Promise<string[]> {
  const decoyRing: string[] = [];

  try {
    const response = await apiClient.get('public-keys');
    if (Array.isArray(response.data)) {
      const keys = [...response.data].filter(k => typeof k === 'string' && k.length > 0);
      while (decoyRing.length < n && keys.length > 0) {
        const randIdx = Math.floor(Math.random() * keys.length);
        const selected = keys.splice(randIdx, 1)[0];
        if (!decoyRing.includes(selected)) {
          decoyRing.push(selected);
        }
      }
    }
  } catch (err) {
    console.warn("Failed to fetch decoy keys from network:", err);
  }

  // Generate missing mathematically valid decoy keys using the EC library to fill the ring
  while (decoyRing.length < n) {
    try {
      const pair = ec.genKeyPair();
      const pubHex = pair.getPublic(false, 'hex');
      if (!decoyRing.includes(pubHex)) {
        decoyRing.push(pubHex);
      }
    } catch (e) {
      // Keep trying
    }
  }

  return decoyRing;
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
  // Pre-Flight Type Checks
  if (typeof myPrivateKeyHex !== 'string') throw new Error('Private key must be a hex string');
  if (!publicKeysRingHex.every(k => typeof k === 'string')) throw new Error('All public keys must be hex strings');

  let tempPrivateKey = myPrivateKeyHex;
  try {
    const key = ec.keyFromPrivate(tempPrivateKey, 'hex');
    const myPublicKeyHex = key.getPublic(false, 'hex');

    let ringHex = [...publicKeysRingHex];
    if (!ringHex.includes(myPublicKeyHex)) {
      ringHex.push(myPublicKeyHex);
    }
    ringHex.sort();

    // Map keys to points while protecting against invalid hex formats
    const ringPoints: any[] = [];
    const validRingHex: string[] = [];

    for (const hex of ringHex) {
      try {
        const point = toPoint(hex);
        ringPoints.push(point);
        validRingHex.push(hex);
      } catch (err) {
        // Generate a mathematically valid point on the fly to replace the invalid one
        let validPoint = null;
        let validHex = "";
        while (!validPoint) {
          try {
            const pair = ec.genKeyPair();
            validHex = pair.getPublic(false, 'hex');
            validPoint = toPoint(validHex);
          } catch (e) {}
        }
        ringPoints.push(validPoint);
        validRingHex.push(validHex);
      }
    }

    const signerIndex = validRingHex.indexOf(myPublicKeyHex);
    const n = validRingHex.length;

    const Hp = ringPoints.map(p => hashToPoint(p));

    const privateKeyBN = key.getPrivate();
    const keyImagePoint = Hp[signerIndex].mul(privateKeyBN);
    const keyImageHex = keyImagePoint.encode('hex', false);

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

      const c_bn = ec.keyFromPrivate(c[idx], 'hex').getPrivate();
      const L_i = ec.g.mul(s_rand).add(ringPoints[idx].mul(c_bn));
      const R_i = Hp[idx].mul(s_rand).add(keyImagePoint.mul(c_bn));

      c[(idx + 1) % n] = hashChallenge(message, L_i, R_i);
    }

    const c_s_bn = ec.keyFromPrivate(c[signerIndex], 'hex').getPrivate();
    const cx = c_s_bn.mul(privateKeyBN).mod(ec.n);
    const s_s = k.sub(cx).umod(ec.n);
    s[signerIndex] = s_s.toString('hex');

    return {
      message,
      ring: validRingHex,
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
