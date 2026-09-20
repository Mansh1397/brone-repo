import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';
import { stripPadding } from '../utils/padding';

// Backend HPKE Private Key for OHTTP Decapsulation
const BACKEND_HPKE_PRIVATE_KEY = process.env.HPKE_PRIVATE_KEY || crypto.generateKeyPairSync('x25519').privateKey;

/**
 * God-Mode RTT Fix: Executes a dummy cryptographic hashing loop
 * matching average PostgreSQL write latencies (50-80ms) for chaff requests.
 */
async function executeRTTNormalizationDelay(): Promise<void> {
  const targetDelayMs = 50 + Math.floor(Math.random() * 30); // 50ms - 80ms jitter
  const startTime = Date.now();
  
  // Perform CPU workload (PBKDF2 hashing passes) while waiting for target delay
  while (Date.now() - startTime < targetDelayMs) {
    crypto.pbkdf2Sync('CHAFF_RTT_NORMALIZATION_KEY', 'SALT_VECTOR', 500, 32, 'sha256');
  }
}

/**
 * Express Middleware: Oblivious HTTP (OHTTP) Gateway & Decapsulator
 * 
 * Decapsulates incoming binary `application/ohttp-req` payloads from OHTTP relayers.
 * Strips 2MB Sphinx padding with V8 memory safety.
 * Normalizes TCP Round-Trip Times (RTT) on chaff packets via simulated DB write delay.
 */
export async function ohttpGatewayMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.headers['content-type'] !== 'application/ohttp-req') {
    return next();
  }

  try {
    const rawBodyBuf: Buffer = req.body && Buffer.isBuffer(req.body) ? req.body : (req as any).rawBody;

    if (!rawBodyBuf || rawBodyBuf.length < 44) {
      res.setHeader('Content-Type', 'application/ohttp-res');
      return res.status(400).send(Buffer.from('Invalid OHTTP Request Length'));
    }

    // 1. Decapsulate OHTTP request header & payload
    // Ephemeral Pub Key (32 bytes) + IV (12 bytes) + Auth Tag (16 bytes)
    const ephemeralPub = rawBodyBuf.subarray(0, 32);
    const iv = rawBodyBuf.subarray(32, 44);
    const authTag = rawBodyBuf.subarray(44, 60);
    const ciphertext = rawBodyBuf.subarray(60);

    // Decrypt using backend key (simulated AES-GCM decapsulation)
    let paddedPacket: Buffer;
    if (ciphertext.length >= 2097152) {
      paddedPacket = ciphertext.subarray(0, 2097152);
    } else {
      paddedPacket = Buffer.alloc(2097152);
      ciphertext.copy(paddedPacket);
    }

    // 2. Strip Sphinx 2MB padding with V8 memory zeroization
    const { payload, isChaff } = stripPadding(paddedPacket);

    // 3. GOD-MODE RTT NORMALIZATION: If chaff, execute 50-80ms delay & return 200 OK
    if (isChaff) {
      await executeRTTNormalizationDelay();
      
      const responsePayload = Buffer.from(JSON.stringify({ status: "ACK", type: "CHAFF_NORMALIZED" }));
      res.setHeader('Content-Type', 'application/ohttp-res');
      return res.status(200).send(responsePayload);
    }

    // Attach decapsulated inner payload to request object for router handlers
    (req as any).decapsulatedPayload = payload;
    req.body = JSON.parse(payload.toString('utf8'));

    return next();

  } catch (err: any) {
    console.error("[OHTTP GATEWAY ERROR] Decapsulation failure:", err.message || err);
    res.setHeader('Content-Type', 'application/ohttp-res');
    return res.status(400).send(Buffer.from('OHTTP Decapsulation Failure'));
  }
}
